//! Browser-camera uplink → ReDroid virtual camera.
//!
//! This module is the *inbound* counterpart to the scrcpy screen-mirror
//! pipeline. Where [`crate::scrcpy`] pulls H.264 off the device and
//! [`crate::webrtc`] pushes it to the browser, this module takes an H.264
//! track the browser *sends* (its `getUserMedia` webcam, encoded by the
//! browser's hardware H.264 encoder) and forwards the raw Annex-B access
//! units to a camera-injection endpoint running *inside* the ReDroid
//! container.
//!
//! ### Why a loopback socket (not scrcpy, not a DataChannel)
//!
//! The bridge and ReDroid share a pod network namespace, so the injection
//! endpoint is reachable on `127.0.0.1`. This mirrors the industry-standard
//! "cloud phone camera redirection" architecture (Intel Celadon camera vHAL
//! `libvhal-client`, Aliyun Wuying `libvhal_sdk` `VideoSink`, Huawei CPH
//! camera HAL): the client encodes, an in-guest **camera HAL** decodes and
//! feeds the Android camera framework, and the transport in between carries
//! an *encoded* stream over a socket. We keep the bridge a pure H.264
//! pass-through (no decode/re-encode) exactly like the outbound path — the
//! MediaCodec hardware decode happens on the Android side where it belongs.
//!
//! ### Wire protocol (bridge → in-guest camera endpoint)
//!
//! The endpoint (an external camera provider vHAL, or a
//! platform-signed helper app) runs a TCP server on
//! [`Config::sink_addr`] (default `127.0.0.1:7910`). The bridge connects as
//! a client and speaks a minimal length-prefixed framing:
//!
//! ```text
//! frame := magic(4) kind(1) len(u32-le) payload(len)
//! magic := "CMR1"                       (0x43 0x4D 0x52 0x31)
//! kind  := 1 Config | 2 Frame | 3 Stop
//! ```
//!
//! * `Config` payload is UTF-8 JSON `{ "width", "height", "fps", "codec",
//!   "facing" }` — sent once immediately after connect, so the vHAL can
//!   advertise the right `camera_capability` to the Android framework before
//!   the first frame (matches libvhal's `SetCameraCapability` handshake).
//! * `Frame` payload is one Annex-B H.264 access unit (SPS/PPS/IDR are
//!   in-band; the browser encoder emits parameter sets before each IDR when
//!   we request keyframes).
//! * `Stop` has an empty payload and tells the endpoint to drop the virtual
//!   camera (so an Android camera app sees the device disappear).
//!
//! The endpoint never sends anything back on this socket; keyframe requests
//! flow the other way (endpoint → bridge → browser PLI) out of band. If the
//! socket drops, the sink task reconnects with backoff and re-sends the
//! `Config` frame, so a vHAL restart doesn't strand the uplink.

use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Framing magic. Little-endian on the wire is irrelevant for the 4 ASCII
/// bytes; we compare them verbatim.
pub const FRAME_MAGIC: &[u8; 4] = b"CMR1";

const KIND_CONFIG: u8 = 1;
const KIND_FRAME: u8 = 2;
const KIND_STOP: u8 = 3;

/// Reconnect backoff bounds for the sink socket.
const BACKOFF_MIN: Duration = Duration::from_millis(200);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Camera capability handshake, serialised as the `Config` frame payload.
#[derive(Debug, Clone, Serialize)]
pub struct CameraConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    /// Always `"h264"` for now — the browser encodes H.264 and the bridge is
    /// a pass-through. Kept explicit so the vHAL can reject unknown codecs.
    pub codec: String,
    /// `"front"` or `"back"`, mapped by the endpoint to `LENS_FACING_*`.
    pub facing: String,
}

impl CameraConfig {
    pub fn new(width: u32, height: u32, fps: u32, facing: &str) -> Self {
        Self {
            width,
            height,
            fps,
            codec: "h264".to_string(),
            facing: facing.to_string(),
        }
    }
}

/// Messages fed to the sink task.
#[derive(Debug)]
enum SinkMsg {
    /// (Re)start a virtual-camera session with the given capability. Any
    /// previous session's socket is torn down and reconnected so the
    /// endpoint always sees a fresh `Config` before frames.
    Start(CameraConfig),
    /// One Annex-B H.264 access unit from the browser uplink track.
    Frame(Vec<u8>),
    /// End the session; the endpoint drops the virtual camera.
    Stop,
}

/// Handle to the camera uplink sink task. Cheap to clone.
#[derive(Clone)]
pub struct CameraSink {
    tx: mpsc::Sender<SinkMsg>,
}

impl CameraSink {
    /// Spawn the sink task. `sink_addr` is the in-guest camera endpoint
    /// (`127.0.0.1:7910` by default). The task idles until [`Self::start`]
    /// is called and only holds a socket open while a session is active.
    pub fn spawn(sink_addr: String) -> Self {
        // Bounded so a wedged/slow endpoint applies backpressure without
        // unbounded memory growth. Frames are drop-newest on a full queue
        // (see `push_frame`) — losing a delta frame just costs one PLI.
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(run_sink(sink_addr, rx));
        Self { tx }
    }

    /// Begin (or restart) a virtual-camera session.
    pub async fn start(&self, cfg: CameraConfig) {
        if self.tx.send(SinkMsg::Start(cfg)).await.is_err() {
            warn!("camera sink task gone; start dropped");
        }
    }

    /// Forward one Annex-B H.264 access unit. Non-blocking: drops the frame
    /// if the queue is full (drop-newest), matching the outbound video
    /// pump's delta-frame backpressure policy. Returns `false` when dropped.
    pub fn push_frame(&self, au: Vec<u8>) -> bool {
        self.tx.try_send(SinkMsg::Frame(au)).is_ok()
    }

    /// End the current session.
    pub async fn stop(&self) {
        let _ = self.tx.send(SinkMsg::Stop).await;
    }
}

/// Sink task: owns the (lazily-established) TCP connection to the in-guest
/// camera endpoint and serialises framed messages onto it.
async fn run_sink(sink_addr: String, mut rx: mpsc::Receiver<SinkMsg>) {
    // The current session's capability, retained so a mid-session reconnect
    // can replay the `Config` handshake before resuming frames.
    let mut active: Option<CameraConfig> = None;
    let mut stream: Option<TcpStream> = None;

    while let Some(msg) = rx.recv().await {
        match msg {
            SinkMsg::Start(cfg) => {
                info!(addr = %sink_addr, ?cfg, "camera uplink: starting virtual-camera session");
                active = Some(cfg.clone());
                // Force a fresh connection so the endpoint always sees the
                // Config frame first.
                stream = connect_and_configure(&sink_addr, &cfg).await;
            }
            SinkMsg::Frame(au) => {
                let Some(cfg) = active.as_ref() else {
                    // Frame arrived before Start (or after Stop) — ignore.
                    continue;
                };
                if stream.is_none() {
                    stream = connect_and_configure(&sink_addr, cfg).await;
                }
                if let Some(s) = stream.as_mut() {
                    if let Err(e) = write_frame(s, KIND_FRAME, &au).await {
                        warn!(error = %e, "camera uplink: frame write failed; will reconnect");
                        stream = None;
                    }
                }
            }
            SinkMsg::Stop => {
                info!("camera uplink: stopping virtual-camera session");
                if let Some(s) = stream.as_mut() {
                    let _ = write_frame(s, KIND_STOP, &[]).await;
                    let _ = s.shutdown().await;
                }
                active = None;
                stream = None;
            }
        }
    }
    debug!("camera sink task exiting (all senders dropped)");
}

/// Connect to the endpoint with bounded backoff and send the `Config`
/// handshake. Returns `None` if the endpoint is unreachable after the
/// backoff cap — the caller retries on the next frame, so a not-yet-ready
/// vHAL just delays the first frame rather than dropping the session.
async fn connect_and_configure(addr: &str, cfg: &CameraConfig) -> Option<TcpStream> {
    let mut backoff = BACKOFF_MIN;
    // A small bounded number of attempts per call; frames keep arriving so
    // we get repeated chances without blocking the whole task on a dead
    // endpoint.
    for attempt in 0..3u32 {
        match TcpStream::connect(addr).await {
            Ok(mut s) => {
                let _ = s.set_nodelay(true);
                let payload = match serde_json::to_vec(cfg) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "camera uplink: serialise config failed");
                        return None;
                    }
                };
                if let Err(e) = write_frame(&mut s, KIND_CONFIG, &payload).await {
                    warn!(error = %e, "camera uplink: config write failed");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
                info!(%addr, "camera uplink: connected + configured");
                return Some(s);
            }
            Err(e) => {
                debug!(%addr, attempt, error = %e, "camera uplink: connect failed");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
    None
}

/// Write one framed message: magic, kind, u32-le length, payload.
async fn write_frame(stream: &mut TcpStream, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut header = [0u8; 9];
    header[..4].copy_from_slice(FRAME_MAGIC);
    header[4] = kind;
    header[5..9].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.write_all(&header).await?;
    if !payload.is_empty() {
        stream.write_all(payload).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn config_defaults_to_h264() {
        let c = CameraConfig::new(1280, 720, 30, "front");
        assert_eq!(c.codec, "h264");
        assert_eq!(c.facing, "front");
        assert_eq!(c.width, 1280);
    }

    /// End-to-end framing round-trip against a real loopback listener:
    /// Start → Config frame, push_frame → Frame frame, with correct magic,
    /// kind bytes and little-endian lengths.
    #[tokio::test]
    async fn writes_config_then_frame_with_correct_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut frames = Vec::new();
            // Read two frames (config + one au).
            for _ in 0..2 {
                let mut header = [0u8; 9];
                sock.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..4], FRAME_MAGIC);
                let kind = header[4];
                let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
                let mut payload = vec![0u8; len];
                sock.read_exact(&mut payload).await.unwrap();
                frames.push((kind, payload));
            }
            frames
        });

        let sink = CameraSink::spawn(addr);
        sink.start(CameraConfig::new(640, 480, 30, "back")).await;
        // Retry a couple times: the sink connects lazily/asynchronously.
        for _ in 0..50 {
            if sink.push_frame(vec![0, 0, 0, 1, 0x65, 0xAA]) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let frames = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server did not receive frames in time")
            .unwrap();

        assert_eq!(frames[0].0, KIND_CONFIG);
        let cfg: serde_json::Value = serde_json::from_slice(&frames[0].1).unwrap();
        assert_eq!(cfg["codec"], "h264");
        assert_eq!(cfg["facing"], "back");
        assert_eq!(cfg["width"], 640);

        assert_eq!(frames[1].0, KIND_FRAME);
        assert_eq!(frames[1].1, vec![0, 0, 0, 1, 0x65, 0xAA]);
    }
}
