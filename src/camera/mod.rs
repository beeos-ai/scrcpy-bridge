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
//! ### Reverse events (v1.1, resident connection)
//!
//! The connection is RESIDENT: the sink connects at startup and keeps the
//! socket open across sharing sessions (sessions are delimited in-band by
//! Config/Stop, not by connection lifecycle). The vHAL uses the same socket
//! for reverse `CamInUse` events (kind=4, JSON `{"in_use":bool,...}`):
//! emitted when an in-guest app opens/closes the camera, replayed on
//! (re)connect. The bridge surfaces them to the viewer as `camera_needed`
//! datachannel messages so the browser can auto-start/stop webcam capture.
//! Keyframe requests still flow out of band (bridge-driven PLI).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::unix::OwnedReadHalf;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};

use crate::observability::CAMERA_FRAMES_DROPPED;

/// Abstract-namespace AF_UNIX socket name of the in-guest CMR1 endpoint
/// (without the leading NUL; that's added by `SocketAddr::from_abstract_name`).
/// Must match the vHAL server (`MakeAbstractAddr` in cmr1.cpp). A UNIX socket
/// is used instead of TCP because ReDroid's kernel blocks AF_INET for the
/// cameraserver uid the vHAL runs as (ANDROID_PARANOID_NETWORK), while
/// AF_UNIX is unrestricted.
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const CMR1_ABSTRACT_NAME: &[u8] = b"beeos_camera_cmr1";

/// Connect the resident sink to the vHAL's abstract-namespace CMR1 socket.
/// Abstract sockets are Linux-only; on other Unix hosts (dev builds / macOS
/// CI) this returns an error every attempt, which the caller treats as an
/// unreachable endpoint (the camera plane is a ReDroid/Linux-only feature).
///
/// Not compiled on Windows: `tokio::net::UnixStream` is unavailable there,
/// and the release matrix's Windows job was skipping the GHCR docker push
/// (docker `needs: binaries` fails closed when any matrix cell fails).
#[cfg(unix)]
async fn connect_cmr1() -> std::io::Result<UnixStream> {
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(CMR1_ABSTRACT_NAME)?;
        let std_stream = std::os::unix::net::UnixStream::connect_addr(&addr)?;
        std_stream.set_nonblocking(true)?;
        UnixStream::from_std(std_stream)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "abstract AF_UNIX sockets are Linux-only",
        ))
    }
}

/// Framing magic. Little-endian on the wire is irrelevant for the 4 ASCII
/// bytes; we compare them verbatim.
pub const FRAME_MAGIC: &[u8; 4] = b"CMR1";

const KIND_CONFIG: u8 = 1;
const KIND_FRAME: u8 = 2;
const KIND_STOP: u8 = 3;
const KIND_CAM_IN_USE: u8 = 4;

/// Reconnect backoff bounds for the resident sink socket. The cap is
/// deliberately lax — during normal pod startup the vHAL may lag the bridge
/// by a while, and a resident reconnect loop at a tight cap would spam logs.
const BACKOFF_MIN: Duration = Duration::from_millis(200);
const BACKOFF_MAX: Duration = Duration::from_secs(15);
/// Log a connect failure at warn level only every N attempts (debug otherwise).
const CONNECT_WARN_EVERY: u32 = 8;

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

/// Messages fed to the sink task (session control only — frames use
/// [`LiveFrameSlot`] so a slow AF_UNIX write never piles up stale AUs).
#[derive(Debug)]
enum SinkMsg {
    /// (Re)start a virtual-camera session with the given capability.
    Start(CameraConfig),
    /// End the session; the endpoint drops the virtual camera.
    Stop,
}

/// Single-slot live frame buffer: push overwrites any pending AU (prefer
/// latest). The writer wakes via [`Notify`]. This is the right backpressure
/// model for a real-time camera path — never ship a multi-second backlog.
struct LiveFrameSlot {
    pending: Mutex<Option<Vec<u8>>>,
    notify: Notify,
    /// How many pending AUs were overwritten before the writer consumed them.
    overwritten: AtomicU64,
    /// Cleared while no virtual-camera session is active so frames during
    /// Stop→Start gaps are discarded cheaply.
    session_active: AtomicBool,
}

impl LiveFrameSlot {
    fn new() -> Self {
        Self {
            pending: Mutex::new(None),
            notify: Notify::new(),
            overwritten: AtomicU64::new(0),
            session_active: AtomicBool::new(false),
        }
    }

    fn set_session_active(&self, active: bool) {
        self.session_active.store(active, Ordering::Release);
        if !active {
            // Drop any frame that would be undeliverable after Stop.
            let _ = self.pending.lock().unwrap_or_else(|e| e.into_inner()).take();
        }
    }

    /// Publish the latest AU. Returns how many previously-pending AUs were
    /// discarded (0 or 1). Always succeeds while the sink task is alive.
    fn push(&self, au: Vec<u8>) -> u64 {
        if !self.session_active.load(Ordering::Acquire) {
            return 0;
        }
        let mut slot = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let dropped = if slot.is_some() { 1 } else { 0 };
        *slot = Some(au);
        if dropped > 0 {
            self.overwritten.fetch_add(dropped, Ordering::Relaxed);
        }
        drop(slot);
        self.notify.notify_one();
        dropped
    }

    fn take(&self) -> Option<Vec<u8>> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

/// Outcome of [`CameraSink::push_frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushFrameOutcome {
    /// Frame is the sole pending AU for the writer.
    Queued,
    /// A still-unwritten AU was replaced by this newer one (live coalesce).
    Coalesced,
    /// No active session (before Start / after Stop) — frame ignored.
    Inactive,
}

/// Handle to the camera uplink sink task. Cheap to clone.
#[derive(Clone)]
pub struct CameraSink {
    tx: mpsc::Sender<SinkMsg>,
    frames: Arc<LiveFrameSlot>,
}

impl CameraSink {
    /// Spawn the resident sink task. The task connects immediately to the
    /// vHAL's abstract AF_UNIX CMR1 endpoint and keeps the socket open
    /// across sessions (reconnect with backoff) — it doubles as the reverse
    /// event channel. Returns the handle plus the receiver of `CamInUse`
    /// events (`true` = an in-guest app opened the camera, `false` = closed).
    ///
    /// `_sink_addr` (the legacy `CAMERA_SINK_ADDR` TCP endpoint) is retained
    /// for CLI/executor compatibility but no longer used for connection —
    /// the transport moved to a fixed abstract AF_UNIX name to bypass
    /// ReDroid's ANDROID_PARANOID_NETWORK AF_INET restriction.
    pub fn spawn(_sink_addr: String) -> (Self, mpsc::Receiver<bool>) {
        // Control channel is tiny (Start/Stop only). Frames go through the
        // live slot so a slow endpoint never builds multi-second latency.
        let (tx, rx) = mpsc::channel(16);
        let frames = Arc::new(LiveFrameSlot::new());
        let (evt_tx, evt_rx) = mpsc::channel(16);
        tokio::spawn(run_sink(rx, frames.clone(), evt_tx));
        (Self { tx, frames }, evt_rx)
    }

    /// Begin (or restart) a virtual-camera session.
    ///
    /// Session-active for the live frame slot is flipped inside the sink task
    /// when it processes `Start`, so frames cannot race ahead of the CMR1
    /// Config handshake.
    pub async fn start(&self, cfg: CameraConfig) {
        if self.tx.send(SinkMsg::Start(cfg)).await.is_err() {
            warn!("camera sink task gone; start dropped");
        }
    }

    /// Forward one Annex-B H.264 access unit. Non-blocking **prefer-latest**:
    /// a still-pending AU is overwritten so the virtual camera never plays
    /// a stale backlog. Callers should treat [`PushFrameOutcome::Coalesced`]
    /// as a decode-chain break for non-IDR frames (request a keyframe).
    pub fn push_frame(&self, au: Vec<u8>) -> PushFrameOutcome {
        if !self.frames.session_active.load(Ordering::Acquire) {
            return PushFrameOutcome::Inactive;
        }
        let dropped = self.frames.push(au);
        if dropped > 0 {
            CAMERA_FRAMES_DROPPED
                .with_label_values(&["sink_full"])
                .inc_by(dropped);
            PushFrameOutcome::Coalesced
        } else {
            PushFrameOutcome::Queued
        }
    }

    /// End the current session.
    pub async fn stop(&self) {
        // Soft-disable immediately so late AUs stop enqueueing; the sink task
        // still emits the in-band Stop on the resident socket.
        self.frames.set_session_active(false);
        let _ = self.tx.send(SinkMsg::Stop).await;
    }
}

/// Non-Unix (Windows) stub: camera injection is ReDroid/Linux-only. Drain
/// the control channel so the rest of the bridge still links, but never
/// attempt AF_UNIX.
#[cfg(not(unix))]
async fn run_sink(
    mut rx: mpsc::Receiver<SinkMsg>,
    frames: Arc<LiveFrameSlot>,
    _evt_tx: mpsc::Sender<bool>,
) {
    loop {
        // Keep the live slot from growing while we only log Start events.
        tokio::select! {
            msg = rx.recv() => match msg {
                None => return,
                Some(SinkMsg::Start(cfg)) => {
                    frames.set_session_active(true);
                    warn!(
                        ?cfg,
                        "camera uplink unavailable on non-Unix host (ReDroid/Linux only)"
                    );
                }
                Some(SinkMsg::Stop) => {
                    frames.set_session_active(false);
                }
            },
            _ = frames.notify.notified() => {
                // Discard — no AF_UNIX writer on this host.
                let _ = frames.take();
            }
        }
    }
}

/// Sink task: owns the RESIDENT connection to the in-guest camera
/// endpoint. Writes framed session messages (Config/Frame/Stop) and reads
/// reverse `CamInUse` events on the same socket. Reconnects with backoff on
/// drop; replays the active session's `Config` after a mid-session reconnect.
#[cfg(unix)]
async fn run_sink(
    mut rx: mpsc::Receiver<SinkMsg>,
    frames: Arc<LiveFrameSlot>,
    evt_tx: mpsc::Sender<bool>,
) {
    // The current session's capability, retained so a mid-session reconnect
    // can replay the `Config` handshake before resuming frames.
    let mut active: Option<CameraConfig> = None;

    'reconnect: loop {
        // ── Resident connect loop. Keep draining control while disconnected
        // so session state stays current. Live-slot frames are discarded —
        // undeliverable until the socket is up; post-reconnect PLI recovers.
        let stream = {
            let mut backoff = BACKOFF_MIN;
            let mut attempts: u32 = 0;
            loop {
                match connect_cmr1().await {
                    Ok(s) => {
                        info!("camera uplink: connected (resident, AF_UNIX @beeos_camera_cmr1)");
                        break s;
                    }
                    Err(e) => {
                        attempts += 1;
                        if attempts % CONNECT_WARN_EVERY == 1 && attempts > 1 {
                            warn!(attempts, error = %e,
                                  "camera uplink: endpoint unreachable; retrying");
                        } else {
                            debug!(attempts, error = %e, "camera uplink: connect failed");
                        }
                        // Sleep with backoff, but keep consuming session
                        // messages so `active` tracks reality.
                        let deadline = tokio::time::Instant::now() + backoff;
                        loop {
                            tokio::select! {
                                _ = tokio::time::sleep_until(deadline) => break,
                                msg = rx.recv() => match msg {
                                    None => {
                                        debug!("camera sink task exiting (all senders dropped)");
                                        return;
                                    }
                                    Some(SinkMsg::Start(cfg)) => {
                                        frames.set_session_active(true);
                                        active = Some(cfg);
                                    }
                                    Some(SinkMsg::Stop) => {
                                        frames.set_session_active(false);
                                        active = None;
                                    }
                                },
                                _ = frames.notify.notified() => {
                                    // Undeliverable while disconnected.
                                    let _ = frames.take();
                                }
                            }
                        }
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                    }
                }
            }
        };

        let (rd, mut wr) = stream.into_split();

        // Replay the in-flight session's Config so the endpoint sees it
        // before any post-reconnect frames.
        if let Some(cfg) = active.as_ref() {
            let Ok(payload) = serde_json::to_vec(cfg) else { continue 'reconnect };
            if let Err(e) = write_frame(&mut wr, KIND_CONFIG, &payload).await {
                warn!(error = %e, "camera uplink: config replay failed; reconnecting");
                continue 'reconnect;
            }
            info!(?cfg, "camera uplink: replayed session config after (re)connect");
        }

        // Reader task: parse reverse frames until EOF/error. Runs separately
        // from the writer so a partial read is never cancelled mid-frame.
        let evt_for_reader = evt_tx.clone();
        let mut reader = tokio::spawn(read_events(rd, evt_for_reader));

        // Writer loop: control messages + live-slot frames. Prefer draining
        // any pending AU after each wake so we never sit on a stale frame.
        loop {
            // Opportunistic drain before waiting — covers the race where a
            // frame was pushed just before we re-enter select.
            if active.is_some() {
                while let Some(au) = frames.take() {
                    if let Err(e) = write_frame(&mut wr, KIND_FRAME, &au).await {
                        warn!(error = %e, "camera uplink: frame write failed; reconnecting");
                        reader.abort();
                        continue 'reconnect;
                    }
                }
            } else {
                let _ = frames.take();
            }

            tokio::select! {
                _ = &mut reader => {
                    debug!("camera uplink: reader ended; reconnecting");
                    continue 'reconnect;
                }
                msg = rx.recv() => match msg {
                    None => {
                        reader.abort();
                        debug!("camera sink task exiting (all senders dropped)");
                        return;
                    }
                    Some(SinkMsg::Start(cfg)) => {
                        info!(?cfg, "camera uplink: starting virtual-camera session");
                        frames.set_session_active(true);
                        active = Some(cfg.clone());
                        let Ok(payload) = serde_json::to_vec(&cfg) else { continue };
                        if let Err(e) = write_frame(&mut wr, KIND_CONFIG, &payload).await {
                            warn!(error = %e, "camera uplink: config write failed; reconnecting");
                            reader.abort();
                            continue 'reconnect;
                        }
                    }
                    Some(SinkMsg::Stop) => {
                        // v1.1: Stop ends the session in-band; the resident
                        // connection stays up (it carries reverse events).
                        info!("camera uplink: stopping virtual-camera session");
                        frames.set_session_active(false);
                        active = None;
                        let _ = frames.take();
                        if let Err(e) = write_frame(&mut wr, KIND_STOP, &[]).await {
                            warn!(error = %e, "camera uplink: stop write failed; reconnecting");
                            reader.abort();
                            continue 'reconnect;
                        }
                    }
                },
                _ = frames.notify.notified() => {
                    // Loop top will drain the slot.
                }
            }
        }
    }
}

/// Read reverse frames (server → client) until EOF/error. Forwards decoded
/// `CamInUse` transitions to `evt_tx`; unknown kinds are skipped (forward
/// compatibility). Pre-v1.1 endpoints never write, so this simply blocks
/// until the connection drops.
#[cfg(unix)]
async fn read_events(mut rd: OwnedReadHalf, evt_tx: mpsc::Sender<bool>) {
    let mut header = [0u8; 9];
    loop {
        if rd.read_exact(&mut header).await.is_err() {
            return; // EOF / connection error → caller reconnects
        }
        if &header[..4] != FRAME_MAGIC {
            warn!("camera uplink: bad reverse-frame magic; dropping connection");
            return;
        }
        let kind = header[4];
        let len = u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;
        // Reverse events are tiny JSON payloads; anything huge means desync.
        if len > 64 * 1024 {
            warn!(len, "camera uplink: absurd reverse-frame length; dropping connection");
            return;
        }
        let mut payload = vec![0u8; len];
        if len > 0 && rd.read_exact(&mut payload).await.is_err() {
            return;
        }
        if kind != KIND_CAM_IN_USE {
            debug!(kind, "camera uplink: ignoring unknown reverse frame kind");
            continue;
        }
        match serde_json::from_slice::<serde_json::Value>(&payload) {
            Ok(v) => {
                let Some(in_use) = v.get("in_use").and_then(|b| b.as_bool()) else {
                    debug!("camera uplink: CamInUse without in_use field; ignoring");
                    continue;
                };
                info!(in_use, "camera uplink: device camera usage changed");
                if evt_tx.send(in_use).await.is_err() {
                    return; // consumer gone — nothing left to do
                }
            }
            Err(e) => {
                debug!(error = %e, "camera uplink: unparseable CamInUse payload; ignoring");
            }
        }
    }
}

/// Write one framed message: magic, kind, u32-le length, payload.
#[cfg(unix)]
async fn write_frame<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    kind: u8,
    payload: &[u8],
) -> std::io::Result<()> {
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

    #[test]
    fn config_defaults_to_h264() {
        let c = CameraConfig::new(1280, 720, 30, "front");
        assert_eq!(c.codec, "h264");
        assert_eq!(c.facing, "front");
        assert_eq!(c.width, 1280);
    }

    /// Full resident-connection round-trip against a real abstract AF_UNIX
    /// listener bound to the SAME fixed name the sink connects to. Covers:
    /// framing (Config/Frame with correct magic/kind/LE-length), reverse
    /// CamInUse surfacing on the event channel, and Stop-keepalive (a
    /// follow-up Config flows on the same still-open connection).
    ///
    /// Linux-only: the sink hard-codes the abstract-namespace name (a Linux
    /// extension), and the single fixed name means this test must run alone
    /// (there is one endpoint per process). macOS dev builds skip it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn resident_connection_framing_reverse_and_stop_keepalive() {
        use std::os::linux::net::SocketAddrExt;
        use tokio::io::AsyncReadExt;
        use tokio::net::UnixListener;

        let addr = std::os::unix::net::SocketAddr::from_abstract_name(CMR1_ABSTRACT_NAME).unwrap();
        let std_listener = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let listener = UnixListener::from_std(std_listener).unwrap();

        let (sink, mut evt_rx) = CameraSink::spawn(String::new());

        // Sink connects at spawn — no session needed (resident).
        let (mut sock, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("sink did not connect at spawn")
            .unwrap();

        // Reverse CamInUse event surfaces on the receiver.
        let payload = br#"{"in_use":true,"width":1280,"height":720}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(FRAME_MAGIC);
        frame.push(KIND_CAM_IN_USE);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        sock.write_all(&frame).await.unwrap();
        let evt = tokio::time::timeout(Duration::from_secs(5), evt_rx.recv())
            .await
            .expect("no CamInUse event")
            .unwrap();
        assert!(evt, "expected in_use=true");

        // Session start (Config) + a Frame with correct framing, then Stop
        // (keeps the socket), then a second Config on the SAME connection.
        sink.start(CameraConfig::new(640, 480, 30, "back")).await;
        // Give the writer a moment to process Start before the frame slot.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let outcome = sink.push_frame(vec![0, 0, 0, 1, 0x65, 0xAA]);
        assert!(
            matches!(
                outcome,
                PushFrameOutcome::Queued | PushFrameOutcome::Coalesced
            ),
            "expected frame to be accepted, got {outcome:?}"
        );
        // Allow the AF_UNIX writer to drain the live slot.
        tokio::time::sleep(Duration::from_millis(50)).await;
        sink.stop().await;
        sink.start(CameraConfig::new(1280, 720, 30, "front")).await;

        // Expect: Config, Frame, Stop, Config — all on one connection.
        let mut got: Vec<(u8, Vec<u8>)> = Vec::new();
        for _ in 0..4 {
            let mut header = [0u8; 9];
            tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut header))
                .await
                .expect("connection closed early — Stop must not drop the resident socket")
                .unwrap();
            assert_eq!(&header[..4], FRAME_MAGIC);
            let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; len];
            sock.read_exact(&mut payload).await.unwrap();
            got.push((header[4], payload));
        }

        assert_eq!(got[0].0, KIND_CONFIG);
        let cfg: serde_json::Value = serde_json::from_slice(&got[0].1).unwrap();
        assert_eq!(cfg["codec"], "h264");
        assert_eq!(cfg["facing"], "back");
        assert_eq!(cfg["width"], 640);
        assert_eq!(got[1], (KIND_FRAME, vec![0, 0, 0, 1, 0x65, 0xAA]));
        assert_eq!(got[2].0, KIND_STOP);
        assert_eq!(got[3].0, KIND_CONFIG);
    }
}
