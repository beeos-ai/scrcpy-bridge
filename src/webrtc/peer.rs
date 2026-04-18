//! str0m-backed WebRTC peer.
//!
//! This module owns exactly *one* [`str0m::Rtc`] instance and drives it from
//! a dedicated tokio task. All inputs come in via the [`PeerCommand`] channel
//! and all outputs leave via the [`PeerEvent`] channel, so the rest of the
//! bridge (which is `Send`-happy tokio async) never touches `Rtc` directly.
//!
//! The current implementation focuses on:
//!   * offer/answer negotiation,
//!   * trickle ICE (both directions),
//!   * H.264 sample API pass-through from scrcpy (no decode/re-encode),
//!   * a single `control` DataChannel for JSON messages.
//!
//! Performance tuning (pacer, BWE, jitter buffer sizes) and TURN candidate
//! gathering are intentionally left as follow-ups; the baseline str0m
//! defaults plus host candidates are enough to validate the spike on LAN and
//! behind a coturn instance with `TURN_URLS` pre-configured in the SDP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use str0m::change::SdpOffer;
use str0m::channel::ChannelId;
use str0m::format::Codec;
use str0m::media::{KeyframeRequestKind, MediaKind, MediaTime, Mid};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event as RtcEvent, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::scrcpy::VideoFrame;

/// TURN/STUN server description (same shape as the browser-side
/// `RTCIceServer` object we receive from the control plane).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeerOptions {
    /// ICE servers for the client; str0m doesn't relay through TURN itself,
    /// but we still surface them to the browser in the answer SDP.
    pub ice_servers: Vec<IceServer>,
    /// Local UDP bind for host candidates. `0.0.0.0:0` lets the OS pick.
    pub local_bind: SocketAddr,
    /// Additional IPs (not ports) to advertise as host candidates. Each will
    /// reuse the bound port. Lets multi-homed hosts (k8s pod IP + node IP)
    /// enumerate reachable candidates without binding more sockets.
    pub extra_local_ips: Vec<std::net::IpAddr>,
    /// Wait this long before emitting the SDP answer. Gives background
    /// candidate gathering (STUN/TURN when we wire it up) a chance to land
    /// before the browser sees the answer.
    pub ice_gather_wait: Duration,
}

impl Default for PeerOptions {
    fn default() -> Self {
        Self {
            ice_servers: vec![],
            local_bind: "0.0.0.0:0".parse().unwrap(),
            extra_local_ips: vec![],
            ice_gather_wait: Duration::ZERO,
        }
    }
}

/// Commands sent *to* the peer task.
pub enum PeerCommand {
    /// Apply a remote SDP offer. The answer SDP comes back as
    /// [`PeerEvent::Answer`].
    AcceptOffer(String),
    /// Trickle an ICE candidate from the remote peer.
    RemoteIce(String),
    /// Write a H.264 AU to the video track (config or full frame).
    WriteVideo(VideoFrame),
    /// Send a UTF-8 text message on the `control` data channel.
    SendControlText(String),
    /// Send a binary payload on the `control` data channel. Used for OPUS
    /// audio packets that the browser's AudioPlayer feeds into WebCodecs.
    SendControlBinary(Vec<u8>),
    /// Ask the encoder for a fresh keyframe.
    RequestKeyframe,
    /// Tear down the peer.
    Close,
}

/// Events emitted *from* the peer task.
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// SDP answer ready after [`PeerCommand::AcceptOffer`].
    Answer(String),
    /// Locally gathered ICE candidate (trickle to the browser via MQTT).
    LocalIce(String),
    /// Peer transitioned to `Connected`.
    Connected,
    /// Peer disconnected or failed — caller should tear down scrcpy.
    Disconnected,
    /// JSON data channel message from the browser.
    ControlMessage(String),
    /// Fatal error inside the run loop.
    Error(String),
}

/// Handle to the peer run-loop task. Cheap to clone — all fields are
/// channel handles or `Arc`s.
#[derive(Clone)]
pub struct WebRtcPeer {
    cmd_tx: mpsc::Sender<PeerCommand>,
    evt_rx: Arc<tokio::sync::Mutex<broadcast::Receiver<PeerEvent>>>,
    evt_tx: broadcast::Sender<PeerEvent>,
}

impl WebRtcPeer {
    pub fn spawn(opts: PeerOptions) -> Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (evt_tx, evt_rx) = broadcast::channel(64);
        let evt_tx_cloned = evt_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_peer(opts, cmd_rx, evt_tx_cloned.clone()).await {
                warn!(error = %e, "webrtc peer run loop exited with error");
                let _ = evt_tx_cloned.send(PeerEvent::Error(e.to_string()));
            }
        });
        Ok(Self {
            cmd_tx,
            evt_rx: Arc::new(tokio::sync::Mutex::new(evt_rx)),
            evt_tx,
        })
    }

    pub async fn accept_offer(&self, sdp: String) -> Result<()> {
        self.cmd_tx
            .send(PeerCommand::AcceptOffer(sdp))
            .await
            .map_err(|_| anyhow!("peer task has exited"))
    }

    pub async fn add_remote_ice(&self, candidate: String) -> Result<()> {
        self.cmd_tx
            .send(PeerCommand::RemoteIce(candidate))
            .await
            .map_err(|_| anyhow!("peer task has exited"))
    }

    pub async fn write_video(&self, frame: VideoFrame) -> Result<()> {
        self.cmd_tx
            .send(PeerCommand::WriteVideo(frame))
            .await
            .map_err(|_| anyhow!("peer task has exited"))
    }

    pub async fn send_control_text(&self, msg: String) -> Result<()> {
        self.cmd_tx
            .send(PeerCommand::SendControlText(msg))
            .await
            .map_err(|_| anyhow!("peer task has exited"))
    }

    /// Send a binary payload on the `control` DataChannel. Used primarily
    /// for OPUS audio packets — the browser's `AudioPlayer` receives them
    /// via `dataChannel.onmessage` when `event.data instanceof ArrayBuffer`.
    pub async fn send_control_binary(&self, payload: Vec<u8>) -> Result<()> {
        self.cmd_tx
            .send(PeerCommand::SendControlBinary(payload))
            .await
            .map_err(|_| anyhow!("peer task has exited"))
    }

    /// Best-effort non-blocking send for the hot audio path. When the peer
    /// command queue is full we prefer to drop the packet rather than back
    /// up the scrcpy audio reader.
    pub fn try_send_control_binary(&self, payload: Vec<u8>) -> bool {
        self.cmd_tx
            .try_send(PeerCommand::SendControlBinary(payload))
            .is_ok()
    }

    pub async fn close(&self) {
        let _ = self.cmd_tx.send(PeerCommand::Close).await;
    }

    /// Returns a new independent subscription to peer events.
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.evt_tx.subscribe()
    }

    /// Legacy helper – yields from the primary receiver (single-consumer).
    pub async fn next_event(&self) -> Option<PeerEvent> {
        let mut rx = self.evt_rx.lock().await;
        rx.recv().await.ok()
    }
}

// ---------------------------------------------------------------------------
// Run loop
// ---------------------------------------------------------------------------

const MAX_UDP_PAYLOAD: usize = 2000;

async fn run_peer(
    opts: PeerOptions,
    mut cmd_rx: mpsc::Receiver<PeerCommand>,
    evt_tx: broadcast::Sender<PeerEvent>,
) -> Result<()> {
    // str0m's `install_process_default()` is process-global and PANICS
    // on the second call — the previous `let _ = …` was a footgun
    // because the fn returns `Result<(), CryptoProvider>` only on the
    // FIRST call and unconditionally panics thereafter. Must guard
    // with std::sync::Once so re-connects (every new offer creates a
    // fresh peer task) don't kill the whole bridge.
    static CRYPTO_INIT: std::sync::Once = std::sync::Once::new();
    CRYPTO_INIT.call_once(|| {
        let _ = str0m::config::CryptoProvider::OpenSsl.install_process_default();
    });

    let socket = UdpSocket::bind(opts.local_bind).await.context("bind udp")?;
    let local_addr = socket.local_addr()?;
    info!(%local_addr, "WebRTC UDP socket bound");

    let mut rtc = Rtc::builder()
        .set_rtp_mode(false)
        .enable_raw_packets(false)
        .build();

    // Host candidates must be concrete addresses — str0m/ICE rejects
    // `0.0.0.0` / `::`. When we bind to a wildcard (`opts.local_bind =
    // 0.0.0.0:0`, which is the default to let the OS pick a port and
    // to receive traffic on any interface) we deliberately SKIP the
    // wildcard as a candidate and rely on `extra_local_ips` for the
    // real per-interface addresses. Callers are expected to enumerate
    // interfaces and pass them in; if `extra_local_ips` is also empty
    // (e.g. misconfiguration) we fall back to `127.0.0.1` so at least
    // same-machine WebRTC still works — the common path during local
    // dev smoke tests.
    let ip_is_wildcard = local_addr.ip().is_unspecified();
    if !ip_is_wildcard {
        let candidate = Candidate::host(local_addr, "udp")
            .map_err(|e| anyhow!("build host candidate: {e}"))?;
        rtc.add_local_candidate(candidate);
    } else if opts.extra_local_ips.is_empty() {
        let fallback = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            local_addr.port(),
        );
        warn!(
            %local_addr,
            "UDP bound to wildcard and no extra_local_ips configured; \
             falling back to 127.0.0.1 host candidate (loopback only)"
        );
        let candidate = Candidate::host(fallback, "udp")
            .map_err(|e| anyhow!("build loopback host candidate: {e}"))?;
        rtc.add_local_candidate(candidate);
    }
    for ip in &opts.extra_local_ips {
        let sa = SocketAddr::new(*ip, local_addr.port());
        match Candidate::host(sa, "udp") {
            Ok(c) => {
                info!(addr = %sa, "adding extra host candidate");
                rtc.add_local_candidate(c);
            }
            Err(e) => warn!(addr = %sa, error = %e, "extra host candidate rejected"),
        }
    }

    let mut state = PeerState::default();
    state.ice_servers = opts.ice_servers.clone();
    state.ice_gather_wait = opts.ice_gather_wait;

    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];

    loop {
        // 1. Drain str0m outputs.
        loop {
            match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
                Output::Timeout(when) => {
                    let now = Instant::now();
                    let delay = if when > now {
                        when - now
                    } else {
                        Duration::ZERO
                    };
                    // Wait for the earliest of (timeout, UDP packet, command).
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {
                            rtc.handle_input(Input::Timeout(Instant::now()))
                                .map_err(|e| anyhow!("handle_input(Timeout): {e}"))?;
                        }
                        res = socket.recv_from(&mut buf) => {
                            match res {
                                Ok((n, src)) => {
                                    let contents = (&buf[..n])
                                        .try_into()
                                        .map_err(|_| anyhow!("invalid incoming udp packet"))?;
                                    rtc.handle_input(Input::Receive(
                                        Instant::now(),
                                        Receive {
                                            proto: Protocol::Udp,
                                            source: src,
                                            destination: local_addr,
                                            contents,
                                        },
                                    ))
                                    .map_err(|e| anyhow!("handle_input(Receive): {e}"))?;
                                }
                                Err(e) => warn!(error=%e, "udp recv"),
                            }
                        }
                        cmd = cmd_rx.recv() => {
                            match cmd {
                                None => return Ok(()),
                                Some(cmd) => {
                                    if !handle_command(cmd, &mut rtc, &mut state, &evt_tx).await? {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                    break; // go re-drain poll_output
                }
                Output::Transmit(t) => {
                    if let Err(e) = socket.send_to(&t.contents, t.destination).await {
                        warn!(error = %e, dest = %t.destination, "udp send");
                    }
                }
                Output::Event(evt) => handle_rtc_event(evt, &mut rtc, &mut state, &evt_tx).await?,
            }
        }
    }
}

async fn handle_command(
    cmd: PeerCommand,
    rtc: &mut Rtc,
    state: &mut PeerState,
    evt_tx: &broadcast::Sender<PeerEvent>,
) -> Result<bool> {
    match cmd {
        PeerCommand::AcceptOffer(sdp) => {
            let offer = SdpOffer::from_sdp_string(&sdp)
                .map_err(|e| anyhow!("parse offer sdp: {e}"))?;
            // `accept_offer` bakes the current set of local candidates into
            // the answer SDP synchronously — so candidates must already be
            // added via `rtc.add_local_candidate` before we get here. The
            // `ice_gather_wait` window gives future STUN/TURN gathering a
            // chance to land before the answer is shipped; for now the delay
            // is just a no-op buffer.
            if !state.ice_gather_wait.is_zero() {
                tokio::time::sleep(state.ice_gather_wait).await;
            }
            let answer = rtc
                .sdp_api()
                .accept_offer(offer)
                .map_err(|e| anyhow!("accept_offer: {e}"))?;
            let _ = evt_tx.send(PeerEvent::Answer(answer.to_sdp_string()));
        }
        PeerCommand::RemoteIce(cand) => {
            // Chrome hides local IPs behind mDNS `.local` hostnames by default
            // (chrome://flags/#enable-webrtc-hide-local-ips-with-mdns). str0m's
            // SDP parser cannot handle these, so silently drop them here and
            // rely on peer-reflexive candidate learning (the remote peer will
            // still hit our advertised LAN IPs and we'll learn its real
            // srcaddr from the incoming STUN binding). Keep warn! for other
            // parse errors so real issues stay visible.
            if is_mdns_candidate(&cand) {
                debug!(candidate = %cand, "ignoring mDNS .local remote candidate (relying on peer-reflexive)");
            } else {
                match Candidate::from_sdp_string(&cand) {
                    Ok(c) => rtc.add_remote_candidate(c),
                    Err(e) => warn!(error = %e, "parse remote candidate"),
                }
            }
        }
        PeerCommand::WriteVideo(frame) => {
            if let Some(mid) = state.video_mid {
                let writer = match rtc.writer(mid) {
                    Some(w) => w,
                    None => {
                        debug!("video writer not available yet");
                        return Ok(true);
                    }
                };
                let pt = writer
                    .payload_params()
                    .find(|p| p.spec().codec == Codec::H264)
                    .map(|p| p.pt());
                let Some(pt) = pt else {
                    debug!("no H264 PT negotiated yet");
                    return Ok(true);
                };
                let media_time = MediaTime::from_micros(frame.pts_us);
                let wallclock = Instant::now();
                if let Err(e) = writer.write(pt, wallclock, media_time, frame.data) {
                    warn!(error = %e, "video write");
                }
            }
        }
        PeerCommand::SendControlText(text) => {
            if let Some(cid) = state.control_channel {
                if let Some(mut chan) = rtc.channel(cid) {
                    // `binary=false` — browser sees this as `event.data: string`.
                    if let Err(e) = chan.write(false, text.as_bytes()) {
                        warn!(error = %e, "datachannel write");
                    }
                }
            } else {
                debug!("datachannel not open; dropping control message");
            }
        }
        PeerCommand::SendControlBinary(payload) => {
            if let Some(cid) = state.control_channel {
                if let Some(mut chan) = rtc.channel(cid) {
                    // `binary=true` — browser sees this as `event.data: ArrayBuffer`,
                    // which `AudioPlayer.feed()` expects.
                    if let Err(e) = chan.write(true, &payload) {
                        warn!(error = %e, "datachannel binary write");
                    }
                }
            } else {
                debug!("datachannel not open; dropping binary payload");
            }
        }
        PeerCommand::RequestKeyframe => {
            if let Some(mid) = state.video_mid {
                if let Some(mut writer) = rtc.writer(mid) {
                    let _ = writer.request_keyframe(None, KeyframeRequestKind::Pli);
                }
            }
        }
        PeerCommand::Close => {
            rtc.disconnect();
            let _ = evt_tx.send(PeerEvent::Disconnected);
            return Ok(false);
        }
    }
    Ok(true)
}

async fn handle_rtc_event(
    evt: RtcEvent,
    _rtc: &mut Rtc,
    state: &mut PeerState,
    evt_tx: &broadcast::Sender<PeerEvent>,
) -> Result<()> {
    match evt {
        RtcEvent::IceConnectionStateChange(s) => {
            info!(state = ?s, "ICE connection state");
            match s {
                IceConnectionState::Connected | IceConnectionState::Completed => {
                    let _ = evt_tx.send(PeerEvent::Connected);
                }
                IceConnectionState::Disconnected => {
                    // str0m's Disconnected is transient — log only and let
                    // ICE restart attempt to recover. Hard failure surfaces
                    // via Rtc::disconnect or the top-level error path.
                    let _ = evt_tx.send(PeerEvent::Disconnected);
                }
                _ => {}
            }
        }
        RtcEvent::MediaAdded(m) => {
            if m.kind == MediaKind::Video {
                state.video_mid = Some(m.mid);
                info!(mid = ?m.mid, "video media track ready");
            }
        }
        RtcEvent::ChannelOpen(cid, label) => {
            info!(%label, "data channel open");
            if label == "control" || state.control_channel.is_none() {
                state.control_channel = Some(cid);
            }
        }
        RtcEvent::ChannelData(d) => {
            if let Ok(text) = std::str::from_utf8(&d.data) {
                let _ = evt_tx.send(PeerEvent::ControlMessage(text.to_string()));
            }
        }
        RtcEvent::ChannelClose(_cid) => {
            state.control_channel = None;
        }
        // NOTE: str0m 0.9 does not emit a dedicated local-ICE-candidate event.
        // Local candidates are baked into the answer SDP after gathering. For
        // trickle ICE we would need to diff poll_output() Transmit addresses;
        // for now, the answer SDP carries all host candidates, which matches
        // the Python agent's behaviour (it also waits for gathering_done).
        _ => {}
    }
    Ok(())
}

#[derive(Default)]
struct PeerState {
    video_mid: Option<Mid>,
    control_channel: Option<ChannelId>,
    ice_servers: Vec<IceServer>,
    ice_gather_wait: Duration,
}

/// Detect Chrome's mDNS-hidden ICE candidates (`xxx.local`).
///
/// Format reference (RFC 8839 §5.1):
///
/// ```text
/// candidate:<foundation> <component> <transport> <priority> \
///     <connection-address> <port> typ <type> ...
/// ```
///
/// The 5th space-separated field is the connection address; if it ends
/// with `.local` (case-insensitive), it's an mDNS hostname that str0m's
/// parser cannot resolve.
fn is_mdns_candidate(sdp_line: &str) -> bool {
    let line = sdp_line.strip_prefix("candidate:").unwrap_or(sdp_line);
    line.split_ascii_whitespace()
        .nth(4)
        .map(|addr| addr.to_ascii_lowercase().ends_with(".local"))
        .unwrap_or(false)
}

#[cfg(test)]
mod mdns_tests {
    use super::is_mdns_candidate;

    #[test]
    fn detects_mdns_hostname() {
        let cand = "candidate:2200977846 1 udp 2113937151 \
            71aada4d-e490-4a53-b326-c39343708736.local 60405 typ host \
            generation 0 ufrag H2gb network-cost 999";
        assert!(is_mdns_candidate(cand));
    }

    #[test]
    fn detects_mdns_with_prefix() {
        let cand = "a=candidate:1 1 udp 2113937151 abc.LOCAL 60000 typ host";
        assert!(is_mdns_candidate(cand.trim_start_matches("a=")));
    }

    #[test]
    fn ignores_ipv4_host() {
        let cand = "candidate:1 1 udp 2113937151 192.168.3.192 60000 typ host";
        assert!(!is_mdns_candidate(cand));
    }

    #[test]
    fn ignores_srflx() {
        let cand = "candidate:1 1 udp 1677729535 203.0.113.10 50000 typ srflx \
            raddr 192.168.1.2 rport 60000";
        assert!(!is_mdns_candidate(cand));
    }
}
