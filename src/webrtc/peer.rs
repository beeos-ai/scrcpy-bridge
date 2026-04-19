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

use crate::scrcpy::{AudioPacket, VideoFrame};

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
    /// Write an Opus packet to the audio track as native WebRTC RTP.
    WriteAudio(AudioPacket),
    /// Send a UTF-8 text message on the `control` data channel.
    SendControlText(String),
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
    /// Both ICE is connected AND video/audio mids have been negotiated — the
    /// media pipeline can now actually carry traffic. The bridge uses this
    /// edge to proactively ask scrcpy for a fresh IDR so the first visible
    /// frame lands without waiting for the browser's first PLI.
    StreamReady,
    /// Transient ICE loss. str0m considers this recoverable via ICE
    /// restart; the bridge should arm its session-hold grace window
    /// but NOT tear down scrcpy yet. In str0m 0.9 this state
    /// additionally covers "hard failure" — the bridge's grace
    /// window makes the final teardown decision, not the peer.
    Disconnected,
    /// JSON data channel message from the browser.
    ControlMessage(String),
    /// Browser asked for a keyframe (PLI/FIR). Caller should ask the scrcpy
    /// encoder for a fresh IDR via `ResetVideo`.
    KeyframeRequested,
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

    /// Non-blocking video write. Drops the frame if the command queue is
    /// full — the bridge's video_task uses this for drop-oldest backpressure
    /// on non-keyframe deltas so the scrcpy reader never stalls on a slow
    /// peer task.
    pub fn try_write_video(&self, frame: VideoFrame) -> bool {
        self.cmd_tx
            .try_send(PeerCommand::WriteVideo(frame))
            .is_ok()
    }

    pub async fn write_audio(&self, pkt: AudioPacket) -> Result<()> {
        self.cmd_tx
            .send(PeerCommand::WriteAudio(pkt))
            .await
            .map_err(|_| anyhow!("peer task has exited"))
    }

    /// Non-blocking audio write. Drops the packet when the command queue is
    /// full. Realtime audio has a hard "late = useless" contract — queuing
    /// up more than a handful of 20 ms Opus frames just adds latency with
    /// no quality benefit.
    pub fn try_write_audio(&self, pkt: AudioPacket) -> bool {
        self.cmd_tx
            .try_send(PeerCommand::WriteAudio(pkt))
            .is_ok()
    }

    pub async fn send_control_text(&self, msg: String) -> Result<()> {
        self.cmd_tx
            .send(PeerCommand::SendControlText(msg))
            .await
            .map_err(|_| anyhow!("peer task has exited"))
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
    // wildcard as a candidate and rely on `extra_local_ips` plus a
    // 127.0.0.1 loopback candidate. Loopback is always emitted so that
    // same-machine WebRTC (the common dev path) works even when Chrome
    // hides its real LAN IP behind mDNS `.local` candidates — which we
    // drop at the bridge side because str0m cannot parse mDNS.
    // Track every concrete local candidate IP we register. We need this
    // at receive-time because the UDP socket is wildcard-bound, but str0m's
    // ICE agent only knows packets that arrive on a *concrete* local
    // candidate — if we hand it `0.0.0.0:port` it discards the STUN request
    // as "unknown interface" and ICE never completes.
    let mut local_candidate_ips: Vec<std::net::IpAddr> = Vec::new();
    let ip_is_wildcard = local_addr.ip().is_unspecified();
    if !ip_is_wildcard {
        let candidate = Candidate::host(local_addr, "udp")
            .map_err(|e| anyhow!("build host candidate: {e}"))?;
        rtc.add_local_candidate(candidate);
        local_candidate_ips.push(local_addr.ip());
    } else {
        let loopback = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            local_addr.port(),
        );
        match Candidate::host(loopback, "udp") {
            Ok(c) => {
                info!(addr = %loopback, "adding loopback host candidate");
                rtc.add_local_candidate(c);
                local_candidate_ips.push(loopback.ip());
            }
            Err(e) => warn!(addr = %loopback, error = %e, "loopback candidate rejected"),
        }
    }
    for ip in &opts.extra_local_ips {
        let sa = SocketAddr::new(*ip, local_addr.port());
        match Candidate::host(sa, "udp") {
            Ok(c) => {
                info!(addr = %sa, "adding extra host candidate");
                rtc.add_local_candidate(c);
                local_candidate_ips.push(*ip);
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
                                    if !state.logged_first_packet {
                                        info!(bytes = n, %src, "first UDP packet received on WebRTC socket");
                                        state.logged_first_packet = true;
                                    }
                                    // Wildcard-bound sockets hand us `0.0.0.0:port`
                                    // as the local addr, which str0m refuses as an
                                    // "unknown interface" and silently discards.
                                    // Pick the most likely local candidate IP based
                                    // on the packet's source, so ICE can match the
                                    // pair and complete.
                                    let dest = if ip_is_wildcard {
                                        SocketAddr::new(
                                            pick_local_ip(&local_candidate_ips, src.ip()),
                                            local_addr.port(),
                                        )
                                    } else {
                                        local_addr
                                    };
                                    let contents = (&buf[..n])
                                        .try_into()
                                        .map_err(|_| anyhow!("invalid incoming udp packet"))?;
                                    rtc.handle_input(Input::Receive(
                                        Instant::now(),
                                        Receive {
                                            proto: Protocol::Udp,
                                            source: src,
                                            destination: dest,
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
                    if !state.logged_first_transmit {
                        info!(bytes = t.contents.len(), dest = %t.destination, "first UDP packet transmit (likely STUN reply)");
                        state.logged_first_transmit = true;
                    }
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
            let sdp = answer.to_sdp_string();
            let candidate_lines: Vec<&str> = sdp
                .lines()
                .filter(|l| l.starts_with("a=candidate:"))
                .collect();
            info!(candidates = ?candidate_lines, "answer SDP candidates");
            let _ = evt_tx.send(PeerEvent::Answer(sdp));
        }
        PeerCommand::RemoteIce(cand) => {
            // Chrome hides local IPs behind mDNS `.local` hostnames by default
            // (chrome://flags/#enable-webrtc-hide-local-ips-with-mdns). str0m's
            // SDP parser cannot resolve those, so for local/same-machine dev
            // we rewrite the connection-address to 127.0.0.1 and add the
            // rewritten candidate. On a different host the rewritten loopback
            // simply fails connectivity checks (harmless) and we still rely
            // on srflx/relay candidates from the remote peer.
            info!(candidate = %cand, "received remote ICE candidate");
            if is_mdns_candidate(&cand) {
                match rewrite_mdns_to_loopback(&cand) {
                    Some(rewritten) => match Candidate::from_sdp_string(&rewritten) {
                        Ok(c) => {
                            info!(original = %cand, rewritten = %rewritten, "rewrote mDNS candidate to loopback");
                            rtc.add_remote_candidate(c);
                        }
                        Err(e) => warn!(error = %e, "parse rewritten mDNS candidate"),
                    },
                    None => {
                        info!(candidate = %cand, "ignoring mDNS .local remote candidate (rewrite failed)");
                    }
                }
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
        PeerCommand::WriteAudio(pkt) => {
            // scrcpy emits a 19-byte `OpusHead` config packet as its first
            // audio frame. RTP Opus tracks negotiate sample-rate/channels
            // via SDP (`a=rtpmap:... opus/48000/2`), so OpusHead is useless
            // on the wire and would just confuse the decoder if forwarded.
            if pkt.is_config {
                return Ok(true);
            }
            if let Some(mid) = state.audio_mid {
                let writer = match rtc.writer(mid) {
                    Some(w) => w,
                    None => {
                        debug!("audio writer not available yet");
                        return Ok(true);
                    }
                };
                let pt = writer
                    .payload_params()
                    .find(|p| p.spec().codec == Codec::Opus)
                    .map(|p| p.pt());
                let Some(pt) = pt else {
                    debug!("no Opus PT negotiated yet");
                    return Ok(true);
                };
                let media_time = MediaTime::from_micros(pkt.pts_us);
                let wallclock = Instant::now();
                if let Err(e) = writer.write(pt, wallclock, media_time, pkt.data) {
                    warn!(error = %e, "audio write");
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
    // Catch-all debug so we can see every str0m event during ICE debugging.
    info!(event = ?evt, "str0m event");
    match evt {
        RtcEvent::IceConnectionStateChange(s) => {
            info!(state = ?s, "ICE connection state");
            match s {
                IceConnectionState::Connected | IceConnectionState::Completed => {
                    state.ice_connected = true;
                    let _ = evt_tx.send(PeerEvent::Connected);
                    maybe_emit_stream_ready(state, evt_tx);
                }
                IceConnectionState::Disconnected => {
                    // str0m 0.9 collapses "transient disconnect" and
                    // "hard failure" into a single state (see comment
                    // on `IceConnectionState` in str0m: "the failed
                    // and closed state doesn't really have a mapping
                    // in this implementation"). The bridge therefore
                    // treats every Disconnected as "arm grace window"
                    // and lets the grace timer decide whether to tear
                    // down scrcpy or wait for a same-viewer offer.
                    //
                    // Deliberately do NOT call `rtc.disconnect()`: a
                    // viewer-driven `accept_offer` with new
                    // ice-ufrag/pwd can still perform a true ICE
                    // restart on this `Rtc` instance.
                    state.ice_connected = false;
                    state.stream_ready_emitted = false;
                    let _ = evt_tx.send(PeerEvent::Disconnected);
                }
                _ => {}
            }
        }
        RtcEvent::MediaAdded(m) => {
            match m.kind {
                MediaKind::Video => {
                    state.video_mid = Some(m.mid);
                    info!(mid = ?m.mid, "video media track ready");
                }
                MediaKind::Audio => {
                    state.audio_mid = Some(m.mid);
                    info!(mid = ?m.mid, "audio media track ready");
                }
            }
            maybe_emit_stream_ready(state, evt_tx);
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
        RtcEvent::KeyframeRequest(_) => {
            // Browser sent PLI/FIR — forward to the bridge so it can ask
            // scrcpy for a fresh IDR. Without this, the receiver-side
            // decoder stays stuck after packet loss and spams keyframe
            // requests until the 30 s watchdog tears the session down.
            let _ = evt_tx.send(PeerEvent::KeyframeRequested);
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
    audio_mid: Option<Mid>,
    control_channel: Option<ChannelId>,
    ice_servers: Vec<IceServer>,
    ice_gather_wait: Duration,
    logged_first_packet: bool,
    logged_first_transmit: bool,
    /// Tracks whether we've already fired `PeerEvent::StreamReady` for the
    /// current ICE session. Cleared on every `Disconnected` so an ICE
    /// restart re-arms the proactive-keyframe signal.
    stream_ready_emitted: bool,
    /// Cached ICE-connected flag. We fire `StreamReady` at the edge where
    /// ICE is up AND at least the video mid is known — whichever happens
    /// second.
    ice_connected: bool,
}

/// Fire `StreamReady` once per ICE session as soon as both preconditions
/// are met (ICE connected + video mid negotiated). Audio is optional —
/// some devices disable audio encoding so requiring audio_mid would
/// deadlock keyframe bootstrap on those devices.
fn maybe_emit_stream_ready(state: &mut PeerState, evt_tx: &broadcast::Sender<PeerEvent>) {
    if state.stream_ready_emitted {
        return;
    }
    if !state.ice_connected || state.video_mid.is_none() {
        return;
    }
    state.stream_ready_emitted = true;
    let _ = evt_tx.send(PeerEvent::StreamReady);
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

/// Rewrite the connection-address (5th field) of an SDP ICE candidate line
/// from a `.local` mDNS hostname to `127.0.0.1`. Returns None if the line
/// is malformed. Preserves the original `a=` prefix handling.
fn rewrite_mdns_to_loopback(sdp_line: &str) -> Option<String> {
    let (prefix, body) = if let Some(stripped) = sdp_line.strip_prefix("a=") {
        ("a=", stripped)
    } else {
        ("", sdp_line)
    };
    let mut parts: Vec<&str> = body.split_ascii_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    if !parts[4].to_ascii_lowercase().ends_with(".local") {
        return None;
    }
    parts[4] = "127.0.0.1";
    Some(format!("{}{}", prefix, parts.join(" ")))
}

/// Pick the most plausible local candidate IP to tag an incoming UDP packet
/// with when the underlying socket is wildcard-bound.
///
/// Heuristic:
/// * loopback src → loopback local IP (falling back to the first IP of the
///   same family),
/// * otherwise, prefer a local IP that shares the first 3 octets of the IPv4
///   source (same /24) so multi-homed hosts still match the right interface,
/// * else pick the first local IP of the same family,
/// * last resort, return the first local IP (or the source IP itself if we
///   somehow have no candidates, which would indicate a logic error upstream).
fn pick_local_ip(local_ips: &[std::net::IpAddr], src: std::net::IpAddr) -> std::net::IpAddr {
    if local_ips.is_empty() {
        return src;
    }
    let same_family = |ip: &std::net::IpAddr| ip.is_ipv4() == src.is_ipv4();
    if src.is_loopback() {
        if let Some(ip) = local_ips.iter().find(|ip| ip.is_loopback() && same_family(ip)) {
            return *ip;
        }
    }
    if let (std::net::IpAddr::V4(src_v4), _) = (src, ()) {
        let src_octets = src_v4.octets();
        if let Some(ip) = local_ips.iter().find(|ip| match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                !v4.is_loopback() && o[0] == src_octets[0] && o[1] == src_octets[1] && o[2] == src_octets[2]
            }
            _ => false,
        }) {
            return *ip;
        }
    }
    if let Some(ip) = local_ips.iter().find(|ip| same_family(ip) && !ip.is_loopback()) {
        return *ip;
    }
    if let Some(ip) = local_ips.iter().find(|ip| same_family(ip)) {
        return *ip;
    }
    local_ips[0]
}

#[cfg(test)]
mod mdns_tests {
    use super::{is_mdns_candidate, rewrite_mdns_to_loopback};

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

    #[test]
    fn rewrites_mdns_to_loopback() {
        let cand = "candidate:2200977846 1 udp 2113937151 \
            71aada4d-e490-4a53-b326-c39343708736.local 60405 typ host \
            generation 0 ufrag H2gb network-cost 999";
        let rewritten = rewrite_mdns_to_loopback(cand).expect("rewrite should succeed");
        assert!(rewritten.contains("127.0.0.1"));
        assert!(!rewritten.contains(".local"));
        assert!(rewritten.contains("60405"));
    }

    #[test]
    fn rewrite_preserves_a_prefix() {
        let cand = "a=candidate:1 1 udp 2113937151 abc.LOCAL 60000 typ host";
        let rewritten = rewrite_mdns_to_loopback(cand).expect("rewrite should succeed");
        assert!(rewritten.starts_with("a=candidate:"));
        assert!(rewritten.contains("127.0.0.1"));
    }

    #[test]
    fn rewrite_skips_non_mdns() {
        let cand = "candidate:1 1 udp 2113937151 192.168.1.1 60000 typ host";
        assert!(rewrite_mdns_to_loopback(cand).is_none());
    }
}

#[cfg(test)]
mod sdp_tests {
    use str0m::change::SdpOffer;
    use str0m::format::Codec;
    use str0m::media::{MediaKind, Mid};
    use str0m::{Event as RtcEvent, Rtc};

    /// Chrome-style recvonly SDP offer carrying both video (H.264) and
    /// audio (Opus) m-lines. Every mandatory attribute str0m needs
    /// (ice-ufrag/pwd, fingerprint, setup, rtpmap for payload types) is
    /// present; ICE candidates are intentionally absent — the peer code
    /// trickles them separately via `RemoteIce`.
    const CHROME_OFFER: &str = "\
v=0\r\n\
o=- 8999999999 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0 1 2\r\n\
a=msid-semantic: WMS *\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 102\r\n\
c=IN IP4 0.0.0.0\r\n\
a=rtcp:9 IN IP4 0.0.0.0\r\n\
a=ice-ufrag:abcd\r\n\
a=ice-pwd:0123456789abcdef0123456789abcdef\r\n\
a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=extmap:3 urn:3gpp:video-orientation\r\n\
a=recvonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:102 H264/90000\r\n\
a=rtcp-fb:102 nack\r\n\
a=rtcp-fb:102 nack pli\r\n\
a=rtcp-fb:102 ccm fir\r\n\
a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
c=IN IP4 0.0.0.0\r\n\
a=rtcp:9 IN IP4 0.0.0.0\r\n\
a=ice-ufrag:abcd\r\n\
a=ice-pwd:0123456789abcdef0123456789abcdef\r\n\
a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
a=setup:actpass\r\n\
a=mid:1\r\n\
a=recvonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=fmtp:111 minptime=10;useinbandfec=1\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:abcd\r\n\
a=ice-pwd:0123456789abcdef0123456789abcdef\r\n\
a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\r\n\
a=setup:actpass\r\n\
a=mid:2\r\n\
a=sctp-port:5000\r\n\
a=max-message-size:262144\r\n";

    /// Accepting a Chrome-style offer with both audio+video m-lines must
    /// produce an answer SDP that mirrors both m-lines with matching
    /// rtpmap entries (H.264/90000 and opus/48000/2). `MediaAdded` events
    /// only fire post-DTLS, so we can't verify them without a full L/R
    /// pair — but the answer SDP is synchronous and is what the browser
    /// actually sees, so it's the right integration boundary to lock
    /// down here.
    #[test]
    fn sdp_negotiates_audio_and_video() {
        let mut rtc = Rtc::new();
        let offer = SdpOffer::from_sdp_string(CHROME_OFFER).expect("parse Chrome offer");
        let answer = rtc
            .sdp_api()
            .accept_offer(offer)
            .expect("str0m should accept Chrome offer");
        let sdp = answer.to_sdp_string();

        let has_video_m = sdp.lines().any(|l| l.starts_with("m=video"));
        let has_audio_m = sdp.lines().any(|l| l.starts_with("m=audio"));
        assert!(has_video_m, "answer missing m=video line:\n{sdp}");
        assert!(has_audio_m, "answer missing m=audio line:\n{sdp}");

        let has_h264 = sdp.contains("H264/90000");
        let has_opus = sdp.contains("opus/48000/2");
        assert!(has_h264, "answer missing H264 rtpmap:\n{sdp}");
        assert!(has_opus, "answer missing Opus rtpmap:\n{sdp}");

        // Suppress unused-import warning for RtcEvent / Mid / MediaKind —
        // they're consumed by the other test in this module.
        let _ = (RtcEvent::IceConnectionStateChange(str0m::IceConnectionState::New),
                  Mid::from("m"), MediaKind::Video, Codec::Opus);
    }
}

#[cfg(test)]
mod stream_ready_tests {
    use super::{maybe_emit_stream_ready, PeerEvent, PeerState};
    use str0m::media::Mid;
    use tokio::sync::broadcast;

    /// `maybe_emit_stream_ready` must only fire once both preconditions
    /// are true (ICE connected AND video mid is negotiated), and must
    /// only fire once per ICE session. The `stream_ready_emitted` latch
    /// is the sole guard against re-priming the keyframe on every
    /// `MediaAdded` poll iteration.
    #[test]
    fn emits_once_when_ice_and_video_mid_both_ready() {
        let (tx, mut rx) = broadcast::channel(4);
        let mut state = PeerState::default();

        // Neither precondition met yet — no event.
        maybe_emit_stream_ready(&mut state, &tx);
        assert!(rx.try_recv().is_err());

        state.ice_connected = true;
        maybe_emit_stream_ready(&mut state, &tx);
        assert!(rx.try_recv().is_err(), "should wait for video_mid");

        state.video_mid = Some(Mid::from("v"));
        maybe_emit_stream_ready(&mut state, &tx);
        assert!(
            matches!(rx.try_recv(), Ok(PeerEvent::StreamReady)),
            "should fire once both preconditions are met"
        );

        // Second call must be a no-op within the same ICE session —
        // otherwise we'd spam reset_video on every MediaAdded.
        maybe_emit_stream_ready(&mut state, &tx);
        assert!(rx.try_recv().is_err(), "must not re-fire without ICE reset");

        // An ICE disconnect clears the latch; next Connected+mid re-arms it.
        state.ice_connected = false;
        state.stream_ready_emitted = false;
        state.ice_connected = true;
        maybe_emit_stream_ready(&mut state, &tx);
        assert!(matches!(rx.try_recv(), Ok(PeerEvent::StreamReady)));
    }
}
