//! WebRTC peer backed by `webrtc-rs`.
//!
//! The previous str0m transport only advertised pod host candidates. That is
//! insufficient across public browsers and private OKE pod networks: neither
//! side can route to the other's host candidate. This implementation consumes
//! the Runtime-provided ICE servers and, whenever TURN is present, requires a
//! relay candidate for the service side as well.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use media::Sample;
use rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtp::codecs::h264::H264Packet;
use rtp::packetizer::Depacketizer;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, info, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::{MediaEngine, MIME_TYPE_H264, MIME_TYPE_OPUS};
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice::network_type::NetworkType;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_gatherer_state::RTCIceGathererState;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;

use crate::scrcpy::{AudioPacket, VideoFrame};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoTransport {
    Rtp,
    DataChannel,
}

impl VideoTransport {
    fn as_u8(self) -> u8 {
        match self {
            Self::Rtp => 0,
            Self::DataChannel => 1,
        }
    }

    fn from_u8(value: u8) -> Self {
        if value == 1 {
            Self::DataChannel
        } else {
            Self::Rtp
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeerOptions {
    pub ice_servers: Vec<IceServer>,
    /// Retained for API compatibility with the old transport. webrtc-rs owns
    /// its sockets and binds an ephemeral IPv4 UDP port itself.
    pub local_bind: SocketAddr,
    /// Retained for local/self-host callers; TURN-backed cloud sessions do not
    /// advertise hand-built host candidates.
    pub extra_local_ips: Vec<std::net::IpAddr>,
    /// Legacy gathering wait hint. TURN-backed sessions use at least ten
    /// seconds for background relay validation. SDP answers are still
    /// published immediately and candidates trickle independently.
    pub ice_gather_wait: Duration,
}

impl Default for PeerOptions {
    fn default() -> Self {
        Self {
            ice_servers: vec![],
            local_bind: "0.0.0.0:0".parse().expect("valid bind address"),
            extra_local_ips: vec![],
            ice_gather_wait: Duration::ZERO,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiationKind {
    Initial,
    MediaRenegotiation,
    IceRestart,
}

impl NegotiationKind {
    fn starts_ice_generation(self) -> bool {
        matches!(self, Self::Initial | Self::IceRestart)
    }
}

pub enum PeerCommand {
    AcceptOffer {
        sdp: String,
        kind: NegotiationKind,
        done: oneshot::Sender<std::result::Result<(), String>>,
    },
    RemoteIce(String),
    WriteVideo(VideoFrame),
    WriteVideoBinary(Vec<u8>),
    WriteAudio(AudioPacket),
    SendControlText(String),
    RequestKeyframe,
    SetCameraSink(Option<mpsc::Sender<CameraFrame>>),
    RequestCameraKeyframe,
    Close,
}

#[derive(Debug, Clone)]
pub struct CameraFrame {
    pub data: Vec<u8>,
    pub pts_us: i64,
}

#[derive(Debug, Clone)]
pub enum PeerEvent {
    Answer(String),
    LocalIce(String),
    Connected,
    StreamReady,
    Disconnected,
    ControlMessage(String),
    ControlChannelOpen,
    KeyframeRequested,
    Error(String),
}

#[derive(Default)]
struct CandidateGateState {
    generation: u64,
    answer_published: bool,
    pending_candidates: Vec<String>,
    relay_seen: bool,
    gathering_complete: bool,
    failure_reported: bool,
}

/// Orders trickled candidates behind their SDP answer and enforces the
/// service-side TURN policy without blocking the peer command loop.
///
/// WebRTC candidate gathering is a state machine, not a one-shot event. A
/// media-only renegotiation reuses the current ICE generation and may never
/// emit another `Complete` transition. Keeping the generation state here
/// prevents that renegotiation from waiting on an event that cannot occur.
#[derive(Clone)]
struct LocalCandidateGate {
    state: Arc<Mutex<CandidateGateState>>,
    evt_tx: broadcast::Sender<PeerEvent>,
    require_relay: bool,
    relay_deadline: Duration,
}

impl LocalCandidateGate {
    fn new(
        evt_tx: broadcast::Sender<PeerEvent>,
        require_relay: bool,
        relay_deadline: Duration,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(CandidateGateState::default())),
            evt_tx,
            require_relay,
            relay_deadline,
        }
    }

    async fn begin_answer(&self, starts_ice_generation: bool) {
        let generation = {
            let mut state = self.state.lock().await;
            if starts_ice_generation {
                state.generation = state.generation.wrapping_add(1);
                state.pending_candidates.clear();
                state.relay_seen = false;
                state.gathering_complete = false;
                state.failure_reported = false;
            }
            state.answer_published = false;
            state.generation
        };

        if starts_ice_generation && self.require_relay {
            let gate = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(gate.relay_deadline).await;
                gate.fail_if_relay_missing(generation, "deadline elapsed")
                    .await;
            });
        }
    }

    async fn publish_answer(&self, sdp: String) {
        // The broadcast receiver owned by WebRtcPeer is created before the
        // peer task, so this answer remains durable even when initial session
        // plumbing has not started its event pump yet.
        let _ = self.evt_tx.send(PeerEvent::Answer(sdp));
        let pending = {
            let mut state = self.state.lock().await;
            state.answer_published = true;
            std::mem::take(&mut state.pending_candidates)
        };
        for candidate in pending {
            let _ = self.evt_tx.send(PeerEvent::LocalIce(candidate));
        }
    }

    async fn add_candidate(&self, candidate: String, is_relay: bool) {
        let publish_now = {
            let mut state = self.state.lock().await;
            state.relay_seen |= is_relay;
            if state.answer_published {
                true
            } else {
                state.pending_candidates.push(candidate.clone());
                false
            }
        };
        if publish_now {
            let _ = self.evt_tx.send(PeerEvent::LocalIce(candidate));
        }
    }

    async fn gathering_complete(&self) {
        let generation = {
            let mut state = self.state.lock().await;
            state.gathering_complete = true;
            state.generation
        };
        self.fail_if_relay_missing(generation, "gathering completed")
            .await;
    }

    async fn fail_if_relay_missing(&self, generation: u64, reason: &'static str) {
        if !self.require_relay {
            return;
        }
        let should_report = {
            let mut state = self.state.lock().await;
            if state.generation != generation || state.relay_seen || state.failure_reported {
                false
            } else if reason == "gathering completed" || !state.gathering_complete {
                state.failure_reported = true;
                true
            } else {
                false
            }
        };
        if should_report {
            let _ = self.evt_tx.send(PeerEvent::Error(format!(
                "TURN was configured but ICE relay validation failed: {reason}"
            )));
        }
    }
}

#[derive(Clone)]
pub struct WebRtcPeer {
    cmd_tx: mpsc::Sender<PeerCommand>,
    evt_rx: Arc<tokio::sync::Mutex<broadcast::Receiver<PeerEvent>>>,
    video_transport: Arc<AtomicU8>,
}

impl WebRtcPeer {
    pub fn spawn(opts: PeerOptions) -> Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (evt_tx, evt_rx) = broadcast::channel(64);
        let evt_for_task = evt_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = run_peer(opts, cmd_rx, evt_for_task.clone()).await {
                warn!(error = %error, "webrtc peer run loop exited with error");
                let _ = evt_for_task.send(PeerEvent::Error(error.to_string()));
            }
        });
        Ok(Self {
            cmd_tx,
            evt_rx: Arc::new(tokio::sync::Mutex::new(evt_rx)),
            video_transport: Arc::new(AtomicU8::new(VideoTransport::Rtp.as_u8())),
        })
    }

    pub async fn accept_offer(&self, sdp: String, kind: NegotiationKind) -> Result<()> {
        let (done, completed) = oneshot::channel();
        self.send(PeerCommand::AcceptOffer { sdp, kind, done })
            .await?;
        completed
            .await
            .map_err(|_| anyhow!("peer exited before completing offer"))?
            .map_err(|error| anyhow!(error))
    }

    pub async fn add_remote_ice(&self, candidate: String) -> Result<()> {
        self.send(PeerCommand::RemoteIce(candidate)).await
    }

    pub async fn write_video(&self, frame: VideoFrame) -> Result<()> {
        self.send(PeerCommand::WriteVideo(frame)).await
    }

    pub fn try_write_video(&self, frame: VideoFrame) -> bool {
        self.cmd_tx.try_send(PeerCommand::WriteVideo(frame)).is_ok()
    }

    pub fn try_write_video_binary(&self, payload: Vec<u8>) -> bool {
        self.cmd_tx
            .try_send(PeerCommand::WriteVideoBinary(payload))
            .is_ok()
    }

    pub async fn write_video_binary(&self, payload: Vec<u8>) -> Result<()> {
        self.send(PeerCommand::WriteVideoBinary(payload)).await
    }

    pub fn set_video_transport(&self, mode: VideoTransport) {
        self.video_transport.store(mode.as_u8(), Ordering::Release);
    }

    pub fn video_transport(&self) -> VideoTransport {
        VideoTransport::from_u8(self.video_transport.load(Ordering::Acquire))
    }

    pub async fn write_audio(&self, packet: AudioPacket) -> Result<()> {
        self.send(PeerCommand::WriteAudio(packet)).await
    }

    pub fn try_write_audio(&self, packet: AudioPacket) -> bool {
        self.cmd_tx
            .try_send(PeerCommand::WriteAudio(packet))
            .is_ok()
    }

    pub async fn send_control_text(&self, message: String) -> Result<()> {
        self.send(PeerCommand::SendControlText(message)).await
    }

    pub async fn set_camera_sink(&self, sink: Option<mpsc::Sender<CameraFrame>>) -> Result<()> {
        self.send(PeerCommand::SetCameraSink(sink)).await
    }

    pub async fn request_camera_keyframe(&self) -> Result<()> {
        self.send(PeerCommand::RequestCameraKeyframe).await
    }

    pub async fn close(&self) {
        let _ = self.send(PeerCommand::Close).await;
    }

    pub async fn next_event(&self) -> Option<PeerEvent> {
        loop {
            match self.evt_rx.lock().await.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "webrtc peer event receiver lagged");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    async fn send(&self, command: PeerCommand) -> Result<()> {
        self.cmd_tx
            .send(command)
            .await
            .map_err(|_| anyhow!("peer task has exited"))
    }
}

type DataChannelSlot = Arc<RwLock<Option<Arc<RTCDataChannel>>>>;
type CameraSinkSlot = Arc<RwLock<Option<mpsc::Sender<CameraFrame>>>>;
type CameraCodecContract = Arc<RwLock<H264CameraContract>>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct H264CameraContract {
    advertised_payload_types: HashSet<u8>,
}

impl H264CameraContract {
    fn authorizes_inbound_video(&self) -> bool {
        !self.advertised_payload_types.is_empty()
    }
}

async fn run_peer(
    opts: PeerOptions,
    mut cmd_rx: mpsc::Receiver<PeerCommand>,
    evt_tx: broadcast::Sender<PeerEvent>,
) -> Result<()> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;

    // OKE is IPv4-only. Limiting gathering to UDP4 also avoids an upstream
    // resolver failure where an unavailable IPv6 route aborts IPv4 TURN.
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_network_types(vec![NetworkType::Udp4]);
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_setting_engine(setting_engine)
        .build();

    let force_relay = has_turn_server(&opts.ice_servers);
    let config = RTCConfiguration {
        ice_servers: opts
            .ice_servers
            .iter()
            .map(|server| RTCIceServer {
                urls: server.urls.clone(),
                username: server.username.clone().unwrap_or_default(),
                credential: server.credential.clone().unwrap_or_default(),
            })
            .collect(),
        ice_transport_policy: if force_relay {
            RTCIceTransportPolicy::Relay
        } else {
            RTCIceTransportPolicy::All
        },
        ..Default::default()
    };
    info!(
        ice_servers = opts.ice_servers.len(),
        policy = if force_relay { "relay" } else { "all" },
        local_bind = %opts.local_bind,
        extra_local_ips = opts.extra_local_ips.len(),
        "creating WebRTC peer"
    );

    let pc = Arc::new(api.new_peer_connection(config).await?);
    let relay_deadline = relay_validation_deadline(opts.ice_gather_wait);
    let candidate_gate = LocalCandidateGate::new(evt_tx.clone(), force_relay, relay_deadline);
    install_state_callbacks(&pc, candidate_gate.clone(), evt_tx.clone());

    let control_dc: DataChannelSlot = Arc::new(RwLock::new(None));
    let video_dc: DataChannelSlot = Arc::new(RwLock::new(None));
    install_data_channel_callback(&pc, control_dc.clone(), video_dc.clone(), evt_tx.clone());

    let camera_sink: CameraSinkSlot = Arc::new(RwLock::new(None));
    let camera_ssrc = Arc::new(AtomicU32::new(0));
    let camera_codec_contract: CameraCodecContract =
        Arc::new(RwLock::new(H264CameraContract::default()));
    install_camera_callback(
        &pc,
        camera_sink.clone(),
        camera_ssrc.clone(),
        camera_codec_contract.clone(),
    );

    let video_track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_H264.to_owned(),
            clock_rate: 90_000,
            ..Default::default()
        },
        "screen".to_owned(),
        "beeos-screen".to_owned(),
    ));
    let video_sender = pc
        .add_track(video_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
        .await
        .context("add H264 screen track")?;
    spawn_outbound_rtcp_reader(video_sender, evt_tx.clone());

    let audio_track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48_000,
            channels: 2,
            ..Default::default()
        },
        "audio".to_owned(),
        "beeos-screen".to_owned(),
    ));
    let audio_sender = pc
        .add_track(audio_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
        .await
        .context("add Opus screen track")?;
    spawn_outbound_rtcp_reader(audio_sender, evt_tx.clone());

    let mut last_video_pts = None;
    let mut last_audio_pts = None;

    while let Some(command) = cmd_rx.recv().await {
        match command {
            PeerCommand::AcceptOffer { sdp, kind, done } => {
                let result =
                    accept_offer(&pc, &candidate_gate, &camera_codec_contract, sdp, kind).await;
                let acknowledgement = result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|error| format!("{error:#}"));
                let _ = done.send(acknowledgement);
                result?;
            }
            PeerCommand::RemoteIce(candidate) => {
                if candidate.trim().is_empty() {
                    continue;
                }
                info!(candidate = %candidate, "received remote ICE candidate");
                if let Err(error) = pc
                    .add_ice_candidate(RTCIceCandidateInit {
                        candidate,
                        sdp_mid: Some("0".to_owned()),
                        sdp_mline_index: Some(0),
                        ..Default::default()
                    })
                    .await
                {
                    // An answer already contains gathered candidates; a late
                    // duplicate trickle candidate is non-fatal.
                    warn!(error = %error, "add remote ICE candidate");
                }
            }
            PeerCommand::WriteVideo(frame) => {
                let duration =
                    sample_duration(&mut last_video_pts, frame.pts_us, Duration::from_millis(33));
                if let Err(error) = video_track
                    .write_sample(&Sample {
                        data: Bytes::from(frame.data),
                        duration,
                        ..Default::default()
                    })
                    .await
                {
                    warn!(error = %error, "video write");
                }
            }
            PeerCommand::WriteVideoBinary(payload) => {
                if let Some(channel) = video_dc.read().await.clone() {
                    if let Err(error) = channel.send(&Bytes::from(payload)).await {
                        warn!(error = %error, "video datachannel write");
                    }
                } else {
                    debug!("video datachannel not open; dropping payload");
                }
            }
            PeerCommand::WriteAudio(packet) => {
                // scrcpy's OpusHead config is represented by SDP, not RTP.
                if packet.is_config {
                    continue;
                }
                let duration = sample_duration(
                    &mut last_audio_pts,
                    packet.pts_us,
                    Duration::from_millis(20),
                );
                if let Err(error) = audio_track
                    .write_sample(&Sample {
                        data: Bytes::from(packet.data),
                        duration,
                        ..Default::default()
                    })
                    .await
                {
                    warn!(error = %error, "audio write");
                }
            }
            PeerCommand::SendControlText(message) => {
                if let Some(channel) = control_dc.read().await.clone() {
                    if let Err(error) = channel.send_text(message).await {
                        warn!(error = %error, "control datachannel write");
                    }
                } else {
                    debug!("control datachannel not open; dropping message");
                }
            }
            PeerCommand::SetCameraSink(sink) => {
                let should_request = sink.is_some();
                *camera_sink.write().await = sink;
                if should_request {
                    send_camera_pli(&pc, camera_ssrc.load(Ordering::Acquire)).await;
                }
            }
            PeerCommand::RequestCameraKeyframe => {
                send_camera_pli(&pc, camera_ssrc.load(Ordering::Acquire)).await;
            }
            // Outbound keyframe recovery is driven by RTCP PLI/FIR and the
            // bridge's scrcpy ResetVideo command. No local WebRTC action is
            // required here.
            PeerCommand::RequestKeyframe => {}
            PeerCommand::Close => {
                let _ = pc.close().await;
                let _ = evt_tx.send(PeerEvent::Disconnected);
                return Ok(());
            }
        }
    }

    let _ = pc.close().await;
    Ok(())
}

fn install_state_callbacks(
    pc: &Arc<RTCPeerConnection>,
    candidate_gate: LocalCandidateGate,
    evt_tx: broadcast::Sender<PeerEvent>,
) {
    let gathering_gate = candidate_gate.clone();
    pc.on_ice_gathering_state_change(Box::new(move |state| {
        let gate = gathering_gate.clone();
        Box::pin(async move {
            info!(state = %state, "ICE gathering state");
            if state == RTCIceGathererState::Complete {
                gate.gathering_complete().await;
            }
        })
    }));

    pc.on_ice_candidate(Box::new(move |candidate| {
        let gate = candidate_gate.clone();
        Box::pin(async move {
            match candidate {
                Some(candidate) => {
                    info!(candidate = %candidate, "local ICE candidate gathered");
                    let is_relay = candidate.typ
                        == webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType::Relay;
                    match candidate.to_json() {
                        Ok(init) => gate.add_candidate(init.candidate, is_relay).await,
                        Err(error) => warn!(%error, "serialize local ICE candidate"),
                    }
                }
                None => info!("local ICE gathering complete"),
            }
        })
    }));

    let ready_emitted = Arc::new(AtomicU8::new(0));
    pc.on_peer_connection_state_change(Box::new(move |state| {
        let tx = evt_tx.clone();
        let ready = ready_emitted.clone();
        Box::pin(async move {
            info!(state = %state, "PeerConnection state");
            match state {
                RTCPeerConnectionState::Connected => {
                    let _ = tx.send(PeerEvent::Connected);
                    if ready.swap(1, Ordering::AcqRel) == 0 {
                        let _ = tx.send(PeerEvent::StreamReady);
                    }
                }
                RTCPeerConnectionState::Disconnected
                | RTCPeerConnectionState::Failed
                | RTCPeerConnectionState::Closed => {
                    ready.store(0, Ordering::Release);
                    let _ = tx.send(PeerEvent::Disconnected);
                }
                _ => {}
            }
        })
    }));
}

fn install_data_channel_callback(
    pc: &Arc<RTCPeerConnection>,
    control_slot: DataChannelSlot,
    video_slot: DataChannelSlot,
    evt_tx: broadcast::Sender<PeerEvent>,
) {
    pc.on_data_channel(Box::new(move |channel| {
        let control_slot = control_slot.clone();
        let video_slot = video_slot.clone();
        let evt_tx = evt_tx.clone();
        Box::pin(async move {
            let label = channel.label().to_owned();
            info!(%label, id = ?channel.id(), "remote datachannel created");

            if label == "video" {
                *video_slot.write().await = Some(channel.clone());
                let slot = video_slot.clone();
                channel.on_close(Box::new(move || {
                    let slot = slot.clone();
                    Box::pin(async move { *slot.write().await = None })
                }));
                return;
            }

            // `control` is the canonical label. For older viewers, the first
            // non-video channel remains the compatibility fallback.
            let use_as_control = label == "control" || control_slot.read().await.is_none();
            if !use_as_control {
                return;
            }
            *control_slot.write().await = Some(channel.clone());

            let open_tx = evt_tx.clone();
            channel.on_open(Box::new(move || {
                let tx = open_tx.clone();
                Box::pin(async move {
                    info!("control datachannel open");
                    let _ = tx.send(PeerEvent::ControlChannelOpen);
                })
            }));

            let message_tx = evt_tx.clone();
            channel.on_message(Box::new(move |message: DataChannelMessage| {
                let tx = message_tx.clone();
                Box::pin(async move {
                    if let Ok(text) = std::str::from_utf8(&message.data) {
                        let _ = tx.send(PeerEvent::ControlMessage(text.to_owned()));
                    }
                })
            }));

            let slot = control_slot.clone();
            channel.on_close(Box::new(move || {
                let slot = slot.clone();
                Box::pin(async move { *slot.write().await = None })
            }));
        })
    }));
}

fn install_camera_callback(
    pc: &Arc<RTCPeerConnection>,
    camera_sink: CameraSinkSlot,
    camera_ssrc: Arc<AtomicU32>,
    camera_codec_contract: CameraCodecContract,
) {
    let pc_weak = Arc::downgrade(pc);
    pc.on_track(Box::new(move |track, _receiver, _transceiver| {
        let sink = camera_sink.clone();
        let ssrc_slot = camera_ssrc.clone();
        let codec_contract = camera_codec_contract.clone();
        let pc_weak = pc_weak.clone();
        Box::pin(async move {
            if track.kind() != RTPCodecType::Video {
                return;
            }

            // webrtc-rs keeps one negotiated payload-type table for every
            // bundled video m-line. During media renegotiation a browser may
            // reuse a PT that the initial screen m-line mapped to VP8, even
            // though the new sendonly camera m-line maps that PT to H.264.
            // TrackRemote::codec() then reports the stale global mapping. The
            // remote SDP media section is the authoritative per-m-line
            // contract. The packet PT cannot be compared with that section's
            // PT set: webrtc-rs exposes the bundled/global PT on TrackRemote,
            // which may legitimately differ from the camera m-line's PT.
            let payload_type = track.payload_type();
            let reported_codec = track.codec().capability.mime_type;
            let contract = codec_contract.read().await.clone();
            if !contract.authorizes_inbound_video() {
                warn!(
                    payload_type,
                    %reported_codec,
                    "ignoring inbound camera track without H264 SDP contract"
                );
                return;
            }

            let ssrc = track.ssrc();
            ssrc_slot.store(ssrc, Ordering::Release);
            info!(
                ssrc,
                payload_type,
                %reported_codec,
                advertised_payload_types = ?contract.advertised_payload_types,
                "inbound H264 camera track ready"
            );
            if sink.read().await.is_some() {
                if let Some(pc) = pc_weak.upgrade() {
                    send_camera_pli(&pc, ssrc).await;
                }
            }

            tokio::spawn(async move {
                let mut depacketizer = H264Packet::default();
                let mut access_unit = Vec::new();
                loop {
                    let (packet, _) = match track.read_rtp().await {
                        Ok(packet) => packet,
                        Err(error) => {
                            debug!(error = %error, "camera RTP reader ended");
                            break;
                        }
                    };
                    match depacketizer.depacketize(&packet.payload) {
                        Ok(nal) if !nal.is_empty() => access_unit.extend_from_slice(&nal),
                        Ok(_) => {}
                        Err(error) => {
                            warn!(error = %error, "camera H264 depacketize");
                            access_unit.clear();
                            continue;
                        }
                    }
                    if packet.header.marker && !access_unit.is_empty() {
                        let frame = CameraFrame {
                            data: std::mem::take(&mut access_unit),
                            pts_us: (u64::from(packet.header.timestamp) * 1_000_000 / 90_000)
                                as i64,
                        };
                        if let Some(tx) = sink.read().await.clone() {
                            if tx.try_send(frame).is_err() {
                                debug!("camera sink full or closed; dropping access unit");
                            }
                        }
                    }
                }
                ssrc_slot.store(0, Ordering::Release);
            });
        })
    }));
}

fn spawn_outbound_rtcp_reader(
    sender: Arc<webrtc::rtp_transceiver::rtp_sender::RTCRtpSender>,
    evt_tx: broadcast::Sender<PeerEvent>,
) {
    tokio::spawn(async move {
        loop {
            let (packets, _) = match sender.read_rtcp().await {
                Ok(result) => result,
                Err(error) => {
                    debug!(error = %error, "outbound RTCP reader ended");
                    return;
                }
            };
            if packets.iter().any(|packet| {
                packet
                    .as_any()
                    .downcast_ref::<PictureLossIndication>()
                    .is_some()
                    || packet.as_any().downcast_ref::<FullIntraRequest>().is_some()
            }) {
                let _ = evt_tx.send(PeerEvent::KeyframeRequested);
            }
        }
    });
}

async fn accept_offer(
    pc: &Arc<RTCPeerConnection>,
    candidate_gate: &LocalCandidateGate,
    camera_codec_contract: &CameraCodecContract,
    sdp: String,
    kind: NegotiationKind,
) -> Result<()> {
    let negotiated_camera_contract =
        h264_camera_contract(&sdp).context("validate inbound camera codec contract")?;
    *camera_codec_contract.write().await = negotiated_camera_contract;

    let offer = RTCSessionDescription::offer(sdp).context("parse offer SDP")?;
    pc.set_remote_description(offer)
        .await
        .context("set remote description")?;
    let answer = pc.create_answer(None).await.context("create answer")?;
    candidate_gate
        .begin_answer(kind.starts_ice_generation())
        .await;
    pc.set_local_description(answer)
        .await
        .context("set local description")?;

    let local = pc
        .local_description()
        .await
        .context("missing local description after answer")?;
    info!(?kind, "answer SDP ready; ICE candidates will trickle");
    candidate_gate.publish_answer(local.sdp).await;
    Ok(())
}

/// Validate every remote sendonly video m-line. A camera uplink has no
/// degraded fallback: the virtual-camera sink consumes H.264 access units
/// directly, so any other primary codec makes the whole offer invalid.
fn h264_camera_contract(sdp: &str) -> Result<H264CameraContract> {
    const AUXILIARY_CODECS: &[&str] = &["rtx", "red", "ulpfec", "flexfec-03"];

    let normalized = sdp.replace("\r\n", "\n");
    let mut h264_payload_types = HashSet::new();

    for raw_section in normalized.split("\nm=").skip(1) {
        let section = format!("m={raw_section}");
        let lines: Vec<&str> = section.lines().map(str::trim).collect();
        let Some(media_line) = lines.first() else {
            continue;
        };
        if !media_line.starts_with("m=video ") || !lines.contains(&"a=sendonly") {
            continue;
        }

        let mut primary_codec_count = 0;
        for payload_type_text in media_line.split_whitespace().skip(3) {
            let prefix = format!("a=rtpmap:{payload_type_text} ");
            let rtpmap = lines
                .iter()
                .find_map(|line| line.strip_prefix(&prefix))
                .ok_or_else(|| anyhow!("camera payload type {payload_type_text} has no rtpmap"))?;
            let codec = rtpmap
                .split(['/', ' '])
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if AUXILIARY_CODECS.contains(&codec.as_str()) {
                continue;
            }

            primary_codec_count += 1;
            if codec != "h264" {
                return Err(anyhow!(
                    "camera m-line offered unsupported primary codec {codec}"
                ));
            }
            h264_payload_types.insert(
                payload_type_text
                    .parse::<u8>()
                    .with_context(|| format!("invalid camera payload type {payload_type_text}"))?,
            );
        }

        if primary_codec_count == 0 {
            return Err(anyhow!("camera m-line has no primary H264 payload type"));
        }
    }

    Ok(H264CameraContract {
        advertised_payload_types: h264_payload_types,
    })
}

async fn send_camera_pli(pc: &Arc<RTCPeerConnection>, media_ssrc: u32) {
    if media_ssrc == 0 {
        return;
    }
    let packets: Vec<Box<dyn rtcp::packet::Packet + Send + Sync>> =
        vec![Box::new(PictureLossIndication {
            sender_ssrc: 0,
            media_ssrc,
        })];
    if let Err(error) = pc.write_rtcp(&packets).await {
        warn!(error = %error, media_ssrc, "send camera PLI");
    }
}

fn has_turn_server(servers: &[IceServer]) -> bool {
    servers.iter().any(|server| {
        server.urls.iter().any(|url| {
            let lower = url.trim().to_ascii_lowercase();
            lower.starts_with("turn:") || lower.starts_with("turns:")
        })
    })
}

fn relay_validation_deadline(legacy_hint: Duration) -> Duration {
    Duration::from_secs(10).max(legacy_hint)
}

fn sample_duration(previous_pts: &mut Option<u64>, pts_us: u64, fallback: Duration) -> Duration {
    let duration = previous_pts
        .and_then(|previous| pts_us.checked_sub(previous))
        .filter(|delta| (1_000..=1_000_000).contains(delta))
        .map(Duration::from_micros)
        .unwrap_or(fallback);
    *previous_pts = Some(pts_us);
    duration
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn next_answer(peer: &WebRtcPeer) -> Result<String> {
        loop {
            let event = tokio::time::timeout(Duration::from_secs(1), peer.next_event())
                .await
                .context("timed out waiting for peer answer")?
                .context("peer event stream closed")?;
            match event {
                PeerEvent::Answer(sdp) => return Ok(sdp),
                PeerEvent::Error(error) => return Err(anyhow!(error)),
                _ => {}
            }
        }
    }

    fn ice_ufrag(sdp: &str) -> Option<&str> {
        sdp.lines()
            .find_map(|line| line.trim().strip_prefix("a=ice-ufrag:"))
    }

    #[test]
    fn camera_payload_contract_uses_the_sendonly_media_mapping() -> Result<()> {
        let sdp = "v=0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
a=recvonly\r\n\
a=rtpmap:96 VP8/90000\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96 121\r\n\
a=sendonly\r\n\
a=rtpmap:96 H264/90000\r\n\
a=rtpmap:121 rtx/90000\r\n\
a=fmtp:121 apt=96\r\n";

        assert_eq!(
            h264_camera_contract(sdp)?,
            H264CameraContract {
                advertised_payload_types: HashSet::from([96]),
            }
        );
        Ok(())
    }

    #[test]
    fn camera_contract_authorizes_track_across_bundle_payload_collision() -> Result<()> {
        let sdp = "v=0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
a=recvonly\r\n\
a=rtpmap:96 VP8/90000\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 107\r\n\
a=sendonly\r\n\
a=rtpmap:107 H264/90000\r\n";

        let contract = h264_camera_contract(sdp)?;
        assert_eq!(contract.advertised_payload_types, HashSet::from([107]));
        assert!(!contract.advertised_payload_types.contains(&96));
        assert!(contract.authorizes_inbound_video());
        Ok(())
    }

    #[test]
    fn camera_payload_contract_rejects_non_h264_primary_codecs() {
        let sdp = "v=0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
a=sendonly\r\n\
a=rtpmap:96 VP8/90000\r\n";

        let error = h264_camera_contract(sdp).expect_err("VP8 camera must fail closed");
        assert!(error.to_string().contains("unsupported primary codec vp8"));
    }

    #[test]
    fn camera_payload_contract_rejects_unmapped_payloads() {
        let sdp = "v=0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 102 127\r\n\
a=sendonly\r\n\
a=rtpmap:102 H264/90000\r\n";

        let error = h264_camera_contract(sdp).expect_err("unmapped PT must fail closed");
        assert!(error.to_string().contains("payload type 127 has no rtpmap"));
    }

    #[test]
    fn camera_payload_contract_is_empty_without_an_uplink() -> Result<()> {
        let sdp = "v=0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 102\r\n\
a=recvonly\r\n\
a=rtpmap:102 H264/90000\r\n";

        assert!(!h264_camera_contract(sdp)?.authorizes_inbound_video());
        Ok(())
    }

    #[tokio::test]
    async fn adding_camera_media_renegotiates_without_waiting_for_new_ice() -> Result<()> {
        use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
        use webrtc::rtp_transceiver::RTCRtpTransceiverInit;

        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let api = APIBuilder::new().with_media_engine(media_engine).build();
        let client = api.new_peer_connection(RTCConfiguration::default()).await?;
        let recvonly = || RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            send_encodings: vec![],
        };
        client
            .add_transceiver_from_kind(RTPCodecType::Video, Some(recvonly()))
            .await?;
        client
            .add_transceiver_from_kind(RTPCodecType::Audio, Some(recvonly()))
            .await?;
        let _control = client.create_data_channel("control", None).await?;

        let peer = WebRtcPeer::spawn(PeerOptions::default())?;
        let initial_offer = client.create_offer(None).await?;
        client.set_local_description(initial_offer).await?;
        let initial_sdp = client
            .local_description()
            .await
            .context("client initial local description")?
            .sdp;
        tokio::time::timeout(
            Duration::from_secs(1),
            peer.accept_offer(initial_sdp.clone(), NegotiationKind::Initial),
        )
        .await
        .context("initial negotiation blocked")??;
        client
            .set_remote_description(RTCSessionDescription::answer(next_answer(&peer).await?)?)
            .await?;

        let camera_track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: MIME_TYPE_H264.to_owned(),
                clock_rate: 90_000,
                ..Default::default()
            },
            "camera".to_owned(),
            "browser-camera".to_owned(),
        ));
        let _camera_sender = client
            .add_track(camera_track as Arc<dyn TrackLocal + Send + Sync>)
            .await?;
        let camera_offer = client.create_offer(None).await?;
        client.set_local_description(camera_offer).await?;
        let camera_sdp = client
            .local_description()
            .await
            .context("client camera local description")?
            .sdp;
        assert_eq!(ice_ufrag(&initial_sdp), ice_ufrag(&camera_sdp));

        tokio::time::timeout(
            Duration::from_secs(1),
            peer.accept_offer(camera_sdp, NegotiationKind::MediaRenegotiation),
        )
        .await
        .context("camera media renegotiation blocked on ICE gathering")??;
        client
            .set_remote_description(RTCSessionDescription::answer(next_answer(&peer).await?)?)
            .await?;

        peer.close().await;
        client.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn trickle_candidates_are_published_after_the_answer() {
        let (evt_tx, mut evt_rx) = broadcast::channel(8);
        let gate = LocalCandidateGate::new(evt_tx, true, Duration::from_secs(60));

        gate.begin_answer(true).await;
        gate.add_candidate("candidate:relay".to_owned(), true).await;
        assert!(matches!(
            evt_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        gate.publish_answer("answer".to_owned()).await;
        assert!(matches!(evt_rx.recv().await, Ok(PeerEvent::Answer(sdp)) if sdp == "answer"));
        assert!(
            matches!(evt_rx.recv().await, Ok(PeerEvent::LocalIce(candidate)) if candidate == "candidate:relay")
        );
    }

    #[tokio::test]
    async fn missing_turn_relay_is_reported_without_blocking_the_answer() {
        let (evt_tx, mut evt_rx) = broadcast::channel(8);
        let gate = LocalCandidateGate::new(evt_tx, true, Duration::from_secs(60));

        gate.begin_answer(true).await;
        gate.publish_answer("answer".to_owned()).await;
        gate.gathering_complete().await;

        assert!(matches!(evt_rx.recv().await, Ok(PeerEvent::Answer(_))));
        assert!(matches!(
            evt_rx.recv().await,
            Ok(PeerEvent::Error(message)) if message.contains("gathering completed")
        ));
    }

    #[test]
    fn only_initial_offers_and_ice_restarts_start_a_generation() {
        assert!(NegotiationKind::Initial.starts_ice_generation());
        assert!(NegotiationKind::IceRestart.starts_ice_generation());
        assert!(!NegotiationKind::MediaRenegotiation.starts_ice_generation());
    }

    #[test]
    fn relay_validation_never_uses_the_legacy_short_wait() {
        assert_eq!(
            relay_validation_deadline(Duration::from_millis(250)),
            Duration::from_secs(10)
        );
        assert_eq!(
            relay_validation_deadline(Duration::from_secs(15)),
            Duration::from_secs(15)
        );
    }

    #[test]
    fn detects_turn_urls_and_ignores_stun_only_configs() {
        let stun = IceServer {
            urls: vec!["stun:stun.example.com:3478".to_owned()],
            username: None,
            credential: None,
        };
        let turn = IceServer {
            urls: vec!["TURNS:turn.example.com:5349?transport=tcp".to_owned()],
            username: Some("u".to_owned()),
            credential: Some("p".to_owned()),
        };
        assert!(!has_turn_server(std::slice::from_ref(&stun)));
        assert!(has_turn_server(&[stun, turn]));
    }

    #[test]
    fn sample_duration_uses_pts_delta_with_sane_fallbacks() {
        let mut previous = None;
        let fallback = Duration::from_millis(33);
        assert_eq!(
            sample_duration(&mut previous, 1_000_000, fallback),
            fallback
        );
        assert_eq!(
            sample_duration(&mut previous, 1_033_333, fallback),
            Duration::from_micros(33_333)
        );
        assert_eq!(
            sample_duration(&mut previous, 1_033_333, fallback),
            fallback
        );
        assert_eq!(
            sample_duration(&mut previous, 9_000_000, fallback),
            fallback
        );
    }
}
