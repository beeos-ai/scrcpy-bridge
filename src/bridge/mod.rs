//! Top-level orchestrator.
//!
//! Lifecycle:
//!   1. Connect MQTT signaling.
//!   2. Wait for an SDP offer from the browser (first offer = first viewer).
//!   3. Start scrcpy server on the device, open video/audio/control sockets.
//!   4. Spawn a WebRTC peer (`str0m`), pass H.264 AUs from scrcpy into it.
//!   5. Forward DataChannel control messages back to the scrcpy control
//!      socket (no IPC, no Python involved).
//!   6. When the viewer disconnects, keep scrcpy running for a grace period
//!      so a page refresh can reconnect without losing the encoder.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::adb::Adb;
use crate::bootstrap::{
    self, spawn_refresh_loop, BootstrapClient, BootstrapConfig, BootstrapEvent, BootstrapResponse,
    IceServerPayload,
};
use crate::config::Cli;
use crate::datachannel::{self, ControlIn};
use crate::mqtt::{
    MqttCredentials, MqttSignaling, MqttSignalingConfig, SignalRequest, SignalResponse,
};
use crate::observability::{
    HealthFlags, AUDIO_PACKETS_DROPPED, AUDIO_PACKETS_TOTAL, CONTROL_MESSAGES_TOTAL,
    SCRCPY_RECONNECTS_TOTAL, SCRCPY_RUNNING, VIDEO_FRAMES_TOTAL, VIEWER_BITRATE_BPS,
    VIEWER_CONNECTED, VIEWER_FPS, VIEWER_PACKETS_LOST, VIEWER_RTT_MS,
};
use crate::scrcpy::protocol::{KeyAction, TouchAction};
use crate::scrcpy::{ScrcpyServer, ScrcpyServerConfig};
use crate::webrtc::{IceServer, PeerEvent, PeerOptions, WebRtcPeer};

/// MQTT username expected by the EMQX JWT auth plugin. All device-scoped
/// connections log in as `device`; the JWT payload carries the true identity.
const MQTT_USERNAME: &str = "device";

pub struct Bridge {
    cli: Cli,
    health: HealthFlags,
    /// Current set of ICE servers to advertise to the browser. Populated
    /// from the Agent Gateway bootstrap response (primary) and optionally
    /// augmented by CLI `--ice-urls` entries (dev-only override, see
    /// [`merge_ice_servers`]). Shared with the bootstrap refresh loop so
    /// that TURN credential rotation takes effect on the very next
    /// `on_offer` without a restart.
    ice_servers: Arc<RwLock<Vec<IceServer>>>,
}

impl Bridge {
    pub fn new(cli: Cli, health: HealthFlags) -> Self {
        Self {
            cli,
            health,
            ice_servers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn run(self) -> Result<()> {
        // 1. Resolve initial broker credentials via Agent Gateway bootstrap.
        //    Runtime issues a short-lived (~10 min) RS256 JWT authenticated
        //    by Ed25519 identity keys. This is the only supported credential
        //    source — no static `--mqtt-token` fallback exists. The response
        //    also carries ICE servers so the caller doesn't need to pre-stuff
        //    TURN creds into CLI flags.
        let (initial_creds, initial_bootstrap) = self.resolve_initial_credentials().await?;

        // Seed the shared ICE server list. Bootstrap is the authoritative
        // source — Runtime owns the TURN pool; CLI `--ice-urls` is
        // dev-only and only fills in when bootstrap returned nothing (or
        // when a local operator explicitly supplied an extra entry that
        // bootstrap didn't include).
        {
            let merged = merge_ice_servers(&initial_bootstrap.ice_servers, &self.cli);
            *self.ice_servers.write().await = merged;
        }

        // 2. MQTT signaling. The handle is cloneable via Arc and supports
        //    hot credential rotation through `reconnect(...)` below.
        //
        // IMPORTANT: we use `initial_bootstrap.device_topic` — NOT
        // `cli.device_id` — for all topic construction. Runtime builds the
        // topic as `devices/device-<instanceUUID>` (see
        // `services/runtime/.../device/provider.go`) and EMQX's JWT ACL is
        // scoped to exactly that prefix. Feeding the bare instance UUID
        // (which is what `cli.device_id` typically holds) would cause every
        // subscribe/publish to be rejected by EMQX with `not authorized`.
        let topic_prefix = initial_bootstrap.device_topic.trim();
        if topic_prefix.is_empty() {
            return Err(anyhow::anyhow!(
                "bootstrap response missing deviceTopic — Runtime misconfigured or instance lacks stream params"
            ));
        }
        let topic_prefix = topic_prefix.to_string();
        let (mqtt, mut sig_rx) = MqttSignaling::connect(MqttSignalingConfig {
            broker_url: initial_creds.broker_url.clone(),
            username: initial_creds.username.clone(),
            token: initial_creds.token.clone(),
            topic_prefix: topic_prefix.clone(),
            client_id: format!("scrcpy-bridge-{}", self.cli.device_id),
        })
        .await
        .context("connect mqtt")?;
        self.health.mqtt_connected.store(true, Ordering::Relaxed);
        let mqtt = Arc::new(mqtt);
        info!(
            device_id = %self.cli.device_id,
            topic_prefix = %topic_prefix,
            "scrcpy-bridge online, waiting for offer"
        );

        // 3. Spawn the refresh loop and pipe its events into the MQTT
        //    supervisor so we never deliver a signaling response with an
        //    expired JWT. Failure here is fatal — without the refresher
        //    the session would be guaranteed to die in ~10 minutes.
        self.spawn_bootstrap_refresh(initial_bootstrap, mqtt.clone())
            .await
            .context("start bootstrap refresher")?;

        // 4. Peer state (one active peer + one active scrcpy session at a time).
        //    The scrcpy encoder config lives in its own Arc so the DataChannel
        //    `configure` handler can mutate it between sessions (G8 hot
        //    reconfigure). Every `on_offer` snapshots this Arc when spawning
        //    a new ScrcpyServer.
        let peer_slot: Arc<Mutex<Option<WebRtcPeer>>> = Arc::new(Mutex::new(None));
        let scrcpy_slot: Arc<Mutex<Option<ScrcpyServer>>> = Arc::new(Mutex::new(None));
        let scrcpy_cfg: Arc<RwLock<ScrcpyServerConfig>> =
            Arc::new(RwLock::new(self.initial_scrcpy_config()));

        while let Some(req) = sig_rx.recv().await {
            match req {
                SignalRequest::Offer { sdp } => {
                    if let Err(e) = self
                        .on_offer(sdp, &mqtt, &peer_slot, &scrcpy_slot, &scrcpy_cfg)
                        .await
                    {
                        error!(error = %e, "handle offer failed");
                    }
                }
                SignalRequest::Ice { candidate } => {
                    let peer = peer_slot.lock().await;
                    if let Some(peer) = peer.as_ref() {
                        if let Some(cand_str) = candidate_as_string(&candidate) {
                            let _ = peer.add_remote_ice(cand_str).await;
                        }
                    } else {
                        warn!("ICE candidate received before peer was created");
                    }
                }
                SignalRequest::Close { reason } => {
                    info!(%reason, "browser requested close");
                    if let Some(peer) = peer_slot.lock().await.take() {
                        peer.close().await;
                    }
                    if let Some(mut s) = scrcpy_slot.lock().await.take() {
                        s.stop().await;
                    }
                    self.health.scrcpy_running.store(false, Ordering::Relaxed);
                    SCRCPY_RUNNING.set(0);
                }
            }
        }
        Ok(())
    }

    /// Build the initial `ScrcpyServerConfig` from CLI flags. Once the bridge
    /// is running, the DataChannel `configure` handler mutates a shared
    /// `Arc<RwLock<ScrcpyServerConfig>>` so subsequent scrcpy restarts pick
    /// up the new encoder knobs without requiring a full bridge reboot.
    fn initial_scrcpy_config(&self) -> ScrcpyServerConfig {
        ScrcpyServerConfig {
            scrcpy_version: crate::SCRCPY_VERSION.to_string(),
            max_fps: self.cli.max_fps,
            max_width: self.cli.max_width,
            bitrate: self.cli.bitrate,
            i_frame_interval: self.cli.i_frame_interval,
            audio: !self.cli.disable_audio,
            control: true,
            override_jar: self.cli.scrcpy_server_jar.clone(),
            remote_jar_path: self.cli.remote_jar_path.clone(),
        }
    }

    async fn on_offer(
        &self,
        offer_sdp: String,
        mqtt: &Arc<MqttSignaling>,
        peer_slot: &Arc<Mutex<Option<WebRtcPeer>>>,
        scrcpy_slot: &Arc<Mutex<Option<ScrcpyServer>>>,
        scrcpy_cfg: &Arc<RwLock<ScrcpyServerConfig>>,
    ) -> Result<()> {
        info!("received WebRTC offer");
        // Replace any existing peer (page refresh or another viewer). Send
        // `viewer_kicked` first so the previous browser surfaces a clear
        // reason in its UI instead of an opaque connection close.
        if let Some(p) = peer_slot.lock().await.take() {
            let _ = p
                .send_control_text(datachannel::build_viewer_kicked("replaced by another viewer"))
                .await;
            // Small delay so the kicked notice actually ships before the
            // peer tears down.
            tokio::time::sleep(Duration::from_millis(100)).await;
            p.close().await;
        }

        // 3. Ensure scrcpy is running.
        let mut scrcpy_guard = scrcpy_slot.lock().await;
        if scrcpy_guard.is_none() {
            let adb = Adb {
                serial: self.cli.adb_serial.clone(),
                host: self.cli.adb_host.clone(),
                port: self.cli.adb_port,
            };
            // Snapshot the current encoder config. Any DataChannel
            // `configure` applied while we were idle is picked up here.
            let cfg_snapshot = scrcpy_cfg.read().await.clone();
            let mut server = ScrcpyServer::new(adb, cfg_snapshot);
            server.start().await.context("start scrcpy server")?;
            self.health.scrcpy_running.store(true, Ordering::Relaxed);
            SCRCPY_RUNNING.set(1);
            SCRCPY_RECONNECTS_TOTAL.inc();
            *scrcpy_guard = Some(server);
        }

        // 4. Spawn WebRTC peer.
        let extra_local_ips = self
            .cli
            .public_ips
            .iter()
            .filter(|s| !s.trim().is_empty())
            .filter_map(|s| match s.trim().parse::<std::net::IpAddr>() {
                Ok(ip) => Some(ip),
                Err(e) => {
                    warn!(ip = %s, error = %e, "ignoring unparseable PUBLIC_IPS entry");
                    None
                }
            })
            .collect::<Vec<_>>();
        // Snapshot the currently-valid ICE servers. Primary source is the
        // Agent Gateway bootstrap response (Runtime TURN pool); CLI
        // `--ice-urls` only fills in when bootstrap was empty or when a
        // local dev operator explicitly added an extra STUN/TURN entry.
        // See `merge_ice_servers` for the merge rules.
        let ice_servers = self.ice_servers.read().await.clone();
        let peer_opts = PeerOptions {
            ice_servers,
            local_bind: "0.0.0.0:0".parse().unwrap(),
            extra_local_ips,
            ice_gather_wait: Duration::from_millis(self.cli.ice_gather_wait_ms),
        };
        let peer = WebRtcPeer::spawn(peer_opts)?;
        peer.accept_offer(offer_sdp).await?;

        // 5. Pump events from the peer → MQTT + scrcpy.
        let mut evt_rx = peer.subscribe();
        let mqtt_evt = mqtt.clone();
        let scrcpy_for_ctrl = scrcpy_slot.clone();
        let scrcpy_cfg_for_ctrl = scrcpy_cfg.clone();
        let peer_for_reply = peer.clone();
        let health = self.health.clone();
        tokio::spawn(async move {
            while let Ok(evt) = evt_rx.recv().await {
                match evt {
                    PeerEvent::Answer(sdp) => {
                        if let Err(e) = mqtt_evt
                            .publish_response(&SignalResponse::Answer { sdp })
                            .await
                        {
                            warn!(error = %e, "publish answer");
                        }
                    }
                    PeerEvent::LocalIce(cand) => {
                        let payload = serde_json::json!({
                            "candidate": cand,
                            "sdpMid": "0",
                            "sdpMLineIndex": 0,
                        });
                        if let Err(e) = mqtt_evt
                            .publish_response(&SignalResponse::Ice { candidate: payload })
                            .await
                        {
                            warn!(error = %e, "publish local ice");
                        }
                    }
                    PeerEvent::Connected => {
                        VIEWER_CONNECTED.set(1);
                        info!("viewer connected");
                    }
                    PeerEvent::Disconnected => {
                        VIEWER_CONNECTED.set(0);
                        info!("viewer disconnected");
                    }
                    PeerEvent::ControlMessage(text) => {
                        if let Err(e) = forward_control(
                            &text,
                            &scrcpy_for_ctrl,
                            &scrcpy_cfg_for_ctrl,
                            &peer_for_reply,
                            &health,
                        )
                        .await
                        {
                            warn!(error = %e, "forward control");
                        }
                    }
                    PeerEvent::Error(e) => {
                        warn!(%e, "peer error event");
                    }
                }
            }
        });

        // 6. Pump video frames from scrcpy → peer (H.264 AUs).
        let scrcpy_for_video = scrcpy_slot.clone();
        let peer_for_video = peer.clone();
        let scrcpy_for_video_cleanup = scrcpy_slot.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            let exit_reason: &'static str = loop {
                let mut guard = scrcpy_for_video.lock().await;
                let Some(server) = guard.as_mut() else {
                    break "scrcpy-gone";
                };
                let Some(video) = server.video.as_mut() else {
                    drop(guard);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let frame = match video.next_frame().await {
                    Ok(Some(f)) => f,
                    Ok(None) => {
                        info!("scrcpy video socket closed");
                        break "video-eof";
                    }
                    Err(e) => {
                        warn!(error = %e, "video read error");
                        break "video-error";
                    }
                };
                drop(guard);
                let kind = if frame.is_config {
                    "config"
                } else if frame.is_keyframe {
                    "keyframe"
                } else {
                    "delta"
                };
                VIDEO_FRAMES_TOTAL.with_label_values(&[kind]).inc();
                if let Err(e) = peer_for_video.write_video(frame).await {
                    warn!(error = %e, "peer write_video");
                    break "peer-write-error";
                }
                // Keep tokio scheduler happy.
                if start.elapsed() > Duration::from_secs(86400) {
                    break "soak-reset";
                }
            };

            // scrcpy pipeline died. Tell the browser to reset its session
            // without counting against the reconnect budget, and drop the
            // now-stale ScrcpyServer so the next offer spins up a fresh
            // one (push jar + reverse tunnel + app_process launch).
            if matches!(exit_reason, "video-eof" | "video-error") {
                let _ = peer_for_video
                    .send_control_text(datachannel::build_stream_restarted())
                    .await;
            }
            if let Some(mut server) = scrcpy_for_video_cleanup.lock().await.take() {
                let _ = server.stop().await;
            }
            SCRCPY_RUNNING.set(0);
            debug!(reason = exit_reason, "video pump exited");
        });

        // 7. Pump OPUS audio packets from scrcpy → peer DataChannel (binary).
        //    The browser-side `AudioPlayer` (see
        //    `web/packages/device-viewer/src/audio-player.ts`) consumes these
        //    as `event.data: ArrayBuffer` and feeds them into WebCodecs.
        //    If the audio socket isn't available (disabled by device), we
        //    simply exit the task quietly.
        let scrcpy_for_audio = scrcpy_slot.clone();
        let peer_for_audio = peer.clone();
        tokio::spawn(async move {
            loop {
                let mut guard = scrcpy_for_audio.lock().await;
                let Some(server) = guard.as_mut() else {
                    break;
                };
                let Some(audio) = server.audio.as_mut() else {
                    // Audio disabled or not connected — exit cleanly without
                    // spinning.
                    break;
                };
                let pkt = match audio.next_packet().await {
                    Ok(Some(p)) => p,
                    Ok(None) => {
                        info!("scrcpy audio socket closed");
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "audio read error");
                        break;
                    }
                };
                drop(guard);
                let kind = if pkt.is_config { "config" } else { "data" };
                AUDIO_PACKETS_TOTAL.with_label_values(&[kind]).inc();
                if !peer_for_audio.try_send_control_binary(pkt.data) {
                    AUDIO_PACKETS_DROPPED.inc();
                }
            }
        });

        *peer_slot.lock().await = Some(peer);
        Ok(())
    }

    /// Pull credentials from Agent Gateway's `/api/v1/device/bootstrap`.
    ///
    /// This is the only supported credential path. Missing/empty key files,
    /// unreachable Agent Gateway, expired/rejected Ed25519 signatures — all
    /// surface as an `Err` here and the bridge refuses to start. There is
    /// **no** static `--mqtt-token` fallback: Runtime-issued JWTs expire in
    /// ~10 minutes and `rumqttc` reuses its initial password on reconnect,
    /// so a static token would guarantee a broken session at expiry.
    async fn resolve_initial_credentials(
        &self,
    ) -> Result<(MqttCredentials, BootstrapResponse)> {
        if self.cli.bridge_private_key_file.is_empty()
            || self.cli.bridge_public_key_file.is_empty()
        {
            return Err(anyhow::anyhow!(
                "BRIDGE_PRIVATE_KEY_FILE and BRIDGE_PUBLIC_KEY_FILE are required"
            ));
        }
        let (creds, resp) = self
            .bootstrap_fetch()
            .await
            .context("bootstrap fetch from Agent Gateway")?;
        info!(
            broker = %mask_broker(&creds.broker_url),
            expires_at = resp.expires_at,
            ice_servers = resp.ice_servers.len(),
            "bootstrap credentials fetched from Agent Gateway"
        );
        Ok((creds, resp))
    }

    /// Load identity, perform a single `/bootstrap` round-trip, translate
    /// into MQTT credentials. Shared between startup and refresh.
    async fn bootstrap_fetch(&self) -> Result<(MqttCredentials, BootstrapResponse)> {
        let priv_b64 = bootstrap::read_private_key_file(&self.cli.bridge_private_key_file).await?;
        let pub_b64 = bootstrap::read_public_key_file(&self.cli.bridge_public_key_file).await?;
        let client = BootstrapClient::new(BootstrapConfig {
            base_url: self.cli.agent_gateway_url.clone(),
            private_key_b64: priv_b64,
            public_key_b64: pub_b64,
            request_timeout: Duration::from_secs(10),
        })?;
        let resp = client.fetch().await?;
        let creds = MqttCredentials {
            broker_url: resp.mqtt_url.clone(),
            username: MQTT_USERNAME.to_string(),
            token: resp.mqtt_token.clone(),
        };
        Ok((creds, resp))
    }

    /// Spawn a background task that periodically refreshes the MQTT JWT via
    /// Agent Gateway and hot-swaps the underlying MQTT session. A loss of
    /// the refresh channel (e.g. Agent Gateway outage lasting past expiry)
    /// flips `health.mqtt_connected` to false so the k8s readinessProbe can
    /// evict the pod before EMQX does.
    async fn spawn_bootstrap_refresh(
        &self,
        initial: BootstrapResponse,
        mqtt: Arc<MqttSignaling>,
    ) -> Result<()> {
        // Build a fresh client so we don't carry connection pools across
        // Bridge clones (there's only one bridge per process but future
        // refactors may change that).
        //
        // Key files are read through `bootstrap::read_private_key_file` /
        // `read_public_key_file` rather than `std::fs` so the `.key.json`
        // dispatch (shared with device-agent + beeos CLI) is honoured on
        // every refresh, not just at startup.
        let priv_b64 = bootstrap::read_private_key_file(&self.cli.bridge_private_key_file)
            .await
            .context("read bridge private key")?;
        let pub_b64 = bootstrap::read_public_key_file(&self.cli.bridge_public_key_file)
            .await
            .context("read bridge public key")?;
        let client = BootstrapClient::new(BootstrapConfig {
            base_url: self.cli.agent_gateway_url.clone(),
            private_key_b64: priv_b64,
            public_key_b64: pub_b64,
            request_timeout: Duration::from_secs(10),
        })?;

        let lead = Duration::from_secs(self.cli.jwt_refresh_lead_secs.max(5));
        let min_interval = Duration::from_secs(self.cli.jwt_refresh_min_interval_secs.max(5));
        let mut rx = spawn_refresh_loop(client, initial, lead, min_interval);

        let health = self.health.clone();
        let ice_store = self.ice_servers.clone();
        let cli_snapshot = self.cli.clone();
        tokio::spawn(async move {
            while let Some(evt) = rx.recv().await {
                match evt {
                    BootstrapEvent::Refreshed(resp) => {
                        // Rotate ICE servers first: TURN credentials
                        // returned by Runtime also expire with the JWT,
                        // so the next `on_offer` must see the fresh
                        // username/credential pair.
                        let merged = merge_ice_servers(&resp.ice_servers, &cli_snapshot);
                        *ice_store.write().await = merged;

                        let creds = MqttCredentials {
                            broker_url: resp.mqtt_url,
                            username: MQTT_USERNAME.to_string(),
                            token: resp.mqtt_token,
                        };
                        match mqtt.reconnect(creds).await {
                            Ok(_) => {
                                health.mqtt_connected.store(true, Ordering::Relaxed);
                                info!(
                                    expires_at = resp.expires_at,
                                    ice_servers = resp.ice_servers.len(),
                                    "MQTT credentials rotated"
                                );
                            }
                            Err(e) => {
                                warn!(error = %e, "MQTT reconnect failed after credential refresh");
                                health.mqtt_connected.store(false, Ordering::Relaxed);
                            }
                        }
                    }
                    BootstrapEvent::Expired(reason) => {
                        // Runtime refused to issue a fresh token and the
                        // current one has expired. Signal health so the
                        // orchestrator can bounce us; the MQTT session will
                        // die on its own at the broker side.
                        warn!(%reason, "bootstrap expired — marking mqtt unhealthy");
                        health.mqtt_connected.store(false, Ordering::Relaxed);
                    }
                }
            }
        });

        Ok(())
    }
}

/// Merge the Agent Gateway bootstrap `iceServers` list (primary, Runtime-
/// owned, authoritative for TURN credentials) with any CLI `--ice-urls`
/// entries (dev-only override).
///
/// Merge rules:
/// 1. Bootstrap entries are copied verbatim, preserving each entry's own
///    `username` / `credential` pair. CLI TURN credentials MUST NOT leak
///    onto bootstrap servers — that would replace the short-lived
///    Runtime-signed password with a stale dev one.
/// 2. CLI entries are appended iff their URL string is not already
///    covered by bootstrap. They pick up `cli.turn_username` /
///    `cli.turn_credential` as their credentials. This mostly serves
///    local `cargo run` sessions where Runtime has no TURN config and
///    bootstrap therefore returns an empty list.
///
/// The result is a flat `Vec<IceServer>` ready to hand to `str0m` via
/// `PeerOptions.ice_servers`.
fn merge_ice_servers(bootstrap: &[IceServerPayload], cli: &Cli) -> Vec<IceServer> {
    let mut out: Vec<IceServer> = bootstrap
        .iter()
        .filter(|s| !s.urls.is_empty())
        .map(|s| IceServer {
            urls: s.urls.clone(),
            username: s.username.clone(),
            credential: s.credential.clone(),
        })
        .collect();

    let covered: std::collections::HashSet<String> = out
        .iter()
        .flat_map(|s| s.urls.iter().cloned())
        .collect();

    for url in cli.ice_urls.iter() {
        let u = url.trim();
        if u.is_empty() || covered.contains(u) {
            continue;
        }
        out.push(IceServer {
            urls: vec![u.to_string()],
            username: cli.turn_username.clone(),
            credential: cli.turn_credential.clone(),
        });
    }
    out
}

/// Redact the token/query portion from an MQTT URL for logging.
fn mask_broker(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            u.set_query(None);
            let _ = u.set_password(None);
            u.to_string()
        }
        Err(_) => "<invalid-url>".to_string(),
    }
}

// ---------------------------------------------------------------------------

/// Translate a browser DataChannel message into scrcpy control socket calls
/// or metrics updates. `peer` is used to send replies (pong, ack) back.
async fn forward_control(
    text: &str,
    scrcpy_slot: &Arc<Mutex<Option<ScrcpyServer>>>,
    scrcpy_cfg: &Arc<RwLock<ScrcpyServerConfig>>,
    peer: &WebRtcPeer,
    _health: &HealthFlags,
) -> Result<()> {
    let msg = datachannel::parse(text.as_bytes())?;
    let kind = msg_kind(&msg);
    CONTROL_MESSAGES_TOTAL.with_label_values(&[kind]).inc();

    // Non-scrcpy messages are handled before we bother taking the scrcpy lock.
    match &msg {
        ControlIn::Ping { ts } => {
            let _ = peer.send_control_text(datachannel::build_pong(*ts)).await;
            return Ok(());
        }
        ControlIn::Stats {
            fps,
            bitrate_bps,
            packets_lost,
            round_trip_time,
        } => {
            VIEWER_FPS.set(*fps);
            VIEWER_BITRATE_BPS.set(*bitrate_bps);
            VIEWER_RTT_MS.set(*round_trip_time * 1000.0);
            // Monotonic browser counter — only bump Prometheus by the delta.
            static LAST_LOST: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let prev = LAST_LOST.swap(*packets_lost, std::sync::atomic::Ordering::Relaxed);
            if *packets_lost >= prev {
                VIEWER_PACKETS_LOST.inc_by(*packets_lost - prev);
            } else {
                // Counter reset (reconnect); reseed without incrementing.
            }
            return Ok(());
        }
        ControlIn::Unknown => {
            debug!("ignoring unknown datachannel message type");
            return Ok(());
        }
        ControlIn::Configure {
            max_fps,
            max_width,
            bitrate,
            i_frame_interval,
        } => {
            // Hot reconfigure (G8):
            //   1. Merge the new encoder knobs into the shared
            //      `ScrcpyServerConfig` so the next `on_offer` spins up
            //      scrcpy with the updated values.
            //   2. Emit `stream_restarted` on the DataChannel so the
            //      browser's `reconnectForStreamRestart` kicks in.
            //   3. Tear down the currently running scrcpy server — its
            //      video pump exits, the WebRTC peer shuts down
            //      naturally, and the browser's reconnect lands on a
            //      clean slot with fresh encoder settings.
            let mut changed = false;
            {
                let mut cfg = scrcpy_cfg.write().await;
                if let Some(v) = *max_fps {
                    if cfg.max_fps != v {
                        cfg.max_fps = v;
                        changed = true;
                    }
                }
                if let Some(v) = *max_width {
                    if cfg.max_width != v {
                        cfg.max_width = v;
                        changed = true;
                    }
                }
                if let Some(v) = *bitrate {
                    if cfg.bitrate != v {
                        cfg.bitrate = v;
                        changed = true;
                    }
                }
                if let Some(v) = *i_frame_interval {
                    if cfg.i_frame_interval != v {
                        cfg.i_frame_interval = v;
                        changed = true;
                    }
                }
            }
            if !changed {
                debug!("configure no-op (identical values)");
                return Ok(());
            }
            info!(
                max_fps = ?max_fps,
                max_width = ?max_width,
                bitrate = ?bitrate,
                i_frame_interval = ?i_frame_interval,
                "hot reconfigure: restarting scrcpy server"
            );
            let _ = peer
                .send_control_text(datachannel::build_stream_restarted())
                .await;
            if let Some(mut s) = scrcpy_slot.lock().await.take() {
                s.stop().await;
            }
            SCRCPY_RUNNING.set(0);
            return Ok(());
        }
        _ => {}
    }

    let guard = scrcpy_slot.lock().await;
    let Some(server) = guard.as_ref() else {
        return Ok(());
    };
    let Some(control) = server.control.as_ref() else {
        return Ok(());
    };

    match msg {
        ControlIn::Touch {
            action,
            x,
            y,
            pointer_id,
            pressure,
            screen_width,
            screen_height,
        } => {
            if let Some(a) = TouchAction::parse(&action) {
                let _ = control
                    .inject_touch(a, x, y, screen_width.max(1), screen_height.max(1), pointer_id, pressure)
                    .await;
            }
        }
        ControlIn::Scroll {
            x,
            y,
            dx,
            dy,
            screen_width,
            screen_height,
        } => {
            let (sx, sy) = datachannel::wheel_to_scroll(dx, dy, 1.0);
            let _ = control
                .inject_scroll(x, y, screen_width.max(1), screen_height.max(1), sx, sy)
                .await;
        }
        ControlIn::Key { action, keycode } => {
            if let Some(code) = crate::scrcpy::protocol::keycode_from_name(&keycode) {
                let a = if action == "up" { KeyAction::Up } else { KeyAction::Down };
                let _ = control.inject_keycode(a, code, 0, 0).await;
            }
        }
        ControlIn::Text { content } => {
            if !content.is_empty() {
                // Rust path uses scrcpy's `InjectText` control message,
                // which supports full Unicode and does not require shell
                // escaping (unlike `adb shell input text`).
                let _ = control.inject_text(&content).await;
            }
        }
        ControlIn::Back => {
            let _ = control.back_or_screen_on(KeyAction::Down).await;
            let _ = control.back_or_screen_on(KeyAction::Up).await;
        }
        ControlIn::Home => {
            if let Some(code) = crate::scrcpy::protocol::keycode_from_name("KEYCODE_HOME") {
                let _ = control.inject_keycode(KeyAction::Down, code, 0, 0).await;
                let _ = control.inject_keycode(KeyAction::Up, code, 0, 0).await;
            }
        }
        ControlIn::Configure { .. } => {
            // Handled pre-lock above; unreachable here.
        }
        // handled above
        ControlIn::Ping { .. } | ControlIn::Stats { .. } | ControlIn::Unknown => {}
    }
    Ok(())
}

fn msg_kind(msg: &ControlIn) -> &'static str {
    match msg {
        ControlIn::Touch { .. } => "touch",
        ControlIn::Scroll { .. } => "scroll",
        ControlIn::Key { .. } => "key",
        ControlIn::Text { .. } => "text",
        ControlIn::Back => "back",
        ControlIn::Home => "home",
        ControlIn::Configure { .. } => "configure",
        ControlIn::Ping { .. } => "ping",
        ControlIn::Stats { .. } => "stats",
        ControlIn::Unknown => "unknown",
    }
}

/// Pull the actual candidate SDP line out of either `{candidate: "..."}` or a
/// plain string — matches what the Python client sends.
fn candidate_as_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o
            .get("candidate")
            .and_then(|c| c.as_str())
            .map(str::to_string),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::io::Write;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// Build a `Cli` populated with placeholder values for every required
    /// field. Individual tests override the subset they exercise.
    fn make_cli() -> Cli {
        Cli {
            device_id: "dev-test".into(),
            adb_serial: "127.0.0.1:5555".into(),
            adb_host: "127.0.0.1".into(),
            adb_port: 5037,
            max_fps: 30,
            max_width: 1920,
            bitrate: 4_000_000,
            i_frame_interval: 2,
            disable_audio: true,
            ice_urls: vec!["stun:stun.l.google.com:19302".into()],
            turn_username: None,
            turn_credential: None,
            metrics_port: 0,
            public_ips: vec![],
            ice_gather_wait_ms: 0,
            log_format: "text".into(),
            scrcpy_server_jar: None,
            remote_jar_path: "/data/local/tmp/scrcpy-server.jar".into(),
            agent_gateway_url: "http://127.0.0.1:1".into(),
            bridge_private_key_file: String::new(),
            bridge_public_key_file: String::new(),
            jwt_refresh_lead_secs: 60,
            jwt_refresh_min_interval_secs: 30,
        }
    }

    /// Write a valid-format Ed25519 seed (32 bytes) + public key (32 bytes)
    /// to tempfiles so `bootstrap_fetch` can sign a request before the mock
    /// server rejects it.
    fn write_identity() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
        let seed = [7u8; 32];
        let pubk = [9u8; 32];
        let mut priv_f = tempfile::NamedTempFile::new().unwrap();
        priv_f.write_all(B64.encode(seed).as_bytes()).unwrap();
        let mut pub_f = tempfile::NamedTempFile::new().unwrap();
        pub_f.write_all(B64.encode(pubk).as_bytes()).unwrap();
        (priv_f, pub_f)
    }

    #[tokio::test]
    async fn resolve_requires_key_files() {
        let mut cli = make_cli();
        cli.bridge_private_key_file = String::new();
        cli.bridge_public_key_file = String::new();
        let bridge = Bridge::new(cli, HealthFlags::default());
        let err = bridge
            .resolve_initial_credentials()
            .await
            .expect_err("missing key files must abort");
        let msg = format!("{err}");
        assert!(
            msg.contains("BRIDGE_PRIVATE_KEY_FILE") && msg.contains("BRIDGE_PUBLIC_KEY_FILE"),
            "unexpected error: {msg}"
        );
    }

    /// Spin up a one-shot TCP listener that always answers with HTTP 401
    /// and verify that `resolve_initial_credentials` surfaces the bootstrap
    /// failure instead of silently continuing.
    #[tokio::test]
    async fn resolve_bubbles_bootstrap_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept one connection, read request (ignore), reply 401.
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 401 Unauthorized\r\n\
                          content-length: 12\r\n\
                          content-type: text/plain\r\n\
                          connection: close\r\n\r\nunauthorized",
                    )
                    .await;
                let _ = sock.shutdown().await;
            }
        });

        let (priv_f, pub_f) = write_identity();
        let mut cli = make_cli();
        cli.agent_gateway_url = format!("http://{}", addr);
        cli.bridge_private_key_file = priv_f.path().to_string_lossy().into_owned();
        cli.bridge_public_key_file = pub_f.path().to_string_lossy().into_owned();
        let bridge = Bridge::new(cli, HealthFlags::default());
        let err = bridge
            .resolve_initial_credentials()
            .await
            .expect_err("401 from Agent Gateway must fail resolve");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("bootstrap") || chain.contains("401") || chain.contains("Unauthorized"),
            "error chain should mention bootstrap/401: {chain}"
        );
    }

    /// `MqttSignaling::connect` must fail fast when `topic_prefix` is
    /// empty — otherwise we'd silently fall back to an empty prefix and
    /// EMQX would reject every subscribe/publish with `not authorized`
    /// long after the process considered itself "online".
    #[tokio::test]
    async fn mqtt_connect_rejects_empty_topic_prefix() {
        use crate::mqtt::MqttSignalingConfig;
        let result = crate::mqtt::MqttSignaling::connect(MqttSignalingConfig {
            broker_url: "mqtt://127.0.0.1:1".into(),
            username: "device".into(),
            token: "whatever".into(),
            topic_prefix: "   ".into(), // whitespace must count as empty
            client_id: "scrcpy-bridge-test".into(),
        })
        .await;
        match result {
            Ok(_) => panic!("empty topic_prefix must fail fast"),
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("topic_prefix"),
                    "error should mention topic_prefix: {msg}"
                );
            }
        }
    }

    /// When bootstrap returns a TURN server carrying its own short-lived
    /// credentials, `merge_ice_servers` MUST copy that entry verbatim
    /// and MUST NOT overwrite its `username`/`credential` with the
    /// CLI's `--turn-username` / `--turn-credential` (those only apply
    /// to dev-only CLI-injected servers).
    #[test]
    fn ice_servers_prefer_bootstrap() {
        let bootstrap = vec![IceServerPayload {
            urls: vec!["turn:turn.runtime:3478".into()],
            username: Some("runtime-user".into()),
            credential: Some("runtime-pass".into()),
        }];
        let mut cli = make_cli();
        cli.ice_urls = vec![
            "stun:stun.l.google.com:19302".into(), // not in bootstrap, keep
            "turn:turn.runtime:3478".into(),       // duplicate of bootstrap, drop
        ];
        cli.turn_username = Some("cli-user".into());
        cli.turn_credential = Some("cli-pass".into());

        let merged = merge_ice_servers(&bootstrap, &cli);

        // Bootstrap entry preserved with its original creds.
        let turn = merged
            .iter()
            .find(|s| s.urls.iter().any(|u| u == "turn:turn.runtime:3478"))
            .expect("bootstrap TURN must be kept");
        assert_eq!(turn.username.as_deref(), Some("runtime-user"));
        assert_eq!(turn.credential.as_deref(), Some("runtime-pass"));

        // CLI STUN appended with CLI creds (which for STUN are harmless).
        let stun = merged
            .iter()
            .find(|s| s.urls.iter().any(|u| u == "stun:stun.l.google.com:19302"))
            .expect("non-duplicate CLI entry must be appended");
        assert_eq!(stun.username.as_deref(), Some("cli-user"));
        assert_eq!(stun.credential.as_deref(), Some("cli-pass"));

        // No duplicate entry for the URL shared with bootstrap.
        let count = merged
            .iter()
            .filter(|s| s.urls.iter().any(|u| u == "turn:turn.runtime:3478"))
            .count();
        assert_eq!(count, 1, "bootstrap URL must not be duplicated by CLI");
    }

    /// When bootstrap's `iceServers` list is empty (Runtime has no TURN
    /// configured — typical in `goreman` local dev), CLI entries must
    /// still seed the merged list so host/STUN candidates work.
    #[test]
    fn ice_servers_fallback_to_cli_when_bootstrap_empty() {
        let bootstrap: Vec<IceServerPayload> = vec![];
        let mut cli = make_cli();
        cli.ice_urls = vec!["stun:stun.l.google.com:19302".into()];
        cli.turn_username = None;
        cli.turn_credential = None;

        let merged = merge_ice_servers(&bootstrap, &cli);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].urls, vec!["stun:stun.l.google.com:19302"]);
    }
}

