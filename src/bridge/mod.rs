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
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
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
    HealthFlags, AUDIO_PACKETS_DROPPED, AUDIO_PACKETS_TOTAL, CONTROL_MESSAGES_TOTAL, PLI_COUNT_TOTAL,
    SCRCPY_RECONNECTS_TOTAL, SCRCPY_RUNNING, VIDEO_FRAMES_DROPPED, VIDEO_FRAMES_TOTAL,
    VIEWER_BITRATE_BPS, VIEWER_CONNECTED, VIEWER_FPS, VIEWER_PACKETS_LOST, VIEWER_RTT_MS,
};
use crate::scrcpy::protocol::{KeyAction, TouchAction};
use crate::scrcpy::{
    AudioReader, ControlSocket, ScrcpyServer, ScrcpyServerConfig, ScrcpyShutdown, VideoReader,
};
use crate::webrtc::{IceServer, PeerEvent, PeerOptions, WebRtcPeer};

/// MQTT username expected by the EMQX JWT auth plugin. All device-scoped
/// connections log in as `device`; the JWT payload carries the true identity.
const MQTT_USERNAME: &str = "device";

/// How long we keep a scrcpy session + str0m peer alive after the viewer
/// appears to be gone (ICE disconnected/failed, or explicit `Close`
/// request). Inside this window:
///
///   * a subsequent `Offer` from the same `viewer_id` is handled as a
///     cheap ICE restart on the existing `WebRtcPeer` — no scrcpy bounce,
///     no black frame;
///   * an `Offer` from a different `viewer_id` (or timeout) tears down
///     the stale session first, restoring the "most recent viewer wins"
///     semantics.
///
/// 30 s is a sweet spot: long enough to survive `window.onbeforeunload`
/// + page reload, wifi handoff, tab backgrounding on mobile Safari; short
/// enough that a real device abandonment doesn't pin the encoder.
const SESSION_GRACE: Duration = Duration::from_secs(30);

/// Control messages the event pump fires into `Bridge::run`'s main loop
/// so the grace-timer state machine lives in exactly one place. The
/// event pump is per-session and must not own grace state directly — it
/// only knows viewer identity and health transitions.
#[derive(Debug)]
enum BridgeInternalEvent {
    /// Peer reached `Connected` (or came back after an ICE blip). The
    /// main loop clears grace if it was armed for the matching viewer.
    ViewerConnected { viewer_id: String },
    /// Peer observed something that might turn into session death:
    /// `IceConnectionState::Disconnected` (transient) or `Failed`
    /// (requires ICE restart to recover). The main loop arms / extends
    /// the grace window; no teardown happens unless the window expires.
    ViewerUnhealthy {
        viewer_id: String,
        reason: &'static str,
    },
    /// The named viewer's session is being (or has already been) torn
    /// down deliberately — by a newer viewer replacing it (`on_offer`
    /// kick path) or by scrcpy dying underneath it (`run_video_pump`
    /// video-eof). The main loop uses this to drop any grace window
    /// still pointing at the dead viewer so it can't expire later and
    /// accidentally shut down a freshly installed session belonging
    /// to someone else.
    ClearGraceFor { viewer_id: String },
}

/// Grace-window state held locally by `Bridge::run`. Never shared
/// beyond the main loop.
struct SessionGrace {
    viewer_id: String,
    deadline: tokio::time::Instant,
    reason: &'static str,
}

fn arm_grace(slot: &mut Option<SessionGrace>, viewer_id: String, reason: &'static str) {
    let deadline = tokio::time::Instant::now() + SESSION_GRACE;
    match slot {
        Some(g) if g.viewer_id == viewer_id => {
            // Extend the existing window — repeated health signals for
            // the same viewer reset the clock so a viewer that keeps
            // flapping doesn't get kicked out by our grace timer.
            g.deadline = deadline;
            g.reason = reason;
            debug!(viewer = %g.viewer_id, %reason, "extended session grace");
        }
        _ => {
            info!(
                viewer = %viewer_id,
                %reason,
                grace_secs = SESSION_GRACE.as_secs(),
                "armed session grace — holding scrcpy + peer for reconnection"
            );
            *slot = Some(SessionGrace {
                viewer_id,
                deadline,
                reason,
            });
        }
    }
}

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

        // 4. Session state (one active session at a time).
        //
        //    A `Session` bundles the peer, the scrcpy control sender, the
        //    spawned tasks (video/audio/event pump) and a `CancellationToken`
        //    that lets us tear all three down atomically. Starting a new
        //    session first cancels + joins the previous one, guaranteeing
        //    no zombie tasks ever touch a reborn scrcpy socket.
        //
        //    The encoder config lives in its own Arc so the DataChannel
        //    `configure` handler can mutate it between sessions (G8 hot
        //    reconfigure). Every `on_offer` snapshots this Arc when spawning
        //    a new ScrcpyServer.
        let current_session: Arc<Mutex<Option<Session>>> = Arc::new(Mutex::new(None));
        let scrcpy_cfg: Arc<RwLock<ScrcpyServerConfig>> =
            Arc::new(RwLock::new(self.initial_scrcpy_config()));

        // Health signals from the per-session event pump flow through a
        // single mpsc so grace-window decisions live in one place. Cloned
        // into each new `run_event_pump` via `on_offer`.
        let (internal_tx, mut internal_rx) = mpsc::channel::<BridgeInternalEvent>(16);
        let mut grace: Option<SessionGrace> = None;

        loop {
            // `sleep_until` on a missing grace blocks forever; we want
            // the branch to never fire in that case. Using `pending`
            // keeps `select!` polling only the real inputs.
            let grace_fire = async {
                match grace.as_ref() {
                    Some(g) => tokio::time::sleep_until(g.deadline).await,
                    None => std::future::pending::<()>().await,
                }
            };

            tokio::select! {
                biased;

                _ = grace_fire => {
                    if let Some(g) = grace.take() {
                        // Verify the active session still belongs to
                        // the viewer whose grace we armed. Between
                        // arming and expiry a different viewer may
                        // have replaced the session via `on_offer`,
                        // and we must NOT tear that one down. The
                        // `on_offer` kick path also sends
                        // `ClearGraceFor` to pre-empt this race, but
                        // this check is the authoritative safety net.
                        let mut guard = current_session.lock().await;
                        let owned = guard
                            .as_ref()
                            .map(|s| s.viewer_id == g.viewer_id)
                            .unwrap_or(false);
                        if owned {
                            if let Some(session) = guard.take() {
                                drop(guard);
                                info!(
                                    viewer = %g.viewer_id,
                                    reason = %g.reason,
                                    "session grace expired — shutting down scrcpy"
                                );
                                session.shutdown().await;
                                self.health.scrcpy_running.store(false, Ordering::Relaxed);
                                SCRCPY_RUNNING.set(0);
                                VIEWER_CONNECTED.set(0);
                            }
                        } else {
                            info!(
                                viewer = %g.viewer_id,
                                reason = %g.reason,
                                "grace expired but session ownership changed — no teardown"
                            );
                        }
                    }
                }

                maybe_ev = internal_rx.recv() => {
                    let Some(ev) = maybe_ev else {
                        // Dropped only at process shutdown; exit cleanly.
                        break;
                    };
                    match ev {
                        BridgeInternalEvent::ViewerConnected { viewer_id } => {
                            if matches!(&grace, Some(g) if g.viewer_id == viewer_id) {
                                info!(viewer = %viewer_id, "viewer healthy again — cancelling grace");
                                grace = None;
                            }
                        }
                        BridgeInternalEvent::ViewerUnhealthy { viewer_id, reason } => {
                            // Only arm grace if this viewer is still the
                            // owner of the active session. A stale event
                            // for an already-replaced viewer would keep
                            // the new viewer's session on the hook.
                            let still_owner = {
                                let guard = current_session.lock().await;
                                guard.as_ref().map(|s| s.viewer_id == viewer_id).unwrap_or(false)
                            };
                            if still_owner {
                                arm_grace(&mut grace, viewer_id, reason);
                            }
                        }
                        BridgeInternalEvent::ClearGraceFor { viewer_id } => {
                            if matches!(&grace, Some(g) if g.viewer_id == viewer_id) {
                                info!(
                                    viewer = %viewer_id,
                                    "grace cleared — owning viewer is being torn down deliberately"
                                );
                                grace = None;
                            }
                        }
                    }
                }

                maybe_req = sig_rx.recv() => {
                    let Some(req) = maybe_req else { break; };
                    match req {
                        SignalRequest::Offer { sdp, viewer_id } => {
                            // Offer arriving inside our grace window
                            // for the same viewer cancels it — the
                            // viewer is driving a successful recovery.
                            if matches!(&grace, Some(g) if g.viewer_id == viewer_id) {
                                info!(viewer = %viewer_id, "offer arrived inside grace window — cancelling grace");
                                grace = None;
                            }
                            if let Err(e) = self
                                .on_offer(
                                    viewer_id,
                                    sdp,
                                    &mqtt,
                                    &current_session,
                                    &scrcpy_cfg,
                                    internal_tx.clone(),
                                )
                                .await
                            {
                                error!(error = format!("{:#}", e), "handle offer failed");
                            }
                        }
                        SignalRequest::Ice { candidate } => {
                            let guard = current_session.lock().await;
                            if let Some(session) = guard.as_ref() {
                                if let Some(cand_str) = candidate_as_string(&candidate) {
                                    let _ = session.peer.add_remote_ice(cand_str).await;
                                }
                            } else {
                                warn!("ICE candidate received before peer was created");
                            }
                        }
                        SignalRequest::Close { reason, viewer_id } => {
                            // Don't tear down immediately — a viewer
                            // "close" is frequently followed by an
                            // automatic reconnect (page nav, tab
                            // switch, mobile backgrounding). Arm grace
                            // so the scrcpy encoder survives.
                            //
                            // Filter by viewer_id when the payload
                            // carries one: a stale tab closing after
                            // it was already replaced must NOT arm
                            // grace against the live session.
                            let owner = {
                                let guard = current_session.lock().await;
                                guard.as_ref().map(|s| s.viewer_id.clone())
                            };
                            match owner {
                                Some(v) => {
                                    if !viewer_id.is_empty() && viewer_id != v {
                                        info!(
                                            %reason,
                                            close_viewer = %viewer_id,
                                            session_viewer = %v,
                                            "stale viewer close — ignoring"
                                        );
                                    } else {
                                        info!(%reason, viewer = %v, "viewer close — entering session grace");
                                        arm_grace(&mut grace, v, "viewer close");
                                    }
                                }
                                None => {
                                    info!(%reason, "viewer close received but no active session");
                                }
                            }
                        }
                    }
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
        viewer_id: String,
        offer_sdp: String,
        mqtt: &Arc<MqttSignaling>,
        current_session: &Arc<Mutex<Option<Session>>>,
        scrcpy_cfg: &Arc<RwLock<ScrcpyServerConfig>>,
        internal_tx: mpsc::Sender<BridgeInternalEvent>,
    ) -> Result<()> {
        info!(viewer = %viewer_id, "received WebRTC offer");

        // Fast path — same viewer, live peer:
        //   * The viewer side just re-ran `createOffer({iceRestart:
        //     true})` after detecting unhealthy (A2) or as part of a
        //     recovery from within our grace window.
        //   * str0m's `sdp_api().accept_offer` detects the new
        //     ice-ufrag/ice-pwd and performs a proper ICE restart
        //     without touching the DTLS session or the media track
        //     assignments, so there is zero black frame and no scrcpy
        //     bounce.
        //
        // Eligibility: non-empty viewer id (legacy viewers that
        // predate B3 sent empty strings and must not cross-contaminate
        // sessions) AND the viewer is still the owner of the current
        // session. str0m 0.9 has no "unrecoverable" state we can
        // check — if accept_offer itself fails we fall through to
        // the replace path below (Fix B).
        if !viewer_id.is_empty() {
            let peer_opt = {
                let guard = current_session.lock().await;
                guard
                    .as_ref()
                    .filter(|s| s.viewer_id == viewer_id)
                    .map(|s| s.peer.clone())
            };
            if let Some(peer) = peer_opt {
                info!(
                    viewer = %viewer_id,
                    "same-viewer offer → ICE restart on existing peer (scrcpy preserved)"
                );
                // Clone the SDP so the replace path below can still
                // consume it if str0m refuses the fast-path offer
                // (e.g. the peer is in a state the SDP-state-machine
                // can't reconcile). String clone is negligible vs.
                // the alternative of losing a recovery opportunity.
                match peer.accept_offer(offer_sdp.clone()).await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        warn!(
                            viewer = %viewer_id,
                            error = %e,
                            "fast-path accept_offer failed — falling back to full session rebuild"
                        );
                        // Fall through to the replace path below.
                        // The next block takes current_session, which
                        // will kick this (now-wedged) peer + scrcpy
                        // and spawn a fresh session — same semantics
                        // as a different-viewer takeover.
                    }
                }
            }
        }

        // Replace any existing session. Two distinct cases land here:
        //
        //   1. Different viewer taking over (`old.viewer_id != viewer_id`).
        //      The previous browser is still live and needs to be told
        //      explicitly why its session died — otherwise it would
        //      just see its DataChannel disappear and schedule endless
        //      reconnect attempts. Send `viewer_kicked` so its UI can
        //      surface the real reason.
        //
        //   2. Same viewer rebuilding after fast-path `accept_offer`
        //      refused to reconcile (`old.viewer_id == viewer_id`, see
        //      the fall-through comment above). This is the client's
        //      own ICE-restart retry hitting a wedged str0m peer — it
        //      is already waiting on MQTT for the answer to its new
        //      offer, and the "old" peer is the exact same browser tab.
        //      Sending `viewer_kicked` here would make the browser
        //      flip into its terminal `kicked` state ("Another viewer
        //      has connected — this session has ended") and ignore the
        //      fresh answer we're about to publish, stranding the user.
        //      For this case we MUST rebuild silently: the client will
        //      receive the new answer and seamlessly resume.
        //
        // Either way we atomically cancel + join + shut down the scrcpy
        // side before starting the new session. This guarantees no
        // zombie task ever touches a reborn scrcpy socket.
        if let Some(old) = current_session.lock().await.take() {
            // Invalidate any grace window still pointing at the old
            // viewer — otherwise, if A was in grace and B just took
            // over, A's grace timer would expire later and shut down
            // B's freshly installed session (see the ownership check
            // in the `grace_fire` branch for the matching safety net).
            let _ = internal_tx
                .send(BridgeInternalEvent::ClearGraceFor {
                    viewer_id: old.viewer_id.clone(),
                })
                .await;
            if old.viewer_id != viewer_id {
                info!(
                    old_viewer = %old.viewer_id,
                    new_viewer = %viewer_id,
                    "different viewer takeover — notifying old browser via viewer_kicked"
                );
                let _ = old
                    .peer
                    .send_control_text(datachannel::build_viewer_kicked(
                        "replaced by another viewer",
                    ))
                    .await;
                // Give the DataChannel a moment to flush the kick
                // payload before we rip the peer down.
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else {
                info!(
                    viewer = %viewer_id,
                    "same-viewer rebuild (fast-path unavailable) — silent teardown, no kick"
                );
            }
            old.shutdown().await;
        }

        // 1. Start a fresh scrcpy session. Every offer gets a clean
        //    app_process + sockets — simpler invariants and matches how
        //    the Python agent behaves.
        let adb = Adb {
            serial: self.cli.adb_serial.clone(),
            host: self.cli.adb_host.clone(),
            port: self.cli.adb_port,
        };
        let cfg_snapshot = scrcpy_cfg.read().await.clone();
        let mut server = ScrcpyServer::new(adb, cfg_snapshot);
        server.start().await.context("start scrcpy server")?;
        self.health.scrcpy_running.store(true, Ordering::Relaxed);
        SCRCPY_RUNNING.set(1);
        SCRCPY_RECONNECTS_TOTAL.inc();

        let parts = server.split();
        let video_reader = parts.video;
        let audio_reader = parts.audio;
        let control_sender = parts.control;
        let mut shutdown = parts.shutdown;

        // 2. Spawn WebRTC peer.
        //
        // Fallibility budget: once `server.start()` above succeeds we
        // hold a live `app_process` child + an adb reverse-forward
        // rule. Any `?`-propagated failure from here on (peer spawn
        // refused by str0m, accept_offer rejected the SDP, ...) must
        // reap them before returning, or the next offer's
        // `ScrcpyServer::new + start` would collide on the same adb
        // forward port. The async block consolidates the two fallible
        // ops so there's a single cleanup site.
        let construct = async {
            let extra_local_ips = self.resolve_extra_local_ips();
            let ice_servers = self.ice_servers.read().await.clone();
            let peer_opts = PeerOptions {
                ice_servers,
                local_bind: "0.0.0.0:0".parse().unwrap(),
                extra_local_ips,
                ice_gather_wait: Duration::from_millis(self.cli.ice_gather_wait_ms),
            };
            let peer = WebRtcPeer::spawn(peer_opts)?;
            peer.accept_offer(offer_sdp).await?;
            anyhow::Ok(peer)
        };
        let peer = match construct.await {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    error = format!("{:#}", e),
                    viewer = %viewer_id,
                    "new session construction failed — reaping scrcpy server + adb forward"
                );
                shutdown.shutdown().await;
                self.health.scrcpy_running.store(false, Ordering::Relaxed);
                SCRCPY_RUNNING.set(0);
                return Err(e);
            }
        };

        // 3. Per-session plumbing.
        let cancel = CancellationToken::new();
        let mut tasks: JoinSet<()> = JoinSet::new();

        // 3a. Event pump: peer -> MQTT + control forwarding + PLI handling.
        {
            let peer_for_evt = peer.clone();
            let mqtt_evt = mqtt.clone();
            let control_for_evt = control_sender.clone();
            let scrcpy_cfg_for_evt = scrcpy_cfg.clone();
            let health = self.health.clone();
            let session_flag_for_evt = current_session.clone();
            let cancel_for_evt = cancel.clone();
            let scroll_sensitivity = self.cli.scroll_sensitivity;
            let viewer_for_evt = viewer_id.clone();
            let internal_tx_for_evt = internal_tx.clone();
            tasks.spawn(async move {
                run_event_pump(
                    peer_for_evt,
                    mqtt_evt,
                    control_for_evt,
                    scrcpy_cfg_for_evt,
                    session_flag_for_evt,
                    health,
                    cancel_for_evt,
                    scroll_sensitivity,
                    viewer_for_evt,
                    internal_tx_for_evt,
                )
                .await;
            });
        }

        // 3b. Video pump: scrcpy VideoReader -> peer RTP.
        if let Some(reader) = video_reader {
            let peer_for_video = peer.clone();
            let cancel_for_video = cancel.clone();
            let session_flag_for_video = current_session.clone();
            let viewer_for_video = viewer_id.clone();
            let internal_tx_for_video = internal_tx.clone();
            tasks.spawn(async move {
                run_video_pump(
                    reader,
                    peer_for_video,
                    cancel_for_video,
                    session_flag_for_video,
                    viewer_for_video,
                    internal_tx_for_video,
                )
                .await;
            });
        } else {
            warn!("scrcpy video socket was not open — session starts without video");
        }

        // 3c. Audio pump: scrcpy AudioReader -> peer RTP.
        if let Some(reader) = audio_reader {
            let peer_for_audio = peer.clone();
            let cancel_for_audio = cancel.clone();
            tasks.spawn(async move {
                run_audio_pump(reader, peer_for_audio, cancel_for_audio).await;
            });
        }

        // Suppress the unused-binding lint: control_sender lives only via
        // the `Arc` clone captured by the event pump; when that task exits
        // (on `cancel`), the last clone drops and the drainer aborts.
        drop(control_sender);

        *current_session.lock().await = Some(Session {
            viewer_id,
            peer,
            cancel,
            tasks,
            shutdown,
        });
        Ok(())
    }

    /// Resolve the concrete IPs to advertise as ICE host candidates. Prefers
    /// operator-pinned `--public-ips`; otherwise enumerates local interfaces
    /// (skipping loopback + IPv6 link-local, which str0m can't parse).
    fn resolve_extra_local_ips(&self) -> Vec<std::net::IpAddr> {
        let mut extra_local_ips = self
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

        if extra_local_ips.is_empty() {
            match if_addrs::get_if_addrs() {
                Ok(ifaces) => {
                    for iface in ifaces {
                        let ip = iface.ip();
                        if ip.is_loopback() || ip.is_unspecified() {
                            continue;
                        }
                        if let std::net::IpAddr::V6(v6) = ip {
                            let seg = v6.segments()[0];
                            if (seg & 0xffc0) == 0xfe80 {
                                continue;
                            }
                        }
                        extra_local_ips.push(ip);
                    }
                    if extra_local_ips.is_empty() {
                        warn!("no non-loopback interfaces found; WebRTC will only work over loopback");
                    } else {
                        info!(count = extra_local_ips.len(), ips = ?extra_local_ips, "auto-enumerated host candidate IPs");
                    }
                }
                Err(e) => warn!(error = %e, "failed to enumerate interfaces for host candidates"),
            }
        }
        extra_local_ips
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
// Session plumbing
// ---------------------------------------------------------------------------

/// Grouping of everything that belongs to a single browser connection. The
/// `Bridge::run` main loop holds at most one `Session` at a time and drops
/// the previous one (via `shutdown()`) before starting a new one, so three
/// invariants always hold:
///
/// 1. scrcpy sockets have exactly one reader/writer task each;
/// 2. cancelling the token causes all spawned tasks to exit on the next
///    await point (they all `select!` on `cancel.cancelled()`);
/// 3. scrcpy process is reaped after — not before — its readers have
///    observed EOF and exited.
pub(crate) struct Session {
    /// Stable per-browser identifier, echoed back by the viewer on
    /// every Offer. Used by the grace-window state machine to
    /// distinguish "same viewer reconnecting" (keep scrcpy) from
    /// "different viewer stealing the device" (kick + rebuild).
    viewer_id: String,
    peer: WebRtcPeer,
    cancel: CancellationToken,
    tasks: JoinSet<()>,
    shutdown: ScrcpyShutdown,
}

impl Session {
    /// Cancel all tasks, wait for them to exit, then tear down scrcpy.
    /// After returning, the underlying adb forward rule is cleared and
    /// the scrcpy `app_process` has been reaped.
    pub(crate) async fn shutdown(mut self) {
        self.cancel.cancel();
        // Close the peer synchronously (this drops the str0m Rtc, which
        // also drops the UDP socket — unblocking any reader task).
        self.peer.close().await;
        // Drain tasks; they each race a `cancel.cancelled()` branch.
        while self.tasks.join_next().await.is_some() {}
        self.shutdown.shutdown().await;
    }
}

/// Pump peer events out to MQTT, back into scrcpy control (PLI → reset_video,
/// DataChannel control messages → touches/keys/etc), and surface connection
/// state changes to the observability layer.
async fn run_event_pump(
    peer: WebRtcPeer,
    mqtt: Arc<MqttSignaling>,
    control: Option<Arc<ControlSocket>>,
    scrcpy_cfg: Arc<RwLock<ScrcpyServerConfig>>,
    current_session: Arc<Mutex<Option<Session>>>,
    health: HealthFlags,
    cancel: CancellationToken,
    scroll_sensitivity: f32,
    viewer_id: String,
    internal_tx: mpsc::Sender<BridgeInternalEvent>,
) {
    let mut evt_rx = peer.subscribe();
    // Browsers emit PLI roughly every 200 ms after any packet loss. Scrcpy
    // needs ~1 encode cycle to emit a new IDR, so we rate-limit how often
    // we actually poke the device. The `StreamReady` edge is NOT subject
    // to this throttle — it fires exactly once per ICE session and is
    // what gets the very first frame on screen without waiting for PLI.
    const PLI_THROTTLE: Duration = Duration::from_millis(200);
    let mut last_reset_video = Instant::now() - Duration::from_secs(5);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!("event pump cancelled");
                return;
            }
            recv = evt_rx.recv() => {
                let evt = match recv {
                    Ok(e) => e,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(lagged = n, "event pump lagged");
                        continue;
                    }
                };
                match evt {
                    PeerEvent::Answer(sdp) => {
                        if let Err(e) = mqtt.publish_response(&SignalResponse::Answer { sdp }).await {
                            warn!(error = %e, "publish answer");
                        }
                    }
                    PeerEvent::LocalIce(cand) => {
                        let payload = serde_json::json!({
                            "candidate": cand,
                            "sdpMid": "0",
                            "sdpMLineIndex": 0,
                        });
                        if let Err(e) = mqtt
                            .publish_response(&SignalResponse::Ice { candidate: payload })
                            .await
                        {
                            warn!(error = %e, "publish local ice");
                        }
                    }
                    PeerEvent::Connected => {
                        VIEWER_CONNECTED.set(1);
                        // Clear any stale grace decision for this
                        // viewer — we're healthy again.
                        info!(viewer = %viewer_id, "viewer connected");
                        let _ = internal_tx
                            .send(BridgeInternalEvent::ViewerConnected {
                                viewer_id: viewer_id.clone(),
                            })
                            .await;
                    }
                    PeerEvent::StreamReady => {
                        // ICE is up AND the video mid is negotiated. We used
                        // to proactively call `reset_video` here to prime an
                        // IDR, but scrcpy's Controller.resetVideo() triggers
                        // SurfaceCapture.invalidate(), which NPEs if the
                        // capture's CaptureListener has not attached yet — a
                        // startup race we lose ~100% of the time because
                        // `server.start()` returns as soon as the sockets
                        // accept, well before the capture pipeline is wired.
                        //
                        // This is also just unnecessary: every `on_offer`
                        // boots a fresh scrcpy process whose very first
                        // emitted NAL unit is an IDR keyframe. So the first
                        // frame is already a keyframe without any prompting.
                        // Mid-stream keyframe recovery is handled by the
                        // `KeyframeRequested` (PLI) branch below, which
                        // fires only after capture is fully initialized.
                        debug!("stream ready — relying on natural initial IDR");
                    }
                    PeerEvent::Disconnected => {
                        VIEWER_CONNECTED.set(0);
                        info!(viewer = %viewer_id, "viewer ICE disconnected");
                        // str0m 0.9 does not distinguish transient vs
                        // fatal ICE failure — both collapse to the
                        // single `Disconnected` event here. We don't
                        // touch the session ourselves; the grace
                        // timer armed by the main loop is the only
                        // arbiter of teardown. If the same viewer
                        // comes back with a new offer, on_offer's
                        // fast path tries an ICE restart and falls
                        // back to a full rebuild iff str0m refuses.
                        let _ = internal_tx
                            .send(BridgeInternalEvent::ViewerUnhealthy {
                                viewer_id: viewer_id.clone(),
                                reason: "ice disconnected",
                            })
                            .await;
                    }
                    PeerEvent::ControlMessage(text) => {
                        if let Err(e) =
                            forward_control(&text, control.as_ref(), &scrcpy_cfg, &peer, &health,
                                &current_session, scroll_sensitivity).await
                        {
                            warn!(error = %e, "forward control");
                        }
                    }
                    PeerEvent::KeyframeRequested => {
                        PLI_COUNT_TOTAL.inc();
                        let now = Instant::now();
                        if now.duration_since(last_reset_video) < PLI_THROTTLE {
                            continue;
                        }
                        last_reset_video = now;
                        if let Some(ctrl) = control.as_ref() {
                            info!("PLI received — asking scrcpy for keyframe");
                            if let Err(e) = ctrl.reset_video().await {
                                warn!(error = %e, "scrcpy reset_video on PLI");
                            }
                        }
                    }
                    PeerEvent::Error(e) => {
                        warn!(%e, "peer error event");
                    }
                }
            }
        }
    }
}

/// Pump H.264 NAL units from scrcpy's video socket into the WebRTC peer as
/// native RTP. Keyframe and codec-config frames block until accepted (they
/// are correctness-critical); delta frames fall back to drop-newest so a
/// temporarily slow peer task never backs up the device-side encoder.
async fn run_video_pump(
    mut reader: VideoReader,
    peer: WebRtcPeer,
    cancel: CancellationToken,
    current_session: Arc<Mutex<Option<Session>>>,
    viewer_id: String,
    internal_tx: mpsc::Sender<BridgeInternalEvent>,
) {
    let exit_reason: &'static str = loop {
        let frame = tokio::select! {
            biased;
            _ = cancel.cancelled() => break "cancelled",
            next = reader.next_frame() => match next {
                Ok(Some(f)) => f,
                Ok(None) => break "video-eof",
                Err(e) => {
                    warn!(error = %e, "video read error");
                    break "video-error";
                }
            }
        };

        let kind = if frame.is_config {
            "config"
        } else if frame.is_keyframe {
            "keyframe"
        } else {
            "delta"
        };
        VIDEO_FRAMES_TOTAL.with_label_values(&[kind]).inc();

        // Keyframes and SPS/PPS config packets MUST reach the peer — losing
        // them would strand the decoder until the next IDR interval.
        // Delta frames are eligible for drop-newest backpressure: if the
        // peer command queue happens to be full at this moment, skipping
        // one P-frame produces at most one visual glitch and the decoder
        // recovers on the next keyframe.
        let must_deliver = frame.is_keyframe || frame.is_config;
        if must_deliver {
            if let Err(e) = peer.write_video(frame).await {
                warn!(error = %e, "peer write_video (keyframe/config)");
                break "peer-write-error";
            }
        } else if !peer.try_write_video(frame) {
            VIDEO_FRAMES_DROPPED.with_label_values(&["queue_full"]).inc();
        }
    };

    // scrcpy video pipeline ended. Only tell the browser to reset its
    // session when the scrcpy side itself went away; `cancelled` means
    // the supervisor is tearing us down on purpose (page refresh / new
    // offer) and the browser already knows.
    if matches!(exit_reason, "video-eof" | "video-error") {
        let _ = peer
            .send_control_text(datachannel::build_stream_restarted())
            .await;
        // Invalidate any grace window still pointing at this viewer —
        // the session we would have held onto during grace is gone,
        // so a future same-viewer offer must go through the full
        // rebuild path. Without this, grace could expire ~30 s later
        // and (through the ownership check) log spuriously or — if a
        // new viewer has replaced us — just be a noisy no-op.
        let _ = internal_tx
            .send(BridgeInternalEvent::ClearGraceFor {
                viewer_id: viewer_id.clone(),
            })
            .await;
        // Drop the whole session so the next offer spawns a clean one.
        if let Some(session) = current_session.lock().await.take() {
            // Avoid blocking the current task on its own JoinSet join
            // (we're inside one of the joined tasks) — spawn the shutdown.
            tokio::spawn(async move {
                session.shutdown().await;
            });
        }
        SCRCPY_RUNNING.set(0);
    }
    debug!(reason = exit_reason, "video pump exited");
}

/// Pump Opus packets from scrcpy's audio socket into the WebRTC peer as
/// native RTP. Audio is always drop-newest: a stale 20 ms Opus frame has
/// no audible value, and the backlog latency it would introduce is worse
/// than the single-packet gap. Config (OpusHead) is filtered inside the
/// peer task since that's where codec knowledge lives.
async fn run_audio_pump(
    mut reader: AudioReader,
    peer: WebRtcPeer,
    cancel: CancellationToken,
) {
    loop {
        let pkt = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!("audio pump cancelled");
                return;
            }
            next = reader.next_packet() => match next {
                Ok(Some(p)) => p,
                Ok(None) => {
                    info!("scrcpy audio socket closed");
                    return;
                }
                Err(e) => {
                    warn!(error = %e, "audio read error");
                    return;
                }
            }
        };

        let kind = if pkt.is_config { "config" } else { "data" };
        AUDIO_PACKETS_TOTAL.with_label_values(&[kind]).inc();
        if !peer.try_write_audio(pkt) {
            AUDIO_PACKETS_DROPPED.inc();
        }
    }
}

// ---------------------------------------------------------------------------

/// Translate a browser DataChannel message into scrcpy control socket calls
/// or metrics updates. `peer` is used to send replies (pong, ack) back.
async fn forward_control(
    text: &str,
    control: Option<&Arc<ControlSocket>>,
    scrcpy_cfg: &Arc<RwLock<ScrcpyServerConfig>>,
    peer: &WebRtcPeer,
    _health: &HealthFlags,
    current_session: &Arc<Mutex<Option<Session>>>,
    scroll_sensitivity: f32,
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
            if let Some(session) = current_session.lock().await.take() {
                // Session::shutdown cancels tasks and reaps scrcpy. The
                // browser's `stream_restarted` handler reconnects shortly
                // after and picks up the fresh encoder config on the
                // next offer.
                tokio::spawn(async move {
                    session.shutdown().await;
                });
            }
            SCRCPY_RUNNING.set(0);
            return Ok(());
        }
        _ => {}
    }

    let Some(control) = control else {
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
            let (sx, sy) = datachannel::wheel_to_scroll(dx, dy, scroll_sensitivity);
            debug!(dx, dy, sx, sy, scroll_sensitivity, "scroll");
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
            scroll_sensitivity: 1.0,
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

