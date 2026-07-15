//! MQTT-based WebRTC signaling client.
//!
//! Self-healing design. Four invariants, each closing a real production
//! failure mode (staging incident 2026-07-13: EMQX pod replaced → bridge
//! silently unreachable for hours while logging "subscribed"):
//!
//! 1. **The event-loop task never blocks on anything but `poll()`** —
//!    inbound signals are forwarded with `try_send` (drop + count on
//!    backpressure) and error backoff sleeps race the shutdown signal.
//!    A blocked event loop stops rumqttc's keepalive, EMQX drops the
//!    connection after 1.5×keepalive, and the task never even sees the
//!    error — the exact silent-death observed when a wedged `on_offer`
//!    stalled the signal receiver.
//! 2. **Session start is truthful** — [`start_session`] drives the
//!    eventloop inline until `ConnAck(Success)` *and* `SubAck` arrive
//!    (bounded by [`CONNECT_DEADLINE`]). "subscribed" is only logged when
//!    the broker acknowledged it; `connect`/`reconnect` returning `Ok`
//!    means messages will actually flow.
//! 3. **Re-subscribe on every reconnect** — sessions use
//!    `clean_session=true`, so rumqttc's internal auto-reconnect loses all
//!    subscriptions. The task re-issues the subscribe on every in-task
//!    `ConnAck`; without this a "recovered" connection receives nothing
//!    forever.
//! 4. **Deterministic teardown, old before new** — teardown signals the
//!    task, waits [`TEARDOWN_GRACE`], then `abort()`s (never leaks).
//!    Rebuilds tear the old session down *before* starting the new one:
//!    both use the same MQTT client id, and a lingering old connection
//!    auto-reconnecting mid-swap would kick the new one off the broker
//!    (mutual-takeover loop).
//!
//! A watchdog task (spawned by [`MqttSignaling::connect`]) checks every
//! [`WATCHDOG_TICK`] that the event loop produced at least one successful
//! poll event within [`STALE_AFTER`] (a healthy idle connection pings every
//! `KEEP_ALIVE`, so silence means wedged) and that the session slot is
//! occupied (a failed credential rotation leaves it empty). Either
//! condition triggers a rebuild from the most recently stored credentials.
//! Hot credential rotation via [`MqttSignaling::reconnect`] rebuilds
//! unconditionally: rumqttc reuses the *initial* password on auto-reconnect,
//! so a fresh JWT only takes effect through a session swap. The
//! externally-visible `mpsc::Receiver<SignalRequest>` survives all rebuilds.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use rumqttc::{
    AsyncClient, ClientError, ConnectReturnCode, Event, EventLoop, MqttOptions, Packet, QoS,
    Transport,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::observability::{
    MQTT_RECONNECTS_TOTAL, MQTT_SIGNALS_DROPPED_TOTAL, MQTT_WATCHDOG_REBUILDS_TOTAL,
};

/// MQTT keepalive. EMQX drops a client after 1.5× this without a PINGREQ,
/// which doubles as our upper bound on how long a wedged-but-connected
/// event loop can appear alive to the broker.
const KEEP_ALIVE: Duration = Duration::from_secs(30);

/// Upper bound for TCP/TLS/WS connect + ConnAck + SubAck during
/// [`start_session`]. rumqttc's own per-connect timeout is 5s; this outer
/// deadline additionally covers the ConnAck/SubAck round trips.
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);

/// How long teardown waits for the event-loop task to exit after the
/// shutdown signal before force-aborting it. The task's awaits are all
/// shutdown-aware, so in practice it exits in milliseconds — the abort is
/// the backstop that guarantees we never leak a connection holding our
/// client id.
const TEARDOWN_GRACE: Duration = Duration::from_secs(2);

/// Watchdog check interval. Also the effective retry cadence for rebuilds
/// after a failed credential rotation (empty session slot).
const WATCHDOG_TICK: Duration = Duration::from_secs(15);

/// No successful poll event for this long ⇒ the event loop is considered
/// wedged and the watchdog rebuilds the session. A healthy idle connection
/// produces PINGREQ/PINGRESP events every [`KEEP_ALIVE`], so 3× keepalive
/// cannot false-positive on quiet links.
const STALE_AFTER: Duration = Duration::from_secs(90);

/// Process-wide monotonic origin for the `last_ok_ms` activity clock.
static CLOCK_ORIGIN: Lazy<Instant> = Lazy::new(Instant::now);

fn now_ms() -> u64 {
    CLOCK_ORIGIN.elapsed().as_millis() as u64
}

#[derive(Debug, Clone)]
pub struct MqttSignalingConfig {
    pub broker_url: String,
    pub username: String,
    /// RS256 JWT string.
    pub token: String,
    /// MQTT topic prefix as issued by Runtime via the Agent Gateway
    /// bootstrap response (field `deviceTopic`). Looks like
    /// `devices/device-<instanceUUID>` — no trailing slash. All signaling
    /// and telemetry topics are built by appending a sub-path to this
    /// value. Do NOT confuse this with the bare instance ID; EMQX's JWT
    /// ACL is scoped to exactly this prefix and any mismatch is rejected.
    pub topic_prefix: String,
    pub client_id: String,
    /// Health flag surfaced on `/healthz` (`mqtt` field). Set to `true`
    /// whenever a session is verified connected+subscribed, `false` when a
    /// rebuild fails or the watchdog detects staleness. The bridge passes
    /// `HealthFlags::mqtt_connected` here.
    pub connected_flag: Arc<AtomicBool>,
}

/// Credentials subset used by [`MqttSignaling::reconnect`]. Everything else
/// (client_id, device_id) is immutable for the lifetime of the bridge and
/// stays on the struct itself.
#[derive(Debug, Clone)]
pub struct MqttCredentials {
    pub broker_url: String,
    pub username: String,
    pub token: String,
}

/// Signaling request as it appears on the wire. Matches the Python / browser
/// JSON shape exactly.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SignalRequest {
    /// SDP offer from the browser.
    Offer {
        sdp: String,
        /// Stable per-browser identifier generated by the viewer
        /// (`crypto.randomUUID()` on first `new WebRTCClient`). Stays
        /// constant across ICE restarts and full reconnects from the
        /// same page load, lets the bridge distinguish "the same
        /// viewer is recovering its connection" from "a different
        /// viewer showed up, kick the old one". Older viewers that
        /// predate this field simply send an empty string, which
        /// matches the legacy "always kick" behaviour.
        #[serde(default, rename = "viewerId")]
        viewer_id: String,
    },
    /// Trickle ICE candidate from the browser.
    Ice {
        candidate: serde_json::Value,
    },
    /// Browser asked us to close the peer (optional).
    Close {
        #[serde(default)]
        reason: String,
        /// Same stable viewer identifier sent with `Offer`. The bridge
        /// ignores `Close` payloads whose `viewer_id` doesn't match
        /// the current session — this happens when a stale tab on the
        /// way out races an already-installed newer viewer. Empty
        /// string keeps backwards-compat with older clients that
        /// predate the field.
        #[serde(default, rename = "viewerId")]
        viewer_id: String,
    },
}

/// Response to publish on `signaling/response`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SignalResponse {
    Answer { sdp: String },
    Ice { candidate: serde_json::Value },
}

/// Client + shutdown handle for a single rumqttc AsyncClient lifetime.
struct Session {
    client: AsyncClient,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// State shared between the public handle, the event-loop tasks and the
/// watchdog. The watchdog holds only a `Weak` so it terminates naturally
/// when the last `MqttSignaling` clone is dropped.
struct Shared {
    /// Current session, `None` while down (e.g. after a failed rebuild —
    /// the watchdog keeps retrying until it comes back).
    session: RwLock<Option<Session>>,
    /// Serializes rebuilds between `reconnect` (credential rotation) and
    /// the watchdog so they can never tear down each other's fresh session.
    rebuild_mu: Mutex<()>,
    /// Most recently issued credentials; rebuilds always use these.
    creds: RwLock<MqttCredentials>,
    /// Millisecond timestamp (see [`now_ms`]) of the last successful
    /// eventloop poll — the liveness signal the watchdog checks.
    last_ok_ms: Arc<AtomicU64>,
    connected: Arc<AtomicBool>,
    topic_prefix: String,
    client_id: String,
    sig_tx: mpsc::Sender<SignalRequest>,
}

pub struct MqttSignaling {
    shared: Arc<Shared>,
}

impl MqttSignaling {
    /// Connect to the broker and return (signaling, request_rx).
    ///
    /// Returns `Ok` only after the broker acknowledged both the connection
    /// (`ConnAck` with `Success`) and the signaling subscription (`SubAck`),
    /// bounded by [`CONNECT_DEADLINE`].
    ///
    /// `request_rx` yields browser → device signaling messages parsed from
    /// JSON. The caller uses [`MqttSignaling::publish_response`] for the
    /// reverse path. When the underlying credentials expire the caller
    /// should invoke [`MqttSignaling::reconnect`] which preserves
    /// `request_rx`.
    pub async fn connect(
        cfg: MqttSignalingConfig,
    ) -> Result<(Self, mpsc::Receiver<SignalRequest>)> {
        if cfg.topic_prefix.trim().is_empty() {
            return Err(anyhow!("MqttSignalingConfig.topic_prefix must not be empty"));
        }
        let (sig_tx, rx) = mpsc::channel::<SignalRequest>(32);
        let shared = Arc::new(Shared {
            session: RwLock::new(None),
            rebuild_mu: Mutex::new(()),
            creds: RwLock::new(MqttCredentials {
                broker_url: cfg.broker_url,
                username: cfg.username,
                token: cfg.token,
            }),
            last_ok_ms: Arc::new(AtomicU64::new(now_ms())),
            connected: cfg.connected_flag,
            topic_prefix: cfg.topic_prefix,
            client_id: cfg.client_id,
            sig_tx,
        });

        rebuild(&shared).await.context("initial mqtt session")?;
        spawn_watchdog(Arc::downgrade(&shared));

        Ok((Self { shared }, rx))
    }

    /// Swap in fresh credentials via a full session rebuild (old torn down
    /// first — see module docs for why order matters). Unconditional: even
    /// a currently-healthy session must be swapped, because rumqttc's
    /// auto-reconnect reuses the password it was constructed with and the
    /// old JWT is about to expire.
    ///
    /// On failure the session slot is left empty and the health flag is
    /// `false`; the watchdog retries with these (or newer) credentials
    /// every [`WATCHDOG_TICK`].
    pub async fn reconnect(&self, creds: MqttCredentials) -> Result<()> {
        MQTT_RECONNECTS_TOTAL.inc();
        *self.shared.creds.write().await = creds;
        rebuild(&self.shared).await
    }

    pub async fn publish_response(&self, resp: &SignalResponse) -> Result<()> {
        let topic = format!("{}/signaling/response", self.shared.topic_prefix);
        let payload = serde_json::to_vec(resp).context("encode signaling response")?;
        self.publish_raw(topic, QoS::AtLeastOnce, payload).await
    }

    /// Publish generic device info or telemetry.
    pub async fn publish_json(&self, suffix: &str, value: &serde_json::Value) -> Result<()> {
        let topic = format!("{}/{}", self.shared.topic_prefix, suffix);
        let payload = serde_json::to_vec(value).context("encode mqtt json")?;
        self.publish_raw(topic, QoS::AtMostOnce, payload).await
    }

    async fn publish_raw(&self, topic: String, qos: QoS, payload: Vec<u8>) -> Result<()> {
        let client = {
            let guard = self.shared.session.read().await;
            guard
                .as_ref()
                .map(|s| s.client.clone())
                .ok_or_else(|| anyhow!("mqtt not connected"))?
        };
        client
            .publish(topic, qos, false, payload)
            .await
            .map_err(|e: ClientError| anyhow!("mqtt publish: {e}"))
    }
}

/// Tear down the current session (if any) and start a fresh one from the
/// stored credentials. Serialized by `rebuild_mu`. On success the health
/// flag is raised and the activity clock reset; on failure the slot stays
/// empty and the flag drops so `/healthz` and the watchdog both see it.
async fn rebuild(shared: &Arc<Shared>) -> Result<()> {
    let _guard = shared.rebuild_mu.lock().await;
    rebuild_locked(shared).await
}

async fn rebuild_locked(shared: &Arc<Shared>) -> Result<()> {
    // Old session down FIRST: it shares our client id, and if it lingered
    // it would auto-reconnect and kick the new session off the broker.
    if let Some(old) = shared.session.write().await.take() {
        teardown(old).await;
    }

    let creds = shared.creds.read().await.clone();
    match start_session(shared, creds).await {
        Ok(session) => {
            *shared.session.write().await = Some(session);
            shared.last_ok_ms.store(now_ms(), Ordering::Relaxed);
            shared.connected.store(true, Ordering::Relaxed);
            Ok(())
        }
        Err(e) => {
            shared.connected.store(false, Ordering::Relaxed);
            Err(e)
        }
    }
}

/// Deterministic session teardown: polite DISCONNECT (best-effort,
/// non-blocking), shutdown signal, bounded join, force-abort. Never blocks
/// longer than [`TEARDOWN_GRACE`] and never leaks the task.
async fn teardown(session: Session) {
    let Session {
        client,
        shutdown,
        mut task,
    } = session;
    // try_disconnect only enqueues; ignore full/closed — the abort below
    // closes the socket regardless.
    let _ = client.try_disconnect();
    let _ = shutdown.send(());
    if tokio::time::timeout(TEARDOWN_GRACE, &mut task).await.is_err() {
        warn!("mqtt event-loop task did not exit within grace — aborting");
        task.abort();
        // Observe the cancellation so the JoinHandle is not dropped mid-air.
        let _ = task.await;
    }
}

/// Watchdog: rebuild the session when the event loop goes silent (wedged
/// connection the broker already dropped) or the session slot is empty
/// (previous rebuild failed). Holds only a `Weak` so it exits when the
/// signaling handle is gone.
fn spawn_watchdog(shared: std::sync::Weak<Shared>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(WATCHDOG_TICK).await;
            let Some(shared) = shared.upgrade() else {
                return;
            };

            let stale =
                now_ms().saturating_sub(shared.last_ok_ms.load(Ordering::Relaxed))
                    > STALE_AFTER.as_millis() as u64;
            let empty = shared.session.read().await.is_none();
            if !stale && !empty {
                continue;
            }

            // Re-check under the rebuild lock: a concurrent credential
            // rotation may have already installed a fresh session while we
            // were waiting, and tearing that one down would be pure churn.
            let guard = shared.rebuild_mu.lock().await;
            let stale =
                now_ms().saturating_sub(shared.last_ok_ms.load(Ordering::Relaxed))
                    > STALE_AFTER.as_millis() as u64;
            let empty = shared.session.read().await.is_none();
            if !stale && !empty {
                continue;
            }

            warn!(stale, empty, "mqtt watchdog: session unhealthy — rebuilding");
            MQTT_WATCHDOG_REBUILDS_TOTAL.inc();
            shared.connected.store(false, Ordering::Relaxed);
            match rebuild_locked(&shared).await {
                Ok(()) => info!("mqtt watchdog: session rebuilt"),
                Err(e) => warn!(
                    error = format!("{e:#}"),
                    retry_secs = WATCHDOG_TICK.as_secs(),
                    "mqtt watchdog: rebuild failed — will retry"
                ),
            }
            drop(guard);
        }
    });
}

/// Build rumqttc options, connect, verify ConnAck + SubAck inline (bounded
/// by [`CONNECT_DEADLINE`]), then hand the eventloop to the long-running
/// task. Success therefore means "the broker acknowledged our
/// subscription", not "a request was enqueued".
async fn start_session(shared: &Arc<Shared>, creds: MqttCredentials) -> Result<Session> {
    let opts = build_mqtt_options(&creds, &shared.client_id)?;
    let (client, mut eventloop) = AsyncClient::new(opts, 64);

    let request_topic = format!("{}/signaling/request", shared.topic_prefix);
    client
        .try_subscribe(&request_topic, QoS::AtLeastOnce)
        .context("enqueue mqtt subscribe")?;

    // Drive the eventloop inline until the broker acknowledged both the
    // connection and the subscription. Early publishes (possible in theory
    // between SUBSCRIBE and SUBACK on session-present brokers) are
    // forwarded, not dropped.
    let deadline = Instant::now() + CONNECT_DEADLINE;
    let mut connected = false;
    let mut subscribed = false;
    while !(connected && subscribed) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!(
                "mqtt session not ready within {}s (connack={connected}, suback={subscribed})",
                CONNECT_DEADLINE.as_secs()
            ));
        }
        let event = tokio::time::timeout(remaining, eventloop.poll())
            .await
            .map_err(|_| {
                anyhow!(
                    "mqtt session not ready within {}s (connack={connected}, suback={subscribed})",
                    CONNECT_DEADLINE.as_secs()
                )
            })?
            .context("mqtt connect")?;
        match event {
            Event::Incoming(Packet::ConnAck(ack)) => {
                if ack.code != ConnectReturnCode::Success {
                    // Covers NotAuthorized on an expired/invalid JWT — the
                    // caller (refresh loop / watchdog) retries with fresh
                    // credentials.
                    return Err(anyhow!("mqtt broker refused connection: {:?}", ack.code));
                }
                connected = true;
            }
            Event::Incoming(Packet::SubAck(_)) => {
                subscribed = true;
            }
            Event::Incoming(Packet::Publish(p)) => {
                handle_publish(&shared.sig_tx, &request_topic, &p.topic, &p.payload);
            }
            _ => {}
        }
    }
    info!(topic = %request_topic, "subscribed to MQTT signaling (broker acknowledged)");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(run_event_loop(
        eventloop,
        client.clone(),
        request_topic,
        shared.sig_tx.clone(),
        shared.last_ok_ms.clone(),
        shutdown_rx,
    ));

    Ok(Session {
        client,
        shutdown: shutdown_tx,
        task,
    })
}

/// Long-running eventloop pump. Every await in here either races the
/// shutdown signal or is `eventloop.poll()` itself — the loop can never be
/// blocked by a slow downstream consumer (invariant 1 in the module docs).
async fn run_event_loop(
    mut eventloop: EventLoop,
    client: AsyncClient,
    request_topic: String,
    sig_tx: mpsc::Sender<SignalRequest>,
    last_ok_ms: Arc<AtomicU64>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                info!(topic = %request_topic, "mqtt event loop received shutdown signal");
                return;
            }
            event = eventloop.poll() => {
                match event {
                    Ok(ev) => {
                        last_ok_ms.store(now_ms(), Ordering::Relaxed);
                        match ev {
                            Event::Incoming(Packet::ConnAck(_)) => {
                                // rumqttc auto-reconnected. clean_session=true
                                // means the broker holds NO subscriptions for
                                // this fresh session — re-subscribe or we'd
                                // poll pings forever receiving nothing.
                                info!(topic = %request_topic, "mqtt reconnected — re-subscribing");
                                if let Err(e) =
                                    client.try_subscribe(&request_topic, QoS::AtLeastOnce)
                                {
                                    // Request channel full/closed. Unfixable
                                    // from here; the watchdog will observe
                                    // the resulting silence and rebuild.
                                    warn!(error = %e, "mqtt re-subscribe enqueue failed");
                                }
                            }
                            Event::Incoming(Packet::SubAck(_)) => {
                                debug!(topic = %request_topic, "mqtt subscription acknowledged");
                            }
                            Event::Incoming(Packet::Publish(p)) => {
                                if !handle_publish(&sig_tx, &request_topic, &p.topic, &p.payload) {
                                    // Receiver gone — the bridge is shutting
                                    // down; nothing left to pump for.
                                    return;
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "MQTT eventloop error, waiting before retry");
                        // Backoff, but stay responsive to shutdown.
                        tokio::select! {
                            _ = &mut shutdown_rx => {
                                info!(topic = %request_topic, "mqtt event loop received shutdown signal");
                                return;
                            }
                            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                        }
                    }
                }
            }
        }
    }
}

/// Forward one inbound publish to the signal channel. Returns `false` only
/// when the receiver is closed (process shutdown). Logs and counts here so
/// [`forward_signal`] stays a pure, unit-testable decision function.
fn handle_publish(
    sig_tx: &mpsc::Sender<SignalRequest>,
    expected_topic: &str,
    topic: &str,
    payload: &[u8],
) -> bool {
    match forward_signal(sig_tx, expected_topic, topic, payload) {
        Forward::Sent | Forward::WrongTopic => true,
        Forward::Invalid(e) => {
            warn!(
                topic = %topic,
                error = %e,
                raw = %String::from_utf8_lossy(payload),
                "invalid signaling payload"
            );
            true
        }
        Forward::DroppedFull => {
            // The bridge main loop is not draining (e.g. a wedged offer
            // handler). Dropping is deliberate: the browser retries
            // offers/candidates, whereas blocking here would starve the
            // MQTT keepalive and get us kicked off the broker silently.
            MQTT_SIGNALS_DROPPED_TOTAL.inc();
            warn!(topic = %topic, "signal channel full — dropping inbound message");
            true
        }
        Forward::ReceiverClosed => false,
    }
}

/// Outcome of routing one inbound publish towards the signal channel.
#[derive(Debug)]
enum Forward {
    Sent,
    WrongTopic,
    Invalid(serde_json::Error),
    DroppedFull,
    ReceiverClosed,
}

/// Pure decision core of [`handle_publish`]: topic filter → JSON parse →
/// non-blocking forward. MUST stay non-blocking (no `.await`): it runs on
/// the MQTT event-loop task where blocking starves the keepalive.
fn forward_signal(
    sig_tx: &mpsc::Sender<SignalRequest>,
    expected_topic: &str,
    topic: &str,
    payload: &[u8],
) -> Forward {
    if topic != expected_topic {
        return Forward::WrongTopic;
    }
    let req = match serde_json::from_slice::<SignalRequest>(payload) {
        Ok(req) => req,
        Err(e) => return Forward::Invalid(e),
    };
    match sig_tx.try_send(req) {
        Ok(()) => Forward::Sent,
        Err(mpsc::error::TrySendError::Full(_)) => Forward::DroppedFull,
        Err(mpsc::error::TrySendError::Closed(_)) => Forward::ReceiverClosed,
    }
}

/// Translate `broker_url` + credentials into rumqttc options. Split out of
/// [`start_session`] for clarity; behaviour (including the rumqttc ws-URL
/// quirk) is unchanged from the original implementation.
fn build_mqtt_options(creds: &MqttCredentials, client_id: &str) -> Result<MqttOptions> {
    let url = url::Url::parse(&creds.broker_url).context("parse MQTT_URL")?;
    let scheme = url.scheme().to_lowercase();
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("MQTT_URL missing host"))?
        .to_string();
    let port = url.port().unwrap_or(match scheme.as_str() {
        "mqtt" => 1883,
        "mqtts" => 8883,
        "ws" => 80,
        "wss" => 443,
        _ => return Err(anyhow!("unsupported MQTT scheme {scheme}")),
    });

    // rumqttc quirk: for TCP/TLS transports `MqttOptions::new(id, host, port)`
    // wants a bare hostname; for Ws/Wss it instead treats `broker_addr` as a
    // full URL and feeds it directly into `tungstenite::client::IntoClientRequest`
    // via `split_url` (see rumqttc src/eventloop.rs). Passing just the host
    // there produces `Invalid Url: Couldn't parse host from url.` every poll.
    let broker_addr = match scheme.as_str() {
        "ws" | "wss" => {
            let path = url.path();
            let path = if path.is_empty() || path == "/" {
                "/mqtt"
            } else {
                path
            };
            format!("{scheme}://{host}:{port}{path}")
        }
        _ => host,
    };

    let mut opts = MqttOptions::new(client_id, broker_addr, port);
    opts.set_credentials(creds.username.clone(), creds.token.clone());
    opts.set_keep_alive(KEEP_ALIVE);
    opts.set_clean_session(true);
    opts.set_max_packet_size(1024 * 1024, 1024 * 1024);

    match scheme.as_str() {
        "mqtts" => {
            opts.set_transport(Transport::tls_with_default_config());
        }
        "wss" => {
            opts.set_transport(Transport::wss_with_default_config());
        }
        "ws" => {
            opts.set_transport(Transport::Ws);
        }
        "mqtt" => {
            opts.set_transport(Transport::Tcp);
        }
        _ => unreachable!(),
    }
    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_payload_with_viewer_id_parses() {
        let raw =
            r#"{"type":"close","reason":"client disconnect","viewerId":"abc-123"}"#;
        let req: SignalRequest = serde_json::from_str(raw).expect("parse close");
        match req {
            SignalRequest::Close { reason, viewer_id } => {
                assert_eq!(reason, "client disconnect");
                assert_eq!(viewer_id, "abc-123");
            }
            other => panic!("expected Close, got {other:?}"),
        }
    }

    #[test]
    fn close_payload_without_viewer_id_defaults_empty() {
        // Legacy viewers predate the viewerId field — must still parse
        // cleanly and default to empty string so the bridge keeps the
        // "arm grace against current session owner" fallback path.
        let raw = r#"{"type":"close","reason":"bye"}"#;
        let req: SignalRequest = serde_json::from_str(raw).expect("parse legacy close");
        match req {
            SignalRequest::Close { reason, viewer_id } => {
                assert_eq!(reason, "bye");
                assert_eq!(viewer_id, "");
            }
            other => panic!("expected Close, got {other:?}"),
        }
    }

    #[test]
    fn close_payload_with_stale_viewer_id_preserves_field() {
        // This is the race where viewer A closes a stale tab after
        // viewer B has already taken over the session. The bridge's
        // owner check must see the mismatched id verbatim.
        let raw =
            r#"{"type":"close","reason":"unmount","viewerId":"stale-viewer-A"}"#;
        let req: SignalRequest = serde_json::from_str(raw).expect("parse stale close");
        match req {
            SignalRequest::Close { viewer_id, .. } => {
                assert_eq!(viewer_id, "stale-viewer-A");
            }
            other => panic!("expected Close, got {other:?}"),
        }
    }

    const TOPIC: &str = "devices/redroid-inst-test/signaling/request";

    fn offer_payload() -> Vec<u8> {
        br#"{"type":"offer","sdp":"v=0","viewerId":"v1"}"#.to_vec()
    }

    #[test]
    fn forward_signal_sends_matching_topic() {
        let (tx, mut rx) = mpsc::channel::<SignalRequest>(4);
        let out = forward_signal(&tx, TOPIC, TOPIC, &offer_payload());
        assert!(matches!(out, Forward::Sent), "got {out:?}");
        match rx.try_recv().expect("message forwarded") {
            SignalRequest::Offer { viewer_id, .. } => assert_eq!(viewer_id, "v1"),
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    #[test]
    fn forward_signal_ignores_other_topics() {
        let (tx, mut rx) = mpsc::channel::<SignalRequest>(4);
        let out = forward_signal(
            &tx,
            TOPIC,
            "devices/redroid-inst-test/telemetry",
            &offer_payload(),
        );
        assert!(matches!(out, Forward::WrongTopic), "got {out:?}");
        assert!(rx.try_recv().is_err(), "nothing must be forwarded");
    }

    #[test]
    fn forward_signal_reports_invalid_json() {
        let (tx, _rx) = mpsc::channel::<SignalRequest>(4);
        let out = forward_signal(&tx, TOPIC, TOPIC, b"{not json");
        assert!(matches!(out, Forward::Invalid(_)), "got {out:?}");
    }

    /// The core self-healing invariant: a full downstream channel must
    /// surface as a DROP decision, never a block — blocking the MQTT
    /// event loop starves the keepalive and gets the client kicked off
    /// the broker without any local error (observed in production).
    #[test]
    fn forward_signal_drops_on_backpressure_instead_of_blocking() {
        let (tx, _rx) = mpsc::channel::<SignalRequest>(1);
        assert!(matches!(
            forward_signal(&tx, TOPIC, TOPIC, &offer_payload()),
            Forward::Sent
        ));
        // Channel now full; a second inbound message must be dropped.
        assert!(matches!(
            forward_signal(&tx, TOPIC, TOPIC, &offer_payload()),
            Forward::DroppedFull
        ));
    }

    #[test]
    fn forward_signal_detects_closed_receiver() {
        let (tx, rx) = mpsc::channel::<SignalRequest>(1);
        drop(rx);
        assert!(matches!(
            forward_signal(&tx, TOPIC, TOPIC, &offer_payload()),
            Forward::ReceiverClosed
        ));
    }

    /// ws/wss URLs must be passed to rumqttc as full URLs (its Ws transport
    /// parses them itself), while tcp/tls variants want a bare host.
    #[test]
    fn build_mqtt_options_accepts_all_supported_schemes() {
        // The tls/wss arms resolve rustls' process-level CryptoProvider at
        // construction. main.rs installs it before any TLS path in
        // production; tests must do the same (idempotent, ignore result).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        for (input, should_work) in [
            ("wss://mqtt-staging.beeos.ai/mqtt", true),
            ("ws://localhost:8093/mqtt", true),
            ("mqtt://localhost:1883", true),
            ("mqtts://broker:8883", true),
            ("http://not-mqtt:80", false),
        ] {
            let creds = MqttCredentials {
                broker_url: input.into(),
                username: "device".into(),
                token: "jwt".into(),
            };
            let got = build_mqtt_options(&creds, "scrcpy-bridge-test");
            assert_eq!(got.is_ok(), should_work, "url: {input}");
        }
    }

    // ---------------------------------------------------------------------
    // Self-healing integration tests against an in-process mock MQTT broker.
    //
    // The mock speaks just enough MQTT 3.1.1 over loopback TCP to exercise
    // the real rumqttc client: CONNECT/CONNACK, SUBSCRIBE/SUBACK,
    // PINGREQ/PINGRESP, broker→client QoS0 PUBLISH, and hard connection
    // drops. Each accepted-and-handshaken connection is handed to the test
    // as a `BrokerConn` so the test can publish into it or kill it.
    // ---------------------------------------------------------------------

    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    enum BrokerCmd {
        Publish { topic: String, payload: Vec<u8> },
        /// Drop the TCP connection without a DISCONNECT (simulates an EMQX
        /// pod replacement / NLB reset — the production incident shape).
        Kill,
    }

    struct BrokerConn {
        cmds: mpsc::Sender<BrokerCmd>,
        /// Topics the client subscribed to on THIS connection (one message
        /// per SUBSCRIBE as it is acked).
        subs: mpsc::Receiver<String>,
    }

    impl BrokerConn {
        async fn publish(&self, topic: &str, payload: &[u8]) {
            self.cmds
                .send(BrokerCmd::Publish {
                    topic: topic.to_string(),
                    payload: payload.to_vec(),
                })
                .await
                .expect("broker conn gone");
        }

        async fn await_subscription(&mut self, expect_topic: &str) {
            let got = tokio::time::timeout(Duration::from_secs(10), self.subs.recv())
                .await
                .expect("timed out waiting for SUBSCRIBE")
                .expect("broker conn closed before SUBSCRIBE");
            assert_eq!(got, expect_topic, "client subscribed to unexpected topic");
        }
    }

    /// Read one MQTT packet: fixed-header byte + varint remaining length +
    /// body. Returns (first_byte, body).
    async fn read_packet(stream: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
        let mut b0 = [0u8; 1];
        stream.read_exact(&mut b0).await?;
        let mut mult: usize = 1;
        let mut len: usize = 0;
        loop {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await?;
            len += (b[0] & 0x7F) as usize * mult;
            if b[0] & 0x80 == 0 {
                break;
            }
            mult *= 128;
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        Ok((b0[0], body))
    }

    fn encode_remaining_len(mut n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (n % 128) as u8;
            n /= 128;
            if n > 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if n == 0 {
                return out;
            }
        }
    }

    /// Start a mock broker. Every connection that completes the CONNECT
    /// handshake (answered with `connack_code`) is surfaced on the returned
    /// receiver. `connack_code = 0` accepts; `5` = NotAuthorized.
    async fn spawn_mock_broker(connack_code: u8) -> (SocketAddr, mpsc::Receiver<BrokerConn>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock broker");
        let addr = listener.local_addr().unwrap();
        let (conn_tx, conn_rx) = mpsc::channel::<BrokerConn>(8);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let conn_tx = conn_tx.clone();
                tokio::spawn(async move {
                    // CONNECT → CONNACK(code).
                    let Ok((b0, _)) = read_packet(&mut stream).await else {
                        return;
                    };
                    if b0 >> 4 != 1 {
                        return; // not a CONNECT — protocol violation, drop
                    }
                    if stream
                        .write_all(&[0x20, 0x02, 0x00, connack_code])
                        .await
                        .is_err()
                        || connack_code != 0
                    {
                        return; // rejected connections end here
                    }

                    let (cmd_tx, mut cmd_rx) = mpsc::channel::<BrokerCmd>(8);
                    let (subs_tx, subs_rx) = mpsc::channel::<String>(8);
                    if conn_tx
                        .send(BrokerConn {
                            cmds: cmd_tx,
                            subs: subs_rx,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }

                    loop {
                        tokio::select! {
                            pkt = read_packet(&mut stream) => {
                                let Ok((b0, body)) = pkt else { return }; // EOF/reset
                                match b0 >> 4 {
                                    8 => {
                                        // SUBSCRIBE: [pid_hi, pid_lo, tlen_hi,
                                        // tlen_lo, topic..., qos]
                                        let tlen =
                                            u16::from_be_bytes([body[2], body[3]]) as usize;
                                        let topic = String::from_utf8_lossy(&body[4..4 + tlen])
                                            .to_string();
                                        // SUBACK granting QoS1.
                                        if stream
                                            .write_all(&[0x90, 0x03, body[0], body[1], 0x01])
                                            .await
                                            .is_err()
                                        {
                                            return;
                                        }
                                        let _ = subs_tx.send(topic).await;
                                    }
                                    12 => {
                                        // PINGREQ → PINGRESP
                                        if stream.write_all(&[0xD0, 0x00]).await.is_err() {
                                            return;
                                        }
                                    }
                                    14 => return, // DISCONNECT
                                    _ => {}       // client PUBLISH etc. — ignore
                                }
                            }
                            cmd = cmd_rx.recv() => {
                                match cmd {
                                    None | Some(BrokerCmd::Kill) => return, // drop TCP
                                    Some(BrokerCmd::Publish { topic, payload }) => {
                                        // QoS0 PUBLISH.
                                        let mut var = Vec::new();
                                        var.extend_from_slice(
                                            &(topic.len() as u16).to_be_bytes(),
                                        );
                                        var.extend_from_slice(topic.as_bytes());
                                        var.extend_from_slice(&payload);
                                        let mut pkt = vec![0x30];
                                        pkt.extend(encode_remaining_len(var.len()));
                                        pkt.extend(var);
                                        if stream.write_all(&pkt).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });
        (addr, conn_rx)
    }

    fn test_config(addr: SocketAddr, prefix: &str) -> MqttSignalingConfig {
        MqttSignalingConfig {
            broker_url: format!("mqtt://{addr}"),
            username: "device".into(),
            token: "jwt-initial".into(),
            topic_prefix: prefix.into(),
            client_id: format!("scrcpy-bridge-{prefix}"),
            connected_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn recv_offer(rx: &mut mpsc::Receiver<SignalRequest>) -> String {
        let req = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("timed out waiting for signal")
            .expect("signal channel closed");
        match req {
            SignalRequest::Offer { viewer_id, .. } => viewer_id,
            other => panic!("expected Offer, got {other:?}"),
        }
    }

    /// Happy path: `connect` returns only after the broker acked the
    /// subscription, the health flag is truthful, and publishes flow.
    #[tokio::test]
    async fn connect_is_truthful_and_delivers_signals() {
        let (addr, mut conns) = spawn_mock_broker(0).await;
        let cfg = test_config(addr, "devices/it-happy");
        let flag = cfg.connected_flag.clone();

        let (_mqtt, mut sig_rx) = MqttSignaling::connect(cfg).await.expect("connect");
        assert!(flag.load(Ordering::Relaxed), "flag must be raised on ack'd connect");

        let mut conn = conns.recv().await.expect("broker saw no connection");
        // SUBACK was already required for connect() to return; the sub
        // notification is buffered on the conn.
        conn.await_subscription("devices/it-happy/signaling/request").await;

        conn.publish(
            "devices/it-happy/signaling/request",
            br#"{"type":"offer","sdp":"v=0","viewerId":"happy-1"}"#,
        )
        .await;
        assert_eq!(recv_offer(&mut sig_rx).await, "happy-1");
    }

    /// Invariant 3: after the broker hard-drops the connection (EMQX pod
    /// replacement), the client auto-reconnects AND re-subscribes — the
    /// production incident was a "recovered" connection with no
    /// subscription, silently receiving nothing.
    #[tokio::test]
    async fn auto_reconnect_resubscribes_and_recovers_delivery() {
        let (addr, mut conns) = spawn_mock_broker(0).await;
        let cfg = test_config(addr, "devices/it-resub");

        let (_mqtt, mut sig_rx) = MqttSignaling::connect(cfg).await.expect("connect");
        let conn1 = conns.recv().await.expect("first connection");

        // Simulate broker death: hard TCP drop, no DISCONNECT.
        conn1.cmds.send(BrokerCmd::Kill).await.expect("kill conn1");

        // rumqttc must reconnect and our task must re-subscribe.
        let mut conn2 = tokio::time::timeout(Duration::from_secs(10), conns.recv())
            .await
            .expect("client never reconnected")
            .expect("broker closed");
        conn2.await_subscription("devices/it-resub/signaling/request").await;

        // Delivery works on the NEW connection.
        conn2
            .publish(
                "devices/it-resub/signaling/request",
                br#"{"type":"offer","sdp":"v=0","viewerId":"resub-1"}"#,
            )
            .await;
        assert_eq!(recv_offer(&mut sig_rx).await, "resub-1");
    }

    /// Credential rotation rebuilds the session (old torn down, new
    /// subscribed) while the external signal receiver keeps working.
    #[tokio::test]
    async fn credential_rotation_swaps_sessions_and_keeps_receiver() {
        let (addr, mut conns) = spawn_mock_broker(0).await;
        let cfg = test_config(addr, "devices/it-rotate");
        let flag = cfg.connected_flag.clone();

        let (mqtt, mut sig_rx) = MqttSignaling::connect(cfg).await.expect("connect");
        let conn1 = conns.recv().await.expect("first connection");

        mqtt.reconnect(MqttCredentials {
            broker_url: format!("mqtt://{addr}"),
            username: "device".into(),
            token: "jwt-rotated".into(),
        })
        .await
        .expect("rotation must succeed against a live broker");
        assert!(flag.load(Ordering::Relaxed));

        let mut conn2 = tokio::time::timeout(Duration::from_secs(10), conns.recv())
            .await
            .expect("no post-rotation connection")
            .expect("broker closed");
        conn2.await_subscription("devices/it-rotate/signaling/request").await;

        // Old session was torn down (teardown drops its socket): the mock's
        // conn task exits on EOF, closing its command channel.
        tokio::time::timeout(Duration::from_secs(5), conn1.cmds.closed())
            .await
            .expect("old connection must be torn down after rotation");

        conn2
            .publish(
                "devices/it-rotate/signaling/request",
                br#"{"type":"offer","sdp":"v=0","viewerId":"rot-1"}"#,
            )
            .await;
        assert_eq!(recv_offer(&mut sig_rx).await, "rot-1");
    }

    /// Invariant 2: a broker that refuses the connection (NotAuthorized —
    /// the expired-JWT case) must surface as a fast `Err`, never as a
    /// "connected" session that silently receives nothing.
    #[tokio::test]
    async fn rejected_connack_fails_fast_with_flag_down() {
        let (addr, _conns) = spawn_mock_broker(5).await; // 5 = NotAuthorized
        let cfg = test_config(addr, "devices/it-reject");
        let flag = cfg.connected_flag.clone();

        let err = match MqttSignaling::connect(cfg).await {
            Ok(_) => panic!("refused ConnAck must fail connect"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refused") || msg.contains("NotAuthorized"),
            "error should surface the refusal: {msg}"
        );
        assert!(!flag.load(Ordering::Relaxed), "flag must stay down");
    }
}
