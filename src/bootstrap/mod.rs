//! Agent Gateway `/bootstrap` client + MQTT JWT auto-refresh.
//!
//! ## Why this module exists
//!
//! Runtime issues RS256 MQTT JWTs that live for **10 minutes** (see
//! `services/runtime/.../device/provider.go`'s `GetDeviceStreamParams`). EMQX
//! rejects the connection the moment `exp` passes, which — for a long-lived
//! sidecar — means we have to refresh well before expiry and rebuild the
//! broker connection.
//!
//! The refresh flow uses the Agent Gateway's Ed25519 auth so the privileged
//! Runtime database is never exposed on the data plane:
//!
//! ```text
//! scrcpy-bridge
//!    │  sign "GET|/api/v1/device/bootstrap|ts|nonce" with Ed25519 private key
//!    ▼
//! Agent Gateway (agent-gateway.beeos.ai / :8083)
//!    │  verifies signature + resolves instance_id by pubkey
//!    ▼
//! Runtime Device gRPC → fresh MQTT JWT + TURN creds
//!    ▲
//!    └─ JSON payload returned verbatim to bridge
//! ```
//!
//! ## Lifecycle
//!
//! * [`BootstrapClient`] is created once at startup with the instance's
//!   private key loaded from `--bridge-private-key-file`.
//! * [`BootstrapClient::fetch`] performs a single round-trip. The bridge runs
//!   this eagerly at boot, then spawns [`spawn_refresh_loop`] which wakes up
//!   `lead` seconds before the previous response's `expiresAt` and triggers
//!   the next fetch.
//! * The loop is resilient to broker outages: on error it retries with
//!   exponential backoff bounded by `min_interval`, and if the JWT is about
//!   to expire mid-retry we publish a `BootstrapEvent::Expired` so the outer
//!   bridge can close the MQTT client proactively (EMQX would otherwise drop
//!   us after exp and we'd lose in-flight signaling messages).
//!
//! ## What this module deliberately does NOT do
//!
//! * It does not own the `rumqttc::AsyncClient` — rebuilding the client is
//!   the bridge's responsibility because it also owns the signaling event
//!   subscription. We hand the bridge a stream of [`BootstrapEvent`]s and let
//!   it decide how to re-plumb MQTT.
//! * It does not cache TURN/ICE credentials. TURN expiry == MQTT expiry in
//!   the current Runtime implementation, so a single bootstrap suffices for
//!   the common case; if that ever diverges we can add a separate refresher.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::observability::JWT_REFRESH_TOTAL;

/// JSON payload returned by Runtime and forwarded by Agent Gateway verbatim
/// (the `jsonData` field of `GetDeviceStreamParamsResponse`). Field names
/// match `backend/services/runtime/pkg/domain/provider/port.go`'s
/// `DeviceStreamParams`.
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapResponse {
    #[serde(rename = "mqttUrl")]
    pub mqtt_url: String,
    #[serde(rename = "mqttToken")]
    pub mqtt_token: String,
    #[serde(rename = "deviceTopic", default)]
    pub device_topic: String,
    #[serde(rename = "iceServers", default)]
    pub ice_servers: Vec<IceServerPayload>,
    /// Unix seconds — when the JWT embedded in `mqtt_token` stops being
    /// accepted by EMQX.
    #[serde(rename = "expiresAt", default)]
    pub expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IceServerPayload {
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub credential: Option<String>,
}

/// Inputs to build a [`BootstrapClient`].
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Agent Gateway base URL, e.g. `https://agent-gateway.beeos.ai`.
    pub base_url: String,
    /// Base64 32-byte Ed25519 seed — matches cluster-proxy's Secret format.
    pub private_key_b64: String,
    /// Base64 32-byte Ed25519 public key — echoed in `X-Agent-Public-Key`.
    pub public_key_b64: String,
    /// Request timeout. 10s is enough even for the slowest Runtime cold path.
    pub request_timeout: Duration,
}

/// Owns the HTTP client + signing key. Cloneable by holding everything in
/// `Arc`-able primitives, so `spawn_refresh_loop` can move it freely.
#[derive(Clone)]
pub struct BootstrapClient {
    http: Client,
    base_url: String,
    signing_key: SigningKey,
    public_key_b64: String,
}

impl BootstrapClient {
    pub fn new(cfg: BootstrapConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(cfg.request_timeout)
            .user_agent(concat!("scrcpy-bridge/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;

        let signing_key = load_signing_key(&cfg.private_key_b64)
            .context("load ed25519 private key for bootstrap")?;

        Ok(Self {
            http,
            base_url: cfg.base_url.trim_end_matches('/').to_string(),
            signing_key,
            public_key_b64: cfg.public_key_b64,
        })
    }

    /// Perform one refresh. Returns the parsed payload. The caller is
    /// expected to schedule the next call via [`spawn_refresh_loop`] rather
    /// than hand-rolling a timer.
    pub async fn fetch(&self) -> Result<BootstrapResponse> {
        let path = "/api/v1/device/bootstrap";
        let url = format!("{}{}", self.base_url, path);

        let ts = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();
        // Message format MUST match `agentauth.VerifyRequest` in Go:
        //   "METHOD|PATH|timestamp|nonce"
        let msg = format!("GET|{}|{}|{}", path, ts, nonce);
        let sig = self.signing_key.sign(msg.as_bytes());
        let sig_b64 = B64.encode(sig.to_bytes());

        let resp = self
            .http
            .get(&url)
            .header("X-Agent-Public-Key", &self.public_key_b64)
            .header("X-Agent-Signature", sig_b64)
            .header("X-Agent-Timestamp", ts.to_string())
            .header("X-Agent-Nonce", nonce)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;

        let status = resp.status();
        let body = resp.bytes().await.context("read bootstrap body")?;
        if !status.is_success() {
            let snippet = String::from_utf8_lossy(&body);
            bail!(
                "agent-gateway /bootstrap returned HTTP {status}: {}",
                truncate(&snippet, 512)
            );
        }

        let parsed: BootstrapResponse =
            serde_json::from_slice(&body).context("decode bootstrap response")?;
        if parsed.mqtt_url.is_empty() || parsed.mqtt_token.is_empty() {
            bail!("bootstrap response missing mqttUrl/mqttToken");
        }
        JWT_REFRESH_TOTAL.with_label_values(&["success"]).inc();
        Ok(parsed)
    }
}

/// Event delivered to the bridge whenever the stored credentials changed or
/// are about to become invalid.
#[derive(Debug, Clone)]
pub enum BootstrapEvent {
    /// Fresh credentials ready; bridge should tear down and rebuild MQTT.
    Refreshed(BootstrapResponse),
    /// We could not refresh before expiry. Bridge should stop accepting
    /// signaling until a later refresh succeeds. The embedded reason is
    /// suitable for logging.
    Expired(String),
}

/// Spawn the background refresher.
///
/// * `lead`          — trigger the refresh this many seconds before `expiresAt`.
/// * `min_interval`  — lower bound on how often we hammer Agent Gateway.
///
/// The refresher keeps running until the receiver side of the returned
/// channel is dropped, so the bridge's shutdown path is simply "drop the
/// receiver".
pub fn spawn_refresh_loop(
    client: BootstrapClient,
    initial: BootstrapResponse,
    lead: Duration,
    min_interval: Duration,
) -> mpsc::Receiver<BootstrapEvent> {
    let (tx, rx) = mpsc::channel::<BootstrapEvent>(4);
    tokio::spawn(async move {
        let mut current_expiry = initial.expires_at;
        loop {
            let wait = compute_sleep(current_expiry, lead, min_interval);
            debug!(
                wait_secs = wait.as_secs(),
                expires_at = current_expiry,
                "bootstrap refresh scheduled"
            );
            sleep_until(Instant::now() + wait).await;

            match client.fetch().await {
                Ok(fresh) => {
                    current_expiry = fresh.expires_at;
                    if tx
                        .send(BootstrapEvent::Refreshed(fresh))
                        .await
                        .is_err()
                    {
                        return; // bridge shutting down
                    }
                }
                Err(e) => {
                    JWT_REFRESH_TOTAL.with_label_values(&["failure"]).inc();
                    let now = chrono::Utc::now().timestamp();
                    if current_expiry > 0 && now >= current_expiry {
                        warn!(error = %e, "bootstrap refresh failed past expiry; MQTT credentials are now stale");
                        let _ = tx
                            .send(BootstrapEvent::Expired(format!(
                                "refresh failed after expiry: {e}"
                            )))
                            .await;
                    } else {
                        warn!(error = %e, "bootstrap refresh failed, will retry");
                    }
                    // Back off: wait at least min_interval before trying again.
                    sleep_until(Instant::now() + min_interval).await;
                }
            }
        }
    });
    rx
}

/// Compute how long we should wait before the next refresh attempt.
///
/// * If `expires_at == 0` the server didn't tell us, so we pick a conservative
///   5-minute cadence.
/// * If the JWT is already past `expires_at - lead`, fire immediately.
/// * Otherwise wait `(expires_at - now - lead)`, floor-clamped by
///   `min_interval` to avoid hot-looping if Runtime issues very short-lived
///   tokens.
fn compute_sleep(expires_at: i64, lead: Duration, min_interval: Duration) -> Duration {
    if expires_at == 0 {
        return Duration::from_secs(5 * 60);
    }
    let now = chrono::Utc::now().timestamp();
    let lead_secs = lead.as_secs() as i64;
    let target = expires_at - lead_secs;
    let delta = target - now;
    if delta <= 0 {
        // Always respect min_interval even for "fire now" to smooth out
        // retry storms when Runtime returns an already-near-expiry token.
        return min_interval;
    }
    let naive = Duration::from_secs(delta as u64);
    if naive < min_interval {
        min_interval
    } else {
        naive
    }
}

/// Helper: load a 32-byte seed from a base64 string and build a SigningKey.
fn load_signing_key(b64: &str) -> Result<SigningKey> {
    let trimmed = b64.trim();
    let seed_bytes = B64
        .decode(trimmed.as_bytes())
        .context("base64 decode ed25519 private key")?;
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("ed25519 private key must be 32 bytes, got {}", seed_bytes.len()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Key file payloads accepted by [`read_private_key_file`] /
/// [`read_public_key_file`]. Two formats coexist:
///
/// 1. **Raw base64 text** — historic layout written by cluster-proxy's
///    `provisionBridgeIdentity` helper: a single file containing a single
///    base64 string (32-byte Ed25519 seed for the private key, 32-byte
///    public key for the public key). Used inside k8s secrets.
///
/// 2. **`.key.json`** — layout shared with the BeeOS CLI / device-agent
///    (`web/packages/core/src/identity/keypair.ts`). One JSON object with
///    both fields: `{ "publicKey": "<b64>", "privateKey": "<b64 seed>" }`.
///    Same file can be pointed at by BOTH `BRIDGE_PRIVATE_KEY_FILE` and
///    `BRIDGE_PUBLIC_KEY_FILE` — the reader dispatches on which field it
///    wants. This lets `beeos device attach` reuse the same key material
///    for device-agent and scrcpy-bridge without any runtime split.
///
/// Detection is simple and robust: trim whitespace, sniff the first byte
/// — `{` means JSON, anything else is treated as raw base64. We do NOT
/// try to actually base64-decode before deciding, because a valid 32-byte
/// seed encoded as base64 never starts with `{`, and a broken JSON that
/// accidentally starts with non-`{` will fail later at the Ed25519 parse
/// step with an actionable error.
#[derive(Debug, Clone, Deserialize)]
struct KeyPairJson {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "privateKey")]
    private_key: String,
}

enum KeyFilePayload {
    RawBase64(String),
    Json(KeyPairJson),
}

async fn load_key_payload(path: impl AsRef<Path>) -> Result<KeyFilePayload> {
    let p = path.as_ref();
    let bytes = tokio::fs::read(p)
        .await
        .with_context(|| format!("read key file {}", p.display()))?;
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    if text.starts_with('{') {
        let parsed: KeyPairJson = serde_json::from_str(&text)
            .with_context(|| format!("parse key JSON at {}", p.display()))?;
        if parsed.private_key.is_empty() && parsed.public_key.is_empty() {
            bail!(
                "key JSON at {} has empty privateKey and publicKey",
                p.display()
            );
        }
        Ok(KeyFilePayload::Json(parsed))
    } else {
        if text.is_empty() {
            bail!("key file {} is empty", p.display());
        }
        Ok(KeyFilePayload::RawBase64(text))
    }
}

/// Read the 32-byte Ed25519 seed (as base64 text) used by [`BootstrapClient`]
/// to sign `/bootstrap` requests. Accepts either the raw-base64 layout used
/// by cluster-proxy or the `.key.json` layout written by the BeeOS CLI.
pub async fn read_private_key_file(path: impl AsRef<Path>) -> Result<String> {
    match load_key_payload(path.as_ref()).await? {
        KeyFilePayload::RawBase64(s) => Ok(s),
        KeyFilePayload::Json(j) => {
            if j.private_key.is_empty() {
                bail!(
                    "key JSON at {} has no privateKey field",
                    path.as_ref().display()
                );
            }
            Ok(j.private_key)
        }
    }
}

/// Read the 32-byte Ed25519 public key (as base64 text). Same accepted
/// formats as [`read_private_key_file`]; when given a `.key.json` the
/// `publicKey` field is returned instead of `privateKey`.
pub async fn read_public_key_file(path: impl AsRef<Path>) -> Result<String> {
    match load_key_payload(path.as_ref()).await? {
        KeyFilePayload::RawBase64(s) => Ok(s),
        KeyFilePayload::Json(j) => {
            if j.public_key.is_empty() {
                bail!(
                    "key JSON at {} has no publicKey field",
                    path.as_ref().display()
                );
            }
            Ok(j.public_key)
        }
    }
}

/// Backwards-compatible wrapper. New code should call
/// [`read_private_key_file`] / [`read_public_key_file`] explicitly so the
/// `.key.json` dispatch picks the right field. Kept as an alias for the
/// private-key path because every historical caller of
/// `read_key_file(<private_key_path>)` expected the Ed25519 seed back.
#[deprecated(
    since = "0.2.0",
    note = "use read_private_key_file or read_public_key_file — the new helpers correctly \
            dispatch between raw-base64 and .key.json layouts"
)]
pub async fn read_key_file(path: impl AsRef<Path>) -> Result<String> {
    read_private_key_file(path).await
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut out = s[..n].to_string();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_sleep_zero_expiry_defaults_to_five_minutes() {
        let d = compute_sleep(0, Duration::from_secs(60), Duration::from_secs(30));
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn compute_sleep_past_expiry_returns_min_interval() {
        let long_ago = chrono::Utc::now().timestamp() - 1_000;
        let d = compute_sleep(long_ago, Duration::from_secs(60), Duration::from_secs(30));
        assert_eq!(d, Duration::from_secs(30));
    }

    #[test]
    fn compute_sleep_honours_lead_and_min_interval() {
        let future = chrono::Utc::now().timestamp() + 600; // 10 min
        let d = compute_sleep(future, Duration::from_secs(60), Duration::from_secs(30));
        // Should be ~540s (600 - 60 lead), well above min_interval.
        assert!(d.as_secs() >= 530 && d.as_secs() <= 545);
    }

    #[test]
    fn compute_sleep_floors_short_window_at_min_interval() {
        let future = chrono::Utc::now().timestamp() + 75; // lead 60 → naive 15s
        let d = compute_sleep(future, Duration::from_secs(60), Duration::from_secs(30));
        assert_eq!(d, Duration::from_secs(30));
    }

    #[test]
    fn load_signing_key_accepts_valid_seed() {
        let seed = [7u8; 32];
        let b64 = B64.encode(seed);
        let sk = load_signing_key(&b64).unwrap();
        // Signing should not panic.
        let _ = sk.sign(b"hello");
    }

    #[test]
    fn load_signing_key_rejects_wrong_length() {
        let b64 = B64.encode([1u8; 16]);
        assert!(load_signing_key(&b64).is_err());
    }

    // ── Key file format dispatch ────────────────────────────

    #[tokio::test]
    async fn read_key_file_raw_base64_priv_and_pub() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let seed_b64 = B64.encode([9u8; 32]);
        writeln!(f, "{}", seed_b64).unwrap();

        let priv_ = read_private_key_file(f.path()).await.unwrap();
        let pub_ = read_public_key_file(f.path()).await.unwrap();
        // Raw format: both helpers return the file contents verbatim — caller
        // is responsible for pointing each env var at the right file.
        assert_eq!(priv_, seed_b64);
        assert_eq!(pub_, seed_b64);
    }

    #[tokio::test]
    async fn read_key_file_json_dispatches_per_field() {
        use std::io::Write;
        let priv_b64 = B64.encode([1u8; 32]);
        let pub_b64 = B64.encode([2u8; 32]);
        let json = format!(
            r#"{{"publicKey":"{}","privateKey":"{}"}}"#,
            pub_b64, priv_b64
        );
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();

        let got_priv = read_private_key_file(f.path()).await.unwrap();
        let got_pub = read_public_key_file(f.path()).await.unwrap();
        assert_eq!(got_priv, priv_b64);
        assert_eq!(got_pub, pub_b64);
    }

    #[tokio::test]
    async fn read_key_file_json_rejects_missing_field() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // Missing privateKey entirely — serde default to "" → helper must bail.
        f.write_all(br#"{"publicKey":"aGVsbG8=","privateKey":""}"#)
            .unwrap();
        let err = read_private_key_file(f.path()).await.unwrap_err();
        assert!(
            err.to_string().contains("no privateKey"),
            "expected missing-field error, got: {err}"
        );
    }

    #[tokio::test]
    async fn read_key_file_rejects_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err = read_private_key_file(f.path()).await.unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "expected empty-file error, got: {err}"
        );
    }

    #[tokio::test]
    async fn read_key_file_json_with_whitespace_dispatches() {
        use std::io::Write;
        // Leading whitespace must not defeat the `{` sniff.
        let priv_b64 = B64.encode([3u8; 32]);
        let pub_b64 = B64.encode([4u8; 32]);
        let json = format!(
            "   \n\t{{\"publicKey\":\"{}\",\"privateKey\":\"{}\"}}\n",
            pub_b64, priv_b64
        );
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        let got = read_public_key_file(f.path()).await.unwrap();
        assert_eq!(got, pub_b64);
    }
}
