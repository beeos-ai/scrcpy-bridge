//! Runtime configuration parsed from CLI + environment.

use clap::Parser;

/// scrcpy-bridge CLI.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "scrcpy-bridge",
    about = "Bridge scrcpy Android screen-mirror to WebRTC via MQTT signaling",
    version
)]
pub struct Cli {
    /// Device id. Used only for (a) the MQTT client id suffix
    /// (`scrcpy-bridge-<device_id>`) and (b) log tagging.
    ///
    /// MQTT topics themselves are built from the `deviceTopic` field of
    /// the Agent Gateway bootstrap response (e.g.
    /// `devices/device-<instanceUUID>`), NOT from this value — that
    /// topic prefix is what EMQX's JWT ACL is scoped to, and the two
    /// are not interchangeable.
    #[arg(long, env = "DEVICE_ID")]
    pub device_id: String,

    /// ADB device serial (e.g. `R5CT1234`, `emulator-5554`, `127.0.0.1:5555`).
    /// In ReDroid sidecar deployments this is `127.0.0.1:5555`.
    #[arg(long, env = "ADB_SERIAL")]
    pub adb_serial: String,

    /// ADB server host.
    #[arg(long, env = "ADB_HOST", default_value = "127.0.0.1")]
    pub adb_host: String,

    /// ADB server port.
    #[arg(long, env = "ADB_PORT", default_value_t = 5037)]
    pub adb_port: u16,

    // ───────────────────── MQTT credentials ─────────────────────
    //
    // There is no `--mqtt-url` / `--mqtt-token` flag. scrcpy-bridge
    // authenticates to EMQX exclusively through credentials fetched from
    // Agent Gateway's `/api/v1/device/bootstrap` endpoint (see the fields
    // below). Runtime issues short-lived (~10 min) RS256 JWTs and this
    // process refreshes them before expiry, rebuilding the rumqttc client
    // each cycle. The MQTT username is always `device` — matching EMQX's
    // JWT auth config — and is not user-configurable.

    /// Max encode FPS passed to scrcpy-server.
    #[arg(long, env = "MAX_FPS", default_value_t = 30)]
    pub max_fps: u32,

    /// Max frame width passed to scrcpy-server (auto aspect).
    #[arg(long, env = "MAX_WIDTH", default_value_t = 1920)]
    pub max_width: u32,

    /// Encode bitrate in bits/second.
    #[arg(long, env = "VIDEO_BITRATE", default_value_t = 16_000_000)]
    pub bitrate: u32,

    /// H.264 i-frame interval in seconds.
    #[arg(long, env = "I_FRAME_INTERVAL", default_value_t = 2)]
    pub i_frame_interval: u32,

    /// Disable audio (OPUS) passthrough.
    #[arg(long, env = "DISABLE_AUDIO")]
    pub disable_audio: bool,

    /// Dev-only override for ICE servers (comma-separated). Each item is
    /// a full URL like `stun:stun.l.google.com:19302` or
    /// `turn:turn.example:3478`.
    ///
    /// **Production never sets this.** Runtime owns the TURN pool and
    /// ships it through the Agent Gateway bootstrap response
    /// (`iceServers` field) where every entry carries its own short-lived
    /// `username`/`credential`. Bootstrap entries always win; values from
    /// this flag are appended *in addition* to bootstrap and are meant
    /// for local `cargo run` sessions where no Runtime TURN config is
    /// available — the default `stun:stun.l.google.com:19302` keeps
    /// host-candidate P2P working on a laptop with no TURN at all.
    #[arg(long, env = "ICE_URLS", value_delimiter = ',', default_value = "stun:stun.l.google.com:19302")]
    pub ice_urls: Vec<String>,

    /// Dev-only TURN username paired with `--ice-urls` entries. Never
    /// applied to bootstrap-provided servers (those carry their own
    /// credentials from Runtime).
    #[arg(long, env = "TURN_USERNAME")]
    pub turn_username: Option<String>,

    /// Dev-only TURN credential paired with `--ice-urls` entries. Never
    /// applied to bootstrap-provided servers.
    #[arg(long, env = "TURN_CREDENTIAL")]
    pub turn_credential: Option<String>,

    /// Port for `/metrics` + `/healthz` HTTP endpoint. 0 to disable.
    #[arg(long, env = "METRICS_PORT", default_value_t = 9091)]
    pub metrics_port: u16,

    /// Extra local IPs to advertise as ICE host candidates (comma-separated).
    ///
    /// In Kubernetes, wire this to the downward API's `status.podIP` plus any
    /// node public IP so the browser can reach the UDP socket from outside
    /// the pod network. In bare-metal farm deployments, list every non-loopback
    /// interface the device can be reached on. `str0m` only automatically
    /// emits a candidate for the OS-bound address (`0.0.0.0` after we bind),
    /// so multi-homed hosts need this hint.
    #[arg(long, env = "PUBLIC_IPS", value_delimiter = ',', default_value = "")]
    pub public_ips: Vec<String>,

    /// Milliseconds to wait for ICE gathering before emitting the SDP answer.
    ///
    /// `str0m 0.9` does not expose a `gathering-complete` event, so we sleep
    /// before replying to let any server-reflexive or TURN-relay candidates
    /// materialise. `0` keeps the legacy behaviour (answer immediately with
    /// whatever host candidates were pre-added).
    #[arg(long, env = "ICE_GATHER_WAIT_MS", default_value_t = 0)]
    pub ice_gather_wait_ms: u64,

    /// Log format: "text" or "json".
    #[arg(long, env = "LOG_FORMAT", default_value = "text")]
    pub log_format: String,

    /// Path to scrcpy-server.jar override (for local dev). Defaults to the
    /// version embedded in the binary.
    #[arg(long, env = "SCRCPY_SERVER_JAR")]
    pub scrcpy_server_jar: Option<std::path::PathBuf>,

    /// Target absolute path on device for scrcpy-server.jar.
    #[arg(long, env = "REMOTE_JAR_PATH", default_value = "/data/local/tmp/scrcpy-server.jar")]
    pub remote_jar_path: String,

    // ───────────────────── Agent Gateway bootstrap ─────────────────────
    //
    // These three fields are **required**. scrcpy-bridge refuses to start
    // without them — there is no legacy fallback path.

    /// Agent Gateway base URL (e.g. `https://agent-gateway.beeos.ai`).
    ///
    /// scrcpy-bridge calls `GET $AGENT_GATEWAY_URL/api/v1/device/bootstrap`
    /// at startup and periodically before the MQTT JWT expires, to refresh
    /// broker credentials. Authentication is Ed25519 using the private key
    /// at `--bridge-private-key-file` matching the public key bound to the
    /// instance on the control plane.
    #[arg(long, env = "AGENT_GATEWAY_URL")]
    pub agent_gateway_url: String,

    /// Path to the Ed25519 private key.
    ///
    /// Two layouts are accepted (auto-detected by the first byte after
    /// whitespace trim — see `bootstrap::read_private_key_file`):
    ///
    /// * **Raw base64 text** — a single line containing the base64-encoded
    ///   32-byte Ed25519 seed. Matches the file layout written by
    ///   cluster-proxy's `provisionBridgeIdentity` and beeos-claw's openclaw
    ///   agent identity secret.
    ///
    /// * **`.key.json`** — JSON object `{ "publicKey": "<b64>",
    ///   "privateKey": "<b64>" }`. Same layout as the BeeOS CLI /
    ///   device-agent (`~/.beeos/identity/device-<serial>.key.json`). When
    ///   this layout is used the same file can be pointed at by both
    ///   `BRIDGE_PRIVATE_KEY_FILE` and `BRIDGE_PUBLIC_KEY_FILE`; the reader
    ///   extracts the appropriate field on each call. This is how
    ///   `beeos device attach` wires scrcpy-bridge alongside device-agent
    ///   without duplicating key material.
    #[arg(long, env = "BRIDGE_PRIVATE_KEY_FILE")]
    pub bridge_private_key_file: String,

    /// Path to the matching Ed25519 public key.
    ///
    /// Accepts the same layouts as `--bridge-private-key-file`. Sent
    /// verbatim in the `X-Agent-Public-Key` header so Agent Gateway can
    /// resolve the instance without walking the key store on every
    /// request. For the `.key.json` layout this path MAY equal
    /// `--bridge-private-key-file`.
    #[arg(long, env = "BRIDGE_PUBLIC_KEY_FILE")]
    pub bridge_public_key_file: String,

    /// Wheel-to-scroll sensitivity multiplier applied to the *coalesced*
    /// browser wheel delta (one accumulated send per physical gesture —
    /// see the device-viewer `InputHandler` state machine) before it is
    /// clamped to scrcpy's scroll intensity ceiling (`±0.3`, see
    /// `datachannel::wheel_to_scroll`).
    ///
    /// The client is responsible for gesture shaping — it folds 30 ms of
    /// initial impulse into a single send — so the server no longer
    /// compensates for rapid-fire events and just treats its input as
    /// linear raw wheel delta. A 1-notch wheel click (`|dy|≈100`) at
    /// `sensitivity=1.0` produces `|sy|≈0.83` which the `±0.3` ceiling
    /// caps to `0.3` — exactly the empirically-measured "one page flip"
    /// magnitude on page-snap apps (TikTok / Douyin / Reels). Lower the
    /// sensitivity if inputs feel too aggressive; raise the cap in
    /// `wheel_to_scroll` only if target apps genuinely need higher
    /// per-event intensity.
    #[arg(long, env = "SCROLL_SENSITIVITY", default_value_t = 1.0)]
    pub scroll_sensitivity: f32,

    /// Seconds before JWT expiry to refresh. Default 60s.
    #[arg(long, env = "JWT_REFRESH_LEAD_SECS", default_value_t = 60)]
    pub jwt_refresh_lead_secs: u64,

    /// Minimum seconds between refresh attempts (rate limiter for error
    /// retries or overly aggressive expiry windows).
    #[arg(long, env = "JWT_REFRESH_MIN_INTERVAL_SECS", default_value_t = 30)]
    pub jwt_refresh_min_interval_secs: u64,
}

impl Cli {
    /// Parse CLI (and environment) into a [`Cli`] struct. Terminates on error.
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
