# scrcpy-bridge

Rust daemon that bridges an Android device's [scrcpy](https://github.com/Genymobile/scrcpy)
H.264 stream to a browser via WebRTC — with **zero decode/re-encode**. Sidecar
for the Python `device-agent`; the two processes are independent and share only
the host's ADB daemon.

## Why

The original Python `device-agent` did H.264 decode → raw frame → re-encode for
every video frame (via `aiortc` + `PyAV`), which capped throughput at ~10-15 FPS
per device and consumed ~1 full CPU core. `scrcpy-bridge` hands the H.264 NALs
straight to `str0m`'s sample API (which packetizes them into RTP) so the entire
video path is zero-copy from the device's hardware encoder to the browser's
hardware decoder.

## Architecture

```
        browser (device-viewer)
           │  WebRTC (H.264 + OPUS + DataChannel)
           ▼
    ┌───────────────────┐         ┌──────────────────┐
    │  scrcpy-bridge    │◄───MQTT─┤  EMQX broker     │
    │  (Rust, this)     │         │  (signaling only)│
    └───────┬───────────┘         └──────────────────┘
            │ ADB (host adb daemon)
            ▼
    ┌───────────────────┐
    │  Android device   │
    │  (scrcpy-server)  │
    └───────────────────┘

 device-agent (Python, sibling) ── Bridge WSS (ACP) ── user AI chat
                                   ADB (host adb daemon, shared)
```

No IPC between `scrcpy-bridge` and `device-agent`. Each can crash independently
and get restarted by the supervisor (edge-agent or Kubernetes).

## Build

```
# Normal build — build.rs downloads scrcpy-server v3.1 from GitHub into
# assets/ and sha256-verifies it.
cargo build --release

# Offline / flaky-network builds — pre-seed the jar and cargo will skip
# the network fetch on subsequent builds (build.rs verifies sha256 and
# reuses a matching jar, no env flag required):
./scripts/fetch-scrcpy-server.sh
cargo build --release

# Custom location (corporate mirror / air-gapped):
SCRCPY_SERVER_JAR=/opt/scrcpy/scrcpy-server-v3.1.jar cargo build --release
```

Docker image:

```
# Debian-based, simple local builds
docker build -t beeos-scrcpy-bridge:dev .

# Static musl binary + gcr.io/distroless/static (for production ReDroid sidecars).
# Multi-arch (linux/amd64, linux/arm64) — see .github/workflows/release.yml.
docker buildx build --platform linux/amd64,linux/arm64 \
  -f Dockerfile.distroless \
  -t ghcr.io/beeos-ai/scrcpy-bridge:dev .
```

## Distribution

Release artifacts are produced on every `scrcpy-bridge-v*` git tag by the
workflow in `.github/workflows/release.yml`:

| Target                          | Artifact                                          | Consumer                   |
|---------------------------------|---------------------------------------------------|----------------------------|
| `x86_64-unknown-linux-gnu`      | `scrcpy-bridge-x86_64-unknown-linux-gnu.tar.gz`   | Linux servers, edge-agent  |
| `aarch64-unknown-linux-gnu`     | `scrcpy-bridge-aarch64-unknown-linux-gnu.tar.gz`  | ARM64 Linux, Raspberry Pi  |
| `x86_64-unknown-linux-musl`     | `scrcpy-bridge-x86_64-unknown-linux-musl.tar.gz`  | Alpine, distroless         |
| `aarch64-unknown-linux-musl`    | `scrcpy-bridge-aarch64-unknown-linux-musl.tar.gz` | ARM64 Alpine / distroless  |
| `x86_64-apple-darwin`           | `scrcpy-bridge-x86_64-apple-darwin.tar.gz`        | macOS Intel dev            |
| `aarch64-apple-darwin`          | `scrcpy-bridge-aarch64-apple-darwin.tar.gz`       | macOS Apple Silicon dev    |
| `x86_64-pc-windows-msvc`        | `scrcpy-bridge-x86_64-pc-windows-msvc.zip`        | Windows dev                |
| `ghcr.io/beeos-ai/scrcpy-bridge:<ver>` | distroless OCI image (amd64 + arm64)       | ReDroid docker-compose / K8s sidecar |

Archives are version-less by design so the BeeOS CLI can resolve them via
`https://github.com/beeos-ai/scrcpy-bridge/releases/latest/download/<name>`
without first fetching the latest tag.

`@beeos-ai/cli` (`beeos device attach` / `beeos device upgrade`) resolves the
binary in this order:
`$BEEOS_SCRCPY_BRIDGE_BIN` → `scrcpy-bridge` on `PATH` → `~/.beeos/bin/scrcpy-bridge`.

On first attach, if no binary is found the CLI downloads the matching
`cargo-dist` archive from `https://github.com/beeos-ai/scrcpy-bridge/releases/latest`
and extracts it to `~/.beeos/bin/scrcpy-bridge[.exe]`. Mirror override:
set `BEEOS_SCRCPY_BRIDGE_RELEASE_URL` to a base URL that serves the same
`scrcpy-bridge-<target-triple>.{tar.gz,zip}` file names. `beeos device upgrade`
force-refreshes the managed binary alongside the Python device-agent venv.

## Run

### Agent Gateway bootstrap + JWT auto-refresh (the only supported path)

scrcpy-bridge authenticates to EMQX exclusively by fetching fresh MQTT
credentials from Agent Gateway `GET /api/v1/device/bootstrap`, signed with
Ed25519, and then auto-refreshing the short-lived JWT before it expires.
**There is no static `--mqtt-token` / `MQTT_URL` fallback**: Runtime-issued
JWTs expire in ~10 minutes and `rumqttc` reuses its initial password on
reconnect, which would guarantee a silently broken session. Missing any of
`AGENT_GATEWAY_URL` / `BRIDGE_PRIVATE_KEY_FILE` / `BRIDGE_PUBLIC_KEY_FILE`
causes scrcpy-bridge to fail-fast at startup.

```
DEVICE_ID=dev-emulator-1 \
ADB_SERIAL=127.0.0.1:5555 \
AGENT_GATEWAY_URL=https://agent-gw.beeos.ai \
BRIDGE_PRIVATE_KEY_FILE=/var/run/bridge/identity/private.key \
BRIDGE_PUBLIC_KEY_FILE=/var/run/bridge/identity/public.key \
JWT_REFRESH_LEAD_SECS=60 \
JWT_REFRESH_MIN_INTERVAL_SECS=30 \
target/release/scrcpy-bridge
```

**Key file layouts.** `BRIDGE_PRIVATE_KEY_FILE` / `BRIDGE_PUBLIC_KEY_FILE`
accept two interchangeable formats (auto-detected by sniffing the first
non-whitespace byte — see `bootstrap::read_private_key_file`):

1. **Raw base64 text** (one line, 32-byte Ed25519 seed for the private
   key, 32-byte public key for the public key). Matches cluster-proxy's
   `provisionBridgeIdentity` secret layout and is the format shown in
   the k8s example above.
2. **`.key.json`** — JSON object `{ "publicKey": "<b64>",
   "privateKey": "<b64>" }`. Same layout as the BeeOS CLI /
   device-agent (`~/.beeos/identity/device-<serial>.key.json`). The
   same file path can be supplied for both env vars — the reader
   extracts the right field on each call. This is what `beeos device
   attach` uses so scrcpy-bridge and device-agent share one identity.

How it works:
 * At startup scrcpy-bridge signs a timestamped challenge with the Ed25519
   private key and calls Agent Gateway `GET /api/v1/device/bootstrap`. The
   signature scheme matches `agentauth.VerifyRequest` in Go —
   `"GET|/api/v1/device/bootstrap|<ts>|<nonce>"` — and the headers are
   `X-Agent-Public-Key` / `X-Agent-Signature` / `X-Agent-Timestamp` /
   `X-Agent-Nonce`. The response (`mqttUrl`, `mqttToken`, `deviceTopic`,
   `iceServers`, `expiresAt`) wires both MQTT (topic prefix +
   credentials) and ICE (full TURN pool with short-lived per-entry
   username/credential).
 * A background task (`bootstrap::spawn_refresh_loop`) refreshes the JWT
   `JWT_REFRESH_LEAD_SECS` seconds before expiry (default 60s), subject to
   `JWT_REFRESH_MIN_INTERVAL_SECS` (default 30s) between attempts.
 * On successful refresh the `mqtt/signaling.rs::reconnect` path tears
   down the current `rumqttc` session and starts a new one with the fresh
   credentials — active WebRTC PeerConnections are unaffected because
   they ride on their own sockets.
 * If refresh fails past expiry, scrcpy-bridge marks the MQTT session
   unhealthy; the `/healthz` endpoint starts returning 503 and Kubernetes
   (or edge-agent) restarts the pod/process.
 * Prometheus metrics: `scrcpy_bridge_jwt_refresh_total{result="success|failure"}`,
   `scrcpy_bridge_mqtt_reconnects_total`.

**Runtime signs JWTs with RS256** (RSA private key in `Runtime`). EMQX
verifies with the matching RSA public key — never HS256. See
`deploy/emqx/README.md` for the local-dev key generation script and
production Helm configuration.

### Optional ICE / TURN overrides

Agent Gateway normally returns the full ICE list in the bootstrap response.
If you need to override it (offline / air-gapped labs), pass the extras as
env vars — these are merged with whatever the bootstrap response delivers:

```
ICE_URLS=stun:stun.l.google.com:19302,turn:turn.example.com:3478 \
TURN_USERNAME=beeos \
TURN_CREDENTIAL=secret \
```

### Multi-homed pods / WebRTC host candidates

Kubernetes pods often have multiple reachable IPs (pod CIDR, node IP,
external load-balancer). `str0m` only binds to wildcard sockets by
default, so you may want to advertise extra host candidates explicitly:

```
POD_IP=10.42.7.42 \
PUBLIC_IPS="$POD_IP,100.64.1.10" \
ICE_GATHER_WAIT_MS=250 \
target/release/scrcpy-bridge
```

`POD_IP` is auto-injected via the Downward API in the executor; the
`ICE_GATHER_WAIT_MS` knob delays SDP answer emission slightly to let
more candidates gather before the offer/answer exchange completes.

## Deployment

### ReDroid Kubernetes Pod (sidecar)

See `deploy/redroid/pod.yaml`:
 * `redroid` container exposes ADB on `127.0.0.1:5555` (shared pod network).
 * `scrcpy-bridge` container runs with `ADB_SERIAL=127.0.0.1:5555` and does
   all streaming work. Python `device-agent` is NOT part of the ReDroid pod —
   it only runs on device-farm hosts where it supervises physical devices.

### Edge Agent (device farm host)

`edge-agent` spawns **two sibling processes** per discovered device:

  * `scrcpy-bridge` — streaming (this crate).
  * `device-agent` — ACP / AI (Python).

Each gets its own `--restart-on-crash` loop. Neither knows about the other;
coordination happens implicitly through the shared host ADB daemon and the
disjoint MQTT topic trees.

## Verify the spike

1. Start `scrcpy-bridge` with a real device and valid MQTT token.
2. Open `device-viewer` in the browser.
3. Check `curl localhost:9091/metrics`:
   * `scrcpy_bridge_video_frames_total{kind="keyframe"}` increases
   * `scrcpy_bridge_viewer_connected 1`
4. Target latency (glass-to-glass): <150ms LAN, <300ms WAN.
5. Target CPU at 1080p30 H.264: <0.5 core (previously ~1 core per device in
   the Python prototype).

## Protocol compatibility

 * MQTT signaling topics and JSON payloads are **identical** to the Python
   `device_agent.mqtt.signaling` implementation, so the browser frontend needs
   zero changes.
 * DataChannel JSON schema (touch / scroll / key / text / back / home /
   configure / ping / stats) matches `device_agent.agent._on_datachannel_message`.
   Outgoing helpers: `build_pong` (replies to browser heartbeats), `build_viewer_kicked`
   (notifies evicted viewers when a new offer arrives), `build_stream_restarted`
   (signals scrcpy pipeline restarts so the frontend reconnects its decoder).
 * H.264 AU format: Annex-B NAL units (SPS/PPS config + keyframes + delta
   frames). Byte-for-byte identical to what scrcpy emits.

### Audio transport (DataChannel binary)

OPUS audio packets from scrcpy's audio socket are forwarded as **binary
DataChannel messages** on the same `control` channel used for JSON
control messages. This matches what the browser `device-viewer` expects
today (`Web Codecs AudioDecoder` fed from binary `message` events), so
no frontend changes are required.

Internally:
 * `scrcpy/audio.rs` parses framed OPUS packets from scrcpy-server.
 * `bridge/mod.rs` spawns an audio pump that forwards each packet via
   `PeerCommand::SendControlBinary` into `webrtc/peer.rs`.
 * `webrtc/peer.rs` writes the bytes to the DataChannel with the binary
   flag (`chan.write(true, &payload)`).

Prometheus metrics: `scrcpy_bridge_audio_packets_total`,
`scrcpy_bridge_audio_packets_dropped_total`.

In Phase 3 this path will move to a dedicated WebRTC audio track
(OPUS PT 111). The DataChannel binary path is the Phase 1 pragmatic
choice to avoid a simultaneous frontend rewrite.

## License

MIT. `scrcpy-server.jar` is Apache-2.0 and redistributed unmodified.
