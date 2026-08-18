# BeeOS Stream Protocol v1

Public contract for cloud-phone video, audio, and input. Aligns with
IETF WebRTC (SDP, ICE, DTLS-SRTP, RTP, RTCP) plus a thin MQTT signaling
channel and a versioned DataChannel for *input*, not encoder policy.

This is the document external integrators should implement. Quality
caps live on the server (CLI/env / stream-params / session plan).
Viewers do **not** own bitrate, resolution, or GOP.

## Layers

```
A. Control plane   GET .../stream-params
B. Signaling       MQTT JSON: offer | answer | ice | close
C. Media           RTP H.264 + Opus; SCTP DataChannel "control" for input
```

Unknown JSON keys and unknown DataChannel `type` values MUST be ignored
on both sides (additive compatibility).

## A. Stream params

`GET /api/v1/instances/{id}/device/stream-params`  
`GET /api/v1/instances/{id}/mobile/stream-params`

Existing fields (required for a session):

| Field | Meaning |
|-------|---------|
| `mqttUrl` / `mqttToken` / `deviceTopic` | Signaling credentials |
| `iceServers` | Standard `RTCIceServer` list |
| `expiresAt` | Token expiry (unix seconds) |
| `viewUrl` | Optional dashboard URL |

Additive (v1 viewers apply only the WebRTC-standard fields):

| Field | Client action |
|-------|----------------|
| `iceTransportPolicy` | `RTCIceTransportPolicy` (`all` \| `relay`) |
| `video.maxWidth` / `video.maxFps` / `video.maxBitrate` / `video.codec` | **Read-only echo** of the server-selected cap. Do not send `configure`. |
| `videoTransport` | Server-owned iOS path: `auto` (default, try RTP then DC), `rtp`, or `datachannel`. Web/Android ignore. |
| `videoTransportFallbackMs` | `auto` only. How long iOS waits for an RTP paint before opening the video DataChannel (default 8000, clamp 1000–30000). |
| `videoDcReliability` | iOS video DC: `unreliable` (default, `maxRetransmits=0`) or `reliable`. |

Runtime ExtraEnv (SKU / ConfigMap) steers those three fields without an app release:

- `VIDEO_TRANSPORT` = `auto` \| `rtp` \| `datachannel`
- `VIDEO_TRANSPORT_FALLBACK_MS` = 1000–30000 (default 8000)
- `VIDEO_DC_RELIABILITY` = `unreliable` \| `reliable`
- `VIEWER_TURN_TRANSPORT` = `tcp` (default) \| `udp` \| `all`
- `VIEWER_ICE_TRANSPORT_POLICY` = `relay` (default when `tcp`) \| `all`

Optional query the last frozen client should send so the server can pick
a profile forever without another app release:

```
?viewportWidth=390&viewportHeight=844&dpr=3
```

The viewer reports screen size only. It never reports a bitrate.

## B. Signaling

Topic prefix comes from `deviceTopic`. Payloads:

```json
{"type":"offer","sdp":"...","viewerId":"...","traceId":"..."}
{"type":"answer","sdp":"..."}
{"type":"ice","candidate":{}}
{"type":"close","reason":"...","viewerId":"..."}
```

ICE restart is a new `offer` on the **same** `RTCPeerConnection` whose
SDP changes `ice-ufrag` / `ice-pwd`. The boolean `iceRestart` field is
not part of the contract; the bridge keys off DTLS fingerprint + ufrag.
A full PeerConnection rebuild changes the DTLS fingerprint and MUST be
the last resort: it drops SCTP/control and looks like "taps do nothing"
until the new handshake finishes.

### ICE / TURN split (server-owned)

`TURN_URLS` on Runtime is the union list (UDP TURN + TCP TURN + STUN).
The two sides of the PeerConnection do **not** consume it the same way:

| Side | Stack | What it can allocate |
|------|--------|----------------------|
| Bridge (this process) | webrtc-rs 0.17 | UDP `turn:` only. TCP TURN / TURNS are dropped. |
| Viewer (iOS / Android / web) | libwebrtc | UDP and TCP TURN. |

webrtc-rs `gather_candidates_relay` is UDP-`turn:` only (TCP is a
documented TODO). Enabling `NetworkType::Tcp4` does not fix that.
The working pair on lossy/UDP-hostile networks is therefore:

- viewer: TCP TURN allocation (`turn:…?transport=tcp`, `iceTransportPolicy=relay`)
- bridge: UDP TURN allocation on the same coturn

Runtime ExtraEnv steers the viewer list without an app release:

- `VIEWER_TURN_TRANSPORT` = `tcp` (default) \| `udp` \| `all`
- `VIEWER_ICE_TRANSPORT_POLICY` = `relay` \| `all`

Bootstrap ICE (this sidecar) is never filtered that way: the bridge
must keep UDP TURN.

The sidecar is the ICE answerer. A relay-only pair cannot check until
this process has a UDP TURN allocation (~2.5 s from OKE). The answer
therefore waits for that relay and embeds it in SDP. Trickle is still
published as a backup. Viewer candidates that arrive before the peer
exists are buffered, not dropped.

## C. Media

Public offer MUST include:

- `m=audio` recvonly Opus
- `m=video` recvonly H.264 Constrained Baseline
- `m=application` SCTP with a `control` DataChannel

Keyframe recovery on the RTP path is **RTCP PLI** (RFC 4585). The
bridge already maps PLI → scrcpy `ResetVideo`.

Video over a binary DataChannel is an iOS-only workaround, not the
external media contract. The bridge adopts that path the moment the
viewer opens a `label="video"` DataChannel (iOS is the only client
that does). It does not wait for `set_video_transport`.

## D. DataChannel `control`

### Viewer → bridge

| `type` | Role |
|--------|------|
| `touch` / `scroll` / `key` / `text` / `back` / `home` | Input |
| `camera_start` / `camera_stop` | Camera uplink |
| `ping` / `stats` / `viewer_ready` | Diagnostics. `viewer_ready` is a client-acked first paint. iOS 1.3.33 does not send it; the bridge logs `bridge.first_keyframe_sent` instead. |

`stats.packetsLost` may be signed; the bridge clamps to `≥ 0`.

### Deprecated (accepted, not authoritative)

| `type` | v1 behavior |
|--------|-------------|
| `configure` | Parsed and **ignored**. Encoder knobs are server-owned. |
| `set_video_transport` | Internal iOS fallback only. |
| `request_keyframe` | Internal DC-video path. RTP uses PLI. |

### Bridge → viewer

| `type` | v1 viewer behavior |
|--------|--------------------|
| `pong` / `device_info` / `camera_needed` / `camera_status` | Existing |
| `viewer_kicked` | Stop; do not steal the session back |
| `stream_restarted` | Flush the decoder and wait for the next IDR. **Do not** tear down the PeerConnection if ICE/SCTP are still up. |
| unknown | Ignore |

## Encoder authority

`MAX_FPS`, `MAX_WIDTH`, `VIDEO_BITRATE`, and `I_FRAME_INTERVAL` (and
the same values when injected by the control plane) plus bootstrap
`video.*` are the encoder authority. A later viewer viewport is
persisted by Runtime and applied on the next `app_process` start
(offer re-fetch, JWT refresh, or keep-PC restart). They apply at the
next `app_process` start.

`video.maxWidth` / `MAX_WIDTH` is the **short-edge** profile (`720` or
`1080`). scrcpy 3.x `max_size` is the **longer** edge, so the sidecar
maps `720 → max_size=1280` and `1080 → max_size=1920`. A 720×1280
portrait framebuffer must encode as 720×1280, not 408×720. Override
with `SCRCPY_MAX_SIZE` only when the long edge is not 16:9.

scrcpy 3.x cannot change width/bitrate/GOP on a live process. Mid-session
the bridge can emit IDRs. Changing resolution or bitrate later **restarts
the encoder and keeps the WebRTC PeerConnection**. The viewer flushes its
decoder on `stream_restarted` and waits for the next SPS/PPS + IDR. There
is a brief black frame; there is no MediaCodec `setParameters` path in
stock 3.1.

Sender BWE (TWCC on the outbound screen track + `get_stats`
`availableOutgoingBitrate`, conservative-min'd with the viewer's reported
receive bitrate) can downshift 1080 → 720 when the estimate stays under
1.8 Mbps for 3 s. Upshift waits 10 s and never exceeds the SKU / viewport
cap from the latest bootstrap `video` (SKU ∩ persisted viewport). A
restart is rate-limited to once per 8 s.

## What this protocol is not

- Not a client-side recovery DSL (`session_policy`, grace timers, Retry UI).
- Not a client-owned ABR ladder.
- Not WHIP/WHEP yet (signaling remains MQTT). Media is still WebRTC.
