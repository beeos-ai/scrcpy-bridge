//! DataChannel control message parsing + outgoing message helpers.
//!
//! The browser sends JSON messages (`{type: "touch", ...}`) and we reply with
//! the shapes `web/packages/device-viewer/src/webrtc-client.ts` expects.
//!
//! ### Browser → device (incoming, handled by [`ControlIn`])
//! - `touch`    — `action` (down/up/move), `x`, `y`, `pointerId?`, `pressure?`,
//!                `screenWidth`, `screenHeight`
//! - `scroll`   — `x`, `y`, `dx`, `dy`, `screenWidth`, `screenHeight`
//! - `key`      — `action` (down/up), `keycode` (string name)
//! - `text`     — `content`
//! - `back`     (no payload) / `home` (no payload)
//! - `configure` — `maxFps?`, `maxWidth?`, `bitrate?`, `iFrameInterval?`
//! - `ping`     — `ts` (ms). Device replies with `pong` mirroring `ts`.
//! - `stats`    — periodic client-side WebRTC stats (fps, rtt, bitrate, …).
//!                Consumed by the bridge for Prometheus metrics.
//!
//! ### Device → browser (outgoing, see [`build_*`] helpers)
//! - `pong`            — `ts: <mirror>` replying to a `ping`.
//! - `stream_restarted` — emitted when scrcpy pipeline was rebuilt; triggers
//!                        a fresh session on the browser (see `webrtc-client.ts`
//!                        `reconnectForStreamRestart`).
//! - `viewer_kicked`    — sent to a *previous* viewer right before we replace
//!                        them with a new offer.
//! - `device_info`      — optional metadata (resolution, codec profile) to
//!                        help the frontend choose touch scaling. Reserved
//!                        for Phase 2.

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ControlIn {
    Touch {
        action: String,
        #[serde(default)]
        x: i32,
        #[serde(default)]
        y: i32,
        #[serde(default = "default_pointer")]
        #[serde(rename = "pointerId")]
        pointer_id: i64,
        #[serde(default = "default_pressure")]
        pressure: f32,
        #[serde(default, rename = "screenWidth")]
        screen_width: u16,
        #[serde(default, rename = "screenHeight")]
        screen_height: u16,
    },
    Scroll {
        #[serde(default)]
        x: i32,
        #[serde(default)]
        y: i32,
        #[serde(default)]
        dx: f32,
        #[serde(default)]
        dy: f32,
        #[serde(default, rename = "screenWidth")]
        screen_width: u16,
        #[serde(default, rename = "screenHeight")]
        screen_height: u16,
    },
    Key {
        #[serde(default = "default_key_action")]
        action: String,
        #[serde(default)]
        keycode: String,
    },
    Text {
        #[serde(default)]
        content: String,
    },
    Back,
    Home,
    Configure {
        #[serde(default, rename = "maxFps")]
        max_fps: Option<u32>,
        #[serde(default, rename = "maxWidth")]
        max_width: Option<u32>,
        #[serde(default)]
        bitrate: Option<u32>,
        #[serde(default, rename = "iFrameInterval")]
        i_frame_interval: Option<u32>,
    },
    /// Browser heartbeat. Device echoes back a `pong` mirroring `ts`.
    Ping {
        /// Client-supplied monotonic timestamp (ms). Mirrored back verbatim.
        #[serde(default)]
        ts: i64,
    },
    /// Periodic inbound-RTP stats from the browser (see
    /// `webrtc-client.ts:startStatsCollection`). Payload is opaque here;
    /// only a few numeric fields are consumed for Prometheus.
    Stats {
        #[serde(default)]
        fps: f64,
        #[serde(default, rename = "bitrate")]
        bitrate_bps: f64,
        #[serde(default, rename = "packetsLost")]
        packets_lost: u64,
        #[serde(default, rename = "roundTripTime")]
        round_trip_time: f64,
    },
    /// Catch-all for unknown types; we ignore these but don't error the pipe.
    #[serde(other)]
    Unknown,
}

fn default_pointer() -> i64 {
    0
}
fn default_pressure() -> f32 {
    1.0
}
fn default_key_action() -> String {
    "down".to_string()
}

pub fn parse(raw: &[u8]) -> Result<ControlIn> {
    Ok(serde_json::from_slice(raw)?)
}

/// Build a `{"type":"pong","ts":<mirror>}` reply to a browser `ping`.
pub fn build_pong(ts: i64) -> String {
    json!({ "type": "pong", "ts": ts }).to_string()
}

/// Build a `{"type":"stream_restarted"}` payload. Browser's
/// `WebRTCClient.reconnectForStreamRestart()` uses this to reset its session
/// without counting against the reconnect budget.
pub fn build_stream_restarted() -> String {
    json!({ "type": "stream_restarted" }).to_string()
}

/// Build a `{"type":"viewer_kicked","reason":...}` payload sent to a
/// *previous* viewer right before it is replaced.
pub fn build_viewer_kicked(reason: &str) -> String {
    json!({ "type": "viewer_kicked", "reason": reason }).to_string()
}

/// Translate the browser's wheel delta into scrcpy's `[-1.0, 1.0]` range,
/// matching the Python implementation so UX stays identical.
pub fn wheel_to_scroll(dx: f32, dy: f32, sensitivity: f32) -> (f32, f32) {
    let raw_x = -dx / 120.0;
    let raw_y = -dy / 120.0;
    let compress = |v: f32| v.abs().powf(0.6).copysign(v);
    (
        (compress(raw_x) * sensitivity).clamp(-1.0, 1.0),
        (compress(raw_y) * sensitivity).clamp(-1.0, 1.0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_touch() {
        let j = br#"{"type":"touch","action":"down","x":10,"y":20,"pointerId":0,"pressure":0.5,"screenWidth":1080,"screenHeight":1920}"#;
        match parse(j).unwrap() {
            ControlIn::Touch { action, x, y, screen_width, screen_height, .. } => {
                assert_eq!(action, "down");
                assert_eq!(x, 10);
                assert_eq!(y, 20);
                assert_eq!(screen_width, 1080);
                assert_eq!(screen_height, 1920);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_key_back_home() {
        assert!(matches!(parse(br#"{"type":"back"}"#).unwrap(), ControlIn::Back));
        assert!(matches!(parse(br#"{"type":"home"}"#).unwrap(), ControlIn::Home));
    }

    #[test]
    fn wheel_math_matches_python() {
        let (sx, sy) = wheel_to_scroll(0.0, 120.0, 1.0);
        assert_eq!(sx, 0.0);
        assert!(sy < 0.0);
    }

    #[test]
    fn parse_ping_echoes_ts() {
        match parse(br#"{"type":"ping","ts":1234567}"#).unwrap() {
            ControlIn::Ping { ts } => assert_eq!(ts, 1234567),
            other => panic!("expected Ping, got {other:?}"),
        }
    }

    #[test]
    fn parse_stats_extracts_fields() {
        match parse(
            br#"{"type":"stats","fps":30,"bitrate":1200000,"packetsLost":2,"roundTripTime":0.05,"jitter":0.001,"bytesReceived":99999,"framesDecoded":900,"timestamp":1}"#,
        )
        .unwrap()
        {
            ControlIn::Stats {
                fps,
                bitrate_bps,
                packets_lost,
                round_trip_time,
            } => {
                assert!((fps - 30.0).abs() < 0.01);
                assert!((bitrate_bps - 1_200_000.0).abs() < 0.01);
                assert_eq!(packets_lost, 2);
                assert!((round_trip_time - 0.05).abs() < 0.001);
            }
            other => panic!("expected Stats, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_type_does_not_error() {
        // Important: future browser extensions must not crash old bridges.
        let parsed = parse(br#"{"type":"unknown_future_message","foo":1}"#).unwrap();
        assert!(matches!(parsed, ControlIn::Unknown));
    }

    #[test]
    fn build_pong_mirrors_ts() {
        let out = build_pong(42);
        assert_eq!(out, r#"{"ts":42,"type":"pong"}"#);
    }
}
