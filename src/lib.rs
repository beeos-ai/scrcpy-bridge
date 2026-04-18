//! scrcpy-bridge
//!
//! A standalone, Rust-native WebRTC gateway that translates scrcpy's Android
//! screen-mirror protocol into a browser-consumable WebRTC stream.
//!
//! ### Zero-coupling design
//!
//! This process runs SIDE BY SIDE with the Python `device-agent`. The two are
//! independent sibling processes that share nothing except:
//!   1. the host's ADB daemon (thread-safe)
//!   2. the MQTT broker (disjoint topic subtrees)
//!   3. the physical device (different ADB command paths)
//!
//! There is NO IPC. Either can crash without affecting the other.
//!
//! ### Modules
//!
//! * [`adb`] — thin wrapper around the `adb` binary (push / forward / shell).
//! * [`scrcpy`] — protocol implementation: pushes server.jar, launches
//!   `app_process`, reads video/audio/control sockets.
//! * [`mqtt`] — MQTT signaling client. Subscribes to
//!   `devices/{id}/signaling/request`, publishes to `.../response`.
//! * [`webrtc`] — `str0m`-backed peer connection with H.264 passthrough.
//! * [`datachannel`] — Parse browser control messages and forward to scrcpy
//!   control socket. Also sends device state updates back.
//! * [`bridge`] — Orchestrator that ties the above together for one device.
//! * [`observability`] — `/metrics` + `/healthz` HTTP endpoint.

#![forbid(unsafe_code)]
#![warn(clippy::all)]

pub mod adb;
pub mod bootstrap;
pub mod bridge;
pub mod config;
pub mod datachannel;
pub mod mqtt;
pub mod observability;
pub mod scrcpy;
pub mod webrtc;

/// Embedded scrcpy-server JAR, downloaded by `build.rs`.
///
/// The runtime writes this to `/data/local/tmp/scrcpy-server.jar` on the
/// target device, so users never need to install scrcpy separately.
pub static SCRCPY_SERVER_JAR: &[u8] = include_bytes!("../assets/scrcpy-server.jar");

/// scrcpy protocol version the embedded JAR matches (set by `build.rs`).
pub const SCRCPY_VERSION: &str = env!("SCRCPY_VERSION");
