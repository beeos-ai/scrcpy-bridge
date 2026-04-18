//! MQTT signaling client.
//!
//! This module exposes a single entry point, [`MqttSignaling`], which:
//!   * connects to EMQX using the URL scheme (mqtt / mqtts / ws / wss),
//!   * subscribes to `{topic_prefix}/signaling/request`,
//!   * decodes the incoming JSON payload into [`SignalRequest`],
//!   * publishes [`SignalResponse`] values on
//!     `{topic_prefix}/signaling/response`.
//!
//! `topic_prefix` is supplied by the caller and MUST come from the Agent
//! Gateway bootstrap response (`deviceTopic` field, e.g.
//! `devices/device-<instanceUUID>`) — Runtime scopes each MQTT JWT's ACL
//! to exactly this prefix, so constructing it from any other source
//! (like a bare UUID) will cause EMQX to reject every subscribe/publish.
//!
//! The protocol is 100 % compatible with the Python `SignalingHandler` in
//! `device_agent.mqtt.signaling`. We keep the JSON shape unchanged so the
//! browser frontend needs zero modifications.

pub mod signaling;

pub use signaling::{
    MqttCredentials, MqttSignaling, MqttSignalingConfig, SignalRequest, SignalResponse,
};
