//! WebRTC peer with service-side TURN relay support.
//!
//! ## H.264 pass-through
//!
//! The whole reason this crate exists is to avoid the decode/re-encode cycle
//! that the Python prototype does. Scrcpy hands us H.264 AUs directly; we
//! simply hand each AU to the WebRTC sample API and its
//! built-in H.264 packetizer chops it into RTP packets.
//!
//! ## Run-loop ownership
//!
//! [`WebRtcPeer`] owns a dedicated tokio task that drives the `Rtc` state
//! machine. The public API is message-passing (offer / ice / close via
//! an mpsc channel, events via a broadcast channel).

pub mod peer_webrtc;

pub use peer_webrtc::{
    BweSnapshot, CameraFrame, IceServer, NegotiationKind, PeerCommand, PeerEvent, PeerOptions,
    VideoTransport, WebRtcPeer,
};
