//! WebRTC peer using `str0m` (Sans-IO).
//!
//! ## H.264 pass-through
//!
//! The whole reason this crate exists is to avoid the decode/re-encode cycle
//! that the Python prototype does. Scrcpy hands us H.264 AUs directly; we
//! simply hand each AU to str0m's sample API (`Writer::write`) and str0m's
//! built-in H.264 packetizer chops it into RTP packets.
//!
//! ## Run-loop ownership
//!
//! [`WebRtcPeer`] owns a dedicated tokio task that drives the `Rtc` state
//! machine. The public API is message-passing (offer / ice / close via
//! an mpsc channel, events via a broadcast channel).

pub mod peer;

pub use peer::{IceServer, PeerCommand, PeerEvent, PeerOptions, WebRtcPeer};
