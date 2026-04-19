//! scrcpy client protocol implementation.
//!
//! The entry point is [`ScrcpyServer`], which owns:
//! - the embedded scrcpy-server.jar (pushed via ADB)
//! - an `adb forward` tunnel on a random local port
//! - three TCP sockets to the device: **video**, **audio**, **control**
//! - the `app_process` subprocess that runs scrcpy-server on the device
//!
//! Protocol reference: scrcpy v3.x with `tunnel_forward=true`, and all
//! `send_*_meta` options disabled except `send_frame_meta=true`.
//!
//! ### Wire format
//!
//! The video and audio sockets share the frame layout:
//!
//! ```text
//! +-----------------+-----------------+-----------+
//! | PTS / flags u64 | payload size u32 |  payload |
//! +-----------------+-----------------+-----------+
//!   (bit63 = config NAL, bit62 = keyframe)
//! ```
//!
//! The control socket is bidirectional; we only write touch / key / scroll
//! messages and drain anything the server writes back.

pub mod audio;
pub mod control;
pub mod protocol;
pub mod server;
pub mod video;

pub use audio::{AudioPacket, AudioReader};
pub use control::ControlSocket;
pub use server::{ScrcpyServer, ScrcpyServerConfig, ScrcpySessionParts, ScrcpyShutdown};
pub use video::{VideoFrame, VideoReader};
