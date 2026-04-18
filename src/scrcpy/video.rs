//! Read H.264 NAL units from scrcpy's video socket.

use anyhow::{anyhow, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use super::protocol::{FLAG_CONFIG, FLAG_KEYFRAME, FRAME_HEADER_LEN, PTS_MASK};

/// A single frame as it arrives from scrcpy.
///
/// `data` is a raw Annex-B NAL unit (starts with `00 00 00 01`). For config
/// frames (`is_config=true`), `data` is the concatenated SPS+PPS.
#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub pts_us: u64,
    pub is_config: bool,
    pub is_keyframe: bool,
    pub data: Vec<u8>,
}

pub struct VideoReader {
    inner: TcpStream,
}

impl VideoReader {
    pub fn new(inner: TcpStream) -> Self {
        Self { inner }
    }

    /// Read the next frame from the socket.
    ///
    /// Returns `Ok(None)` on clean EOF so callers can distinguish that from an
    /// I/O error that should be logged.
    pub async fn next_frame(&mut self) -> Result<Option<VideoFrame>> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        match self.inner.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(anyhow!("scrcpy video header read: {e}")),
        };
        let pts_word = u64::from_be_bytes(header[..8].try_into().unwrap());
        let size = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;

        if size == 0 || size > 10 * 1024 * 1024 {
            return Err(anyhow!("scrcpy video: invalid frame size {size}"));
        }

        let mut data = vec![0u8; size];
        self.inner
            .read_exact(&mut data)
            .await
            .map_err(|e| anyhow!("scrcpy video payload read: {e}"))?;

        Ok(Some(VideoFrame {
            pts_us: pts_word & PTS_MASK,
            is_config: pts_word & FLAG_CONFIG != 0,
            is_keyframe: pts_word & FLAG_KEYFRAME != 0,
            data,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::protocol::{FLAG_CONFIG, FLAG_KEYFRAME};

    #[test]
    fn parses_pts_flags() {
        let cfg_pts = FLAG_CONFIG | 123;
        assert_eq!(cfg_pts & FLAG_CONFIG, FLAG_CONFIG);
        assert_eq!(cfg_pts & PTS_MASK, 123);

        let kf_pts = FLAG_KEYFRAME | 456;
        assert_eq!(kf_pts & FLAG_KEYFRAME, FLAG_KEYFRAME);
        assert_eq!(kf_pts & PTS_MASK, 456);
    }
}
