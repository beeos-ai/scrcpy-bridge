//! Read OPUS audio packets from scrcpy's audio socket.

use anyhow::{anyhow, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use super::protocol::{AUDIO_DISABLE_ERROR, AUDIO_DISABLE_SOFT, FLAG_CONFIG, FRAME_HEADER_LEN, PTS_MASK};

#[derive(Debug, Clone)]
pub struct AudioPacket {
    pub pts_us: u64,
    pub is_config: bool,
    pub data: Vec<u8>,
}

/// State machine for the scrcpy audio socket.
///
/// On connect the server writes a 4-byte status word first; values 0/1 mean
/// "audio disabled" and the socket then closes. Anything else is the first
/// 4 bytes of a regular 12-byte frame header and we continue normally.
pub struct AudioReader {
    inner: TcpStream,
    disabled: bool,
    pending_prefix: Option<[u8; 4]>,
}

impl AudioReader {
    pub fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            disabled: false,
            pending_prefix: None,
        }
    }

    async fn handshake(&mut self) -> Result<()> {
        if self.disabled || self.pending_prefix.is_some() {
            return Ok(());
        }
        let mut peek = [0u8; 4];
        self.inner.read_exact(&mut peek).await.map_err(|e| anyhow!("audio peek: {e}"))?;
        let code = u32::from_be_bytes(peek);
        if code == AUDIO_DISABLE_SOFT || code == AUDIO_DISABLE_ERROR {
            self.disabled = true;
            return Err(anyhow!("audio disabled by device (code={code})"));
        }
        self.pending_prefix = Some(peek);
        Ok(())
    }

    pub async fn next_packet(&mut self) -> Result<Option<AudioPacket>> {
        if self.disabled {
            return Ok(None);
        }
        self.handshake().await?;

        let mut header = [0u8; FRAME_HEADER_LEN];
        if let Some(prefix) = self.pending_prefix.take() {
            header[..4].copy_from_slice(&prefix);
            if let Err(e) = self.inner.read_exact(&mut header[4..]).await {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Ok(None);
                }
                return Err(anyhow!("audio first header tail: {e}"));
            }
        } else {
            match self.inner.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(anyhow!("audio header read: {e}")),
            }
        }

        let pts_word = u64::from_be_bytes(header[..8].try_into().unwrap());
        let size = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
        if size == 0 || size > 1024 * 1024 {
            return Err(anyhow!("audio: invalid packet size {size}"));
        }
        let mut data = vec![0u8; size];
        self.inner
            .read_exact(&mut data)
            .await
            .map_err(|e| anyhow!("audio payload read: {e}"))?;
        Ok(Some(AudioPacket {
            pts_us: pts_word & PTS_MASK,
            is_config: pts_word & FLAG_CONFIG != 0,
            data,
        }))
    }
}
