//! Write control messages to scrcpy's control socket.
//!
//! Wire format matches scrcpy v3.x `ControlMessage.java`. All multi-byte
//! integers are big-endian.

use anyhow::Result;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use super::protocol::{ControlType, KeyAction, TouchAction};

pub struct ControlSocket {
    writer: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    /// Background task that drains the server → client half of the socket so
    /// the kernel's receive buffer never fills up.
    _drainer: tokio::task::JoinHandle<()>,
}

impl ControlSocket {
    pub fn new(stream: TcpStream) -> Self {
        let (mut read_half, write_half) = stream.into_split();
        let drainer = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match read_half.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
        });
        Self {
            writer: Mutex::new(write_half),
            _drainer: drainer,
        }
    }

    async fn send(&self, buf: &[u8]) -> Result<()> {
        let mut w = self.writer.lock().await;
        w.write_all(buf).await?;
        Ok(())
    }

    /// Inject a touch event. `pressure` is clamped to `[0.0, 1.0]`.
    pub async fn inject_touch(
        &self,
        action: TouchAction,
        x: i32,
        y: i32,
        screen_w: u16,
        screen_h: u16,
        pointer_id: i64,
        pressure: f32,
    ) -> Result<()> {
        // 28 bytes (excluding the opcode) in scrcpy v3.x; packed layout:
        //   u8 opcode, u8 action, i64 pointerId, i32 x, i32 y, u16 w, u16 h,
        //   u16 pressure, u32 actionButton, u32 buttons
        let mut b = BytesMut::with_capacity(1 + 1 + 8 + 4 + 4 + 2 + 2 + 2 + 4 + 4);
        b.put_u8(ControlType::InjectTouch as u8);
        b.put_u8(action as u8);
        b.put_i64(pointer_id);
        b.put_i32(x);
        b.put_i32(y);
        b.put_u16(screen_w);
        b.put_u16(screen_h);
        let p = if matches!(action, TouchAction::Up) {
            0u16
        } else {
            (pressure.clamp(0.0, 1.0) * u16::MAX as f32) as u16
        };
        b.put_u16(p);
        b.put_u32(0); // actionButton
        b.put_u32(0); // buttons
        self.send(&b).await
    }

    /// Inject a scroll event. `scroll_x`/`scroll_y` are clamped to `[-1, 1]`.
    pub async fn inject_scroll(
        &self,
        x: i32,
        y: i32,
        screen_w: u16,
        screen_h: u16,
        scroll_x: f32,
        scroll_y: f32,
    ) -> Result<()> {
        let hscroll = float_to_i16_fp(scroll_x);
        let vscroll = float_to_i16_fp(scroll_y);
        // Layout: u8 opcode, i32 x, i32 y, u16 w, u16 h, i16 hscroll, i16 vscroll, u32 buttons
        let mut b = BytesMut::with_capacity(1 + 4 + 4 + 2 + 2 + 2 + 2 + 4);
        b.put_u8(ControlType::InjectScroll as u8);
        b.put_i32(x);
        b.put_i32(y);
        b.put_u16(screen_w);
        b.put_u16(screen_h);
        b.put_i16(hscroll);
        b.put_i16(vscroll);
        b.put_u32(0);
        self.send(&b).await
    }

    /// Inject a raw Android keycode.
    pub async fn inject_keycode(
        &self,
        action: KeyAction,
        keycode: i32,
        repeat: i32,
        metastate: i32,
    ) -> Result<()> {
        let mut b = BytesMut::with_capacity(1 + 1 + 4 + 4 + 4);
        b.put_u8(ControlType::InjectKeycode as u8);
        b.put_u8(action as u8);
        b.put_i32(keycode);
        b.put_i32(repeat);
        b.put_i32(metastate);
        self.send(&b).await
    }

    /// Send BACK_OR_SCREEN_ON.
    pub async fn back_or_screen_on(&self, action: KeyAction) -> Result<()> {
        let buf = [ControlType::BackOrScreenOn as u8, action as u8];
        self.send(&buf).await
    }

    /// Inject UTF-8 text via scrcpy's `INJECT_TEXT` message.
    ///
    /// The device-side scrcpy server caps a single `INJECT_TEXT` payload at
    /// [`INJECT_TEXT_MAX_LENGTH`] bytes (scrcpy v3.x). To support long
    /// clipboard pastes / Unicode strings without silently dropping the tail,
    /// the payload is chunked on UTF-8 character boundaries and sent as
    /// consecutive `INJECT_TEXT` messages. Each chunk carries complete code
    /// points, so multi-byte characters are never split.
    pub async fn inject_text(&self, text: &str) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        for chunk in utf8_chunks(text, INJECT_TEXT_MAX_LENGTH) {
            let payload = chunk.as_bytes();
            let mut b = BytesMut::with_capacity(1 + 4 + payload.len());
            b.put_u8(ControlType::InjectText as u8);
            b.put_u32(payload.len() as u32);
            b.put_slice(payload);
            self.send(&b).await?;
        }
        Ok(())
    }

    /// Set the device clipboard. `paste=true` also dispatches ACTION_PASTE.
    pub async fn set_clipboard(&self, text: &str, paste: bool) -> Result<()> {
        let payload = text.as_bytes();
        let mut b = BytesMut::with_capacity(1 + 8 + 1 + 4 + payload.len());
        b.put_u8(ControlType::SetClipboard as u8);
        b.put_u64(0); // sequence
        b.put_u8(if paste { 1 } else { 0 });
        b.put_u32(payload.len() as u32);
        b.put_slice(payload);
        self.send(&b).await
    }

    /// Ask the encoder for a fresh IDR (clears any decoder-side freeze).
    pub async fn reset_video(&self) -> Result<()> {
        self.send(&[ControlType::ResetVideo as u8]).await
    }
}

fn float_to_i16_fp(v: f32) -> i16 {
    let v = v.clamp(-1.0, 1.0);
    let scaled = (v * 0x8000 as f32) as i32;
    scaled.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

/// Maximum bytes scrcpy's `INJECT_TEXT` control message accepts in a single
/// payload (matches `SC_CONTROL_MSG_INJECT_TEXT_MAX_LENGTH` in scrcpy v3.x).
const INJECT_TEXT_MAX_LENGTH: usize = 300;

/// Split a UTF-8 string into chunks of at most `max_bytes` bytes, ensuring
/// every chunk is itself valid UTF-8 (i.e. never cuts a multi-byte character
/// in the middle). The iterator yields non-empty slices borrowed from the
/// original string.
fn utf8_chunks(s: &str, max_bytes: usize) -> impl Iterator<Item = &str> {
    debug_assert!(max_bytes > 0);
    let mut start = 0usize;
    let len = s.len();
    std::iter::from_fn(move || {
        if start >= len {
            return None;
        }
        let remaining = len - start;
        if remaining <= max_bytes {
            let chunk = &s[start..];
            start = len;
            return Some(chunk);
        }
        let tentative_end = start + max_bytes;
        // Walk backwards until we land on a UTF-8 char boundary.
        let mut end = tentative_end;
        while end > start && !s.is_char_boundary(end) {
            end -= 1;
        }
        // Edge case: a single character exceeds max_bytes. Push end forward
        // to the next char boundary so we still make progress (the chunk
        // will exceed max_bytes but the server-side cap is conservative).
        if end == start {
            end = tentative_end;
            while end < len && !s.is_char_boundary(end) {
                end += 1;
            }
        }
        let chunk = &s[start..end];
        start = end;
        Some(chunk)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_fp_roundtrip() {
        assert_eq!(float_to_i16_fp(0.0), 0);
        assert_eq!(float_to_i16_fp(1.0), i16::MAX);
        assert_eq!(float_to_i16_fp(-1.0), i16::MIN);
        assert!(float_to_i16_fp(0.5) > 0);
        assert!(float_to_i16_fp(-0.5) < 0);
    }

    #[test]
    fn utf8_chunks_short_text_yields_single_chunk() {
        let chunks: Vec<&str> = utf8_chunks("hello", 300).collect();
        assert_eq!(chunks, vec!["hello"]);
    }

    #[test]
    fn utf8_chunks_respects_byte_budget() {
        let s = "abcdefghij"; // 10 ASCII bytes
        let chunks: Vec<&str> = utf8_chunks(s, 4).collect();
        assert_eq!(chunks, vec!["abcd", "efgh", "ij"]);
        assert!(chunks.iter().all(|c| c.len() <= 4));
    }

    #[test]
    fn utf8_chunks_never_splits_multibyte_char() {
        // Each Chinese char is 3 bytes in UTF-8.
        let s = "你好世界啊"; // 5 chars * 3 bytes = 15 bytes
        // Cap at 4 bytes: each chunk should fit exactly one 3-byte char
        // (the 4th byte would start the next char, which is not a boundary
        // if we stopped at byte 4 — we must walk back to byte 3).
        let chunks: Vec<&str> = utf8_chunks(s, 4).collect();
        for chunk in &chunks {
            assert!(std::str::from_utf8(chunk.as_bytes()).is_ok());
            assert!(chunk.len() <= 4);
        }
        // Concatenation round-trips the input.
        assert_eq!(chunks.concat(), s);
    }

    #[test]
    fn utf8_chunks_handles_empty_string() {
        let chunks: Vec<&str> = utf8_chunks("", 10).collect();
        assert!(chunks.is_empty());
    }

    #[test]
    fn utf8_chunks_max_equals_total_len() {
        let s = "hello";
        let chunks: Vec<&str> = utf8_chunks(s, 5).collect();
        assert_eq!(chunks, vec!["hello"]);
    }
}
