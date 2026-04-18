//! scrcpy protocol wire-format constants + types.
//!
//! These match the Java sources in `com.genymobile.scrcpy` for the v3.x line.
//! Bump alongside the pinned `SCRCPY_VERSION` in `build.rs`.

/// Bit set on the PTS word to mark a config NAL (SPS/PPS).
pub const FLAG_CONFIG: u64 = 1u64 << 63;
/// Bit set on the PTS word to mark a keyframe NAL.
pub const FLAG_KEYFRAME: u64 = 1u64 << 62;
/// Mask to extract the actual PTS (microseconds since stream start).
pub const PTS_MASK: u64 = !(FLAG_CONFIG | FLAG_KEYFRAME);
/// Frame header size (pts_flags u64 BE + size u32 BE).
pub const FRAME_HEADER_LEN: usize = 12;

/// Control message opcodes (see `ControlMessage.java`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlType {
    InjectKeycode = 0,
    InjectText = 1,
    InjectTouch = 2,
    InjectScroll = 3,
    BackOrScreenOn = 4,
    ExpandNotificationPanel = 5,
    CollapsePanels = 7,
    GetClipboard = 8,
    SetClipboard = 9,
    SetScreenPowerMode = 10,
    RotateDevice = 11,
    UhidCreate = 12,
    ResetVideo = 17,
}

/// Android key action (`KeyEvent.ACTION_*`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Down = 0,
    Up = 1,
}

/// Touch action (`MotionEvent.ACTION_*`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchAction {
    Down = 0,
    Up = 1,
    Move = 2,
}

impl TouchAction {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "down" => Some(Self::Down),
            "up" => Some(Self::Up),
            "move" => Some(Self::Move),
            _ => None,
        }
    }
}

/// The "disable" code scrcpy sends on the audio socket when audio was rejected.
/// 0 = soft disable, 1 = error, anything else = a real header with payload.
pub const AUDIO_DISABLE_SOFT: u32 = 0;
pub const AUDIO_DISABLE_ERROR: u32 = 1;

/// Android KeyEvent key codes for the keys we forward from browsers.
pub fn keycode_from_name(name: &str) -> Option<i32> {
    Some(match name {
        "KEYCODE_BACK" => 4,
        "KEYCODE_HOME" => 3,
        "KEYCODE_APP_SWITCH" => 187,
        "KEYCODE_ENTER" => 66,
        "KEYCODE_DEL" => 67,
        "KEYCODE_TAB" => 61,
        "KEYCODE_SPACE" => 62,
        "KEYCODE_DPAD_UP" => 19,
        "KEYCODE_DPAD_DOWN" => 20,
        "KEYCODE_DPAD_LEFT" => 21,
        "KEYCODE_DPAD_RIGHT" => 22,
        "KEYCODE_VOLUME_UP" => 24,
        "KEYCODE_VOLUME_DOWN" => 25,
        "KEYCODE_POWER" => 26,
        "KEYCODE_MENU" => 82,
        _ => return None,
    })
}
