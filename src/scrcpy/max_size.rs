//! Map Stream Protocol v1 `maxWidth` (short-edge profile) onto scrcpy
//! `max_size` (longer encoded edge).
//!
//! scrcpy 3.x `max_size` is `max(width, height)`. A 720×1280 portrait
//! framebuffer with `max_size=720` is scaled to 408×720. The 720p
//! profile must keep 720×1280, so `max_size` is 1280.

/// Convert a server-owned short-edge profile (`MAX_WIDTH` 720 / 1080)
/// into the scrcpy `max_size` long-edge cap.
pub fn scrcpy_max_size(profile_short_edge: u32) -> u32 {
    match profile_short_edge {
        0 => 1920,
        w if w <= 720 => 1280,
        w if w <= 1080 => 1920,
        // Already a long-edge override (legacy MAX_WIDTH=1280/1920).
        w => w,
    }
}

#[cfg(test)]
mod tests {
    use super::scrcpy_max_size;

    #[test]
    fn profile_720_keeps_portrait_720x1280() {
        assert_eq!(scrcpy_max_size(720), 1280);
    }

    #[test]
    fn profile_1080_keeps_portrait_1080x1920() {
        assert_eq!(scrcpy_max_size(1080), 1920);
    }

    #[test]
    fn long_edge_override_is_unchanged() {
        assert_eq!(scrcpy_max_size(1280), 1280);
        assert_eq!(scrcpy_max_size(1920), 1920);
    }

    #[test]
    fn zero_defaults_to_1080p_long_edge() {
        assert_eq!(scrcpy_max_size(0), 1920);
    }
}
