//! Server-owned encoder ladder + sender BWE.
//!
//! scrcpy 3.1 cannot retarget bitrate or resolution on a live `app_process`.
//! When estimated available bitrate stays below the current rung, the bridge
//! restarts the encoder (new `app_process`) while keeping the WebRTC
//! PeerConnection. Viewers flush the decoder on `stream_restarted`.
//!
//! There is no live MediaCodec `setParameters` path.

use std::time::{Duration, Instant};

use crate::scrcpy::ScrcpyServerConfig;

/// 720p rung: 720×1280 @ 2.5 Mbps. Matches Runtime stream-profile.
pub const RUNG_720: EncoderRung = EncoderRung {
    max_width: 720,
    bitrate: 2_500_000,
    max_fps: 30,
    i_frame_interval: 2,
};

/// 1080p rung: 1080×1920 @ 4 Mbps. Matches Runtime stream-profile.
pub const RUNG_1080: EncoderRung = EncoderRung {
    max_width: 1080,
    bitrate: 4_000_000,
    max_fps: 30,
    i_frame_interval: 2,
};

/// Highest-to-lowest is never used as a search order; index 0 is the floor.
pub const LADDER: [EncoderRung; 2] = [RUNG_720, RUNG_1080];

/// How long estimated bitrate must stay *below* the current rung before a
/// downshift. Short enough to escape a congested 1080p encode, long enough
/// that a single TWCC dip does not bounce the encoder.
pub const DOWN_HOLD: Duration = Duration::from_secs(3);
/// Upshift waits longer so a brief recovery does not flap 720 ↔ 1080.
pub const UP_HOLD: Duration = Duration::from_secs(10);
/// Floor between any encoder restart (BWE or recovery). Prevents a tight
/// restart loop when the network is oscillating around a threshold.
pub const MIN_SHIFT_GAP: Duration = Duration::from_secs(8);
/// Floor between video-eof encoder restarts. Scrcpy 3.1 NPEs
/// `SurfaceCapture.invalidate` when a new `app_process` starts while
/// the previous capture listener is still tearing down (~600 ms attach
/// loop). Two seconds lets the virtual display die cleanly.
pub const MIN_EOF_RESTART_GAP: Duration = Duration::from_secs(2);

/// 1080p downshifts when the estimate stays under 1.8 Mbps (plan v1).
pub const DOWN_THRESHOLD_1080_BPS: u64 = 1_800_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderRung {
    /// Stream Protocol short-edge profile (`MAX_WIDTH`).
    pub max_width: u32,
    pub bitrate: u32,
    pub max_fps: u32,
    pub i_frame_interval: u32,
}

impl EncoderRung {
    pub fn apply(self, cfg: &mut ScrcpyServerConfig) {
        cfg.max_width = self.max_width;
        cfg.bitrate = self.bitrate;
        cfg.max_fps = self.max_fps;
        cfg.i_frame_interval = self.i_frame_interval;
        // Recompute scrcpy `max_size` from the short-edge profile
        // (720 → 1280, 1080 → 1920). An operator long-edge override
        // must not pin a downshifted 720p encode to 1920.
        cfg.scrcpy_max_size = None;
    }
}

/// Ladder index for a short-edge profile. Widths above 720 sit on 1080p.
pub fn rung_index_for_width(max_width: u32) -> usize {
    if max_width <= 720 {
        0
    } else {
        1
    }
}

/// Combine sender-side send rate with the viewer's reported receive
/// bitrate. `available_outgoing_bps` is GCC/ICE TWCC; on TURN-TCP it
/// sits around 0.5 Mbps even while a 1080p encode is healthy, and
/// `min()` then always downshifts 1080→720. That restart crash-loops
/// scrcpy on Redroid HWC (`Physical 1280x800` + `wm size` override).
/// Ignore the ICE sample. If neither send nor receive is populated,
/// return `None` so BWE Holds instead of acting on a false floor.
pub fn combine_estimates(
    _available_outgoing_bps: Option<u64>,
    outbound_video_bps: Option<u64>,
    viewer_rx_bps: u64,
) -> Option<u64> {
    let mut samples = Vec::with_capacity(2);
    if viewer_rx_bps > 0 {
        samples.push(viewer_rx_bps);
    }
    if let Some(bps) = outbound_video_bps {
        if bps > 0 {
            samples.push(bps);
        }
    }
    samples.into_iter().min()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BweDecision {
    Hold,
    Downshift(EncoderRung),
    Upshift(EncoderRung),
}

/// Hysteresis controller. Pure: feed it timestamps + estimates in tests.
pub struct BweController {
    current_idx: usize,
    cap_idx: usize,
    /// Lowest rung still allowed this session. Raised to the SKU cap
    /// after a downshift dies before a keyframe so we never retry 720p.
    floor_idx: usize,
    below_since: Option<Instant>,
    above_since: Option<Instant>,
    last_shift: Instant,
}

impl BweController {
    /// `cap_width` is the SKU / viewport ceiling (never upshift past it).
    /// `current_width` is the live encoder profile.
    pub fn new(cap_width: u32, current_width: u32, now: Instant) -> Self {
        let cap_idx = rung_index_for_width(cap_width);
        let current_idx = rung_index_for_width(current_width).min(cap_idx);
        Self {
            current_idx,
            cap_idx,
            floor_idx: 0,
            below_since: None,
            above_since: None,
            last_shift: now - MIN_SHIFT_GAP,
        }
    }

    pub fn current_rung(&self) -> EncoderRung {
        LADDER[self.current_idx]
    }

    /// SKU / viewport ceiling. Distinct from the live encoder width
    /// after a BWE downshift — `ScrcpyServerConfig.max_width` is the
    /// live rung and must not be fed back into `set_cap`.
    pub fn cap_width(&self) -> u32 {
        LADDER[self.cap_idx].max_width
    }

    /// Start the shift-gap clock *now*. Used when the first keyframe
    /// lands so a TWCC estimate of ~600 kbps during ICE cannot downshift
    /// 1080→720 four seconds into the session (that restart crash-loops
    /// scrcpy on a 1280×800 HWC + `wm size` override).
    pub fn lock_rung(&mut self, now: Instant) {
        self.last_shift = now;
        self.below_since = None;
        self.above_since = None;
    }

    /// Lower (or raise) the SKU / viewport ceiling. Clamps the live
    /// rung so BWE cannot upshift past a newly persisted 720p cap.
    pub fn set_cap(&mut self, cap_width: u32) {
        self.cap_idx = rung_index_for_width(cap_width);
        if self.floor_idx > self.cap_idx {
            self.floor_idx = self.cap_idx;
        }
        if self.current_idx > self.cap_idx {
            self.current_idx = self.cap_idx;
        }
    }

    /// Ban every rung below `floor_width` for the rest of this session.
    /// `0` means "no extra floor" (ladder index 0 / 720p still allowed).
    pub fn set_floor(&mut self, floor_width: u32) {
        let floor_idx = if floor_width == 0 {
            0
        } else {
            rung_index_for_width(floor_width)
        };
        self.floor_idx = floor_idx.min(self.cap_idx);
        if self.current_idx < self.floor_idx {
            self.current_idx = self.floor_idx;
        }
    }

    pub fn observe(&mut self, estimated_bps: Option<u64>, now: Instant) -> BweDecision {
        let Some(estimate) = estimated_bps.filter(|bps| *bps > 0) else {
            return BweDecision::Hold;
        };

        if self.can_downshift() && estimate < down_threshold(self.current_rung()) {
            self.above_since = None;
            let since = *self.below_since.get_or_insert(now);
            if now.duration_since(since) >= DOWN_HOLD
                && now.duration_since(self.last_shift) >= MIN_SHIFT_GAP
            {
                self.current_idx -= 1;
                self.below_since = None;
                self.last_shift = now;
                return BweDecision::Downshift(self.current_rung());
            }
            return BweDecision::Hold;
        }

        if self.can_upshift() && estimate > up_threshold(LADDER[self.current_idx + 1]) {
            self.below_since = None;
            let since = *self.above_since.get_or_insert(now);
            if now.duration_since(since) >= UP_HOLD
                && now.duration_since(self.last_shift) >= MIN_SHIFT_GAP
            {
                self.current_idx += 1;
                self.above_since = None;
                self.last_shift = now;
                return BweDecision::Upshift(self.current_rung());
            }
            return BweDecision::Hold;
        }

        self.below_since = None;
        self.above_since = None;
        BweDecision::Hold
    }

    fn can_downshift(&self) -> bool {
        self.current_idx > self.floor_idx
    }

    fn can_upshift(&self) -> bool {
        self.current_idx < self.cap_idx
    }
}

fn down_threshold(rung: EncoderRung) -> u64 {
    if rung.max_width >= 1080 {
        DOWN_THRESHOLD_1080_BPS
    } else {
        // Floor rung — observe() never downshifts from index 0.
        0
    }
}

fn up_threshold(next: EncoderRung) -> u64 {
    (u64::from(next.bitrate) * 4) / 5
}

/// What a video-pump EOF should do. Recovery / BWE already cancel the
/// encoder generation; those EOFs must not tear the PeerConnection down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderEofAction {
    Ignore,
    RestartKeepPc,
}

/// If a BWE (or other) downshift dies before the first keyframe, restart
/// at the SKU cap instead of looping the crashing lower rung. `live_width`
/// is the encoder that just died; `cap_width` is the SKU / viewport ceiling.
pub fn revert_rung_after_failed_generation(
    keyframes: u64,
    live_width: u32,
    cap_width: u32,
) -> Option<EncoderRung> {
    if keyframes > 0 {
        return None;
    }
    let live_idx = rung_index_for_width(live_width);
    let cap_idx = rung_index_for_width(cap_width);
    if live_idx >= cap_idx {
        return None;
    }
    Some(LADDER[cap_idx])
}

pub fn video_eof_action(restarting: bool, generation_matches: bool) -> EncoderEofAction {
    if restarting || !generation_matches {
        EncoderEofAction::Ignore
    } else {
        EncoderEofAction::RestartKeepPc
    }
}

/// Recovery watchdog `Rebuild` used to call `Session::shutdown()` and
/// drop the PC. Stream Protocol v1 restarts only the encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderRestartKind {
    KeepPeerConnection,
}

pub fn encoder_restart_kind() -> EncoderRestartKind {
    EncoderRestartKind::KeepPeerConnection
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn width_720_is_floor_rung() {
        assert_eq!(rung_index_for_width(720), 0);
        assert_eq!(rung_index_for_width(480), 0);
    }

    #[test]
    fn width_1080_is_top_rung() {
        assert_eq!(rung_index_for_width(1080), 1);
        assert_eq!(rung_index_for_width(1920), 1);
    }

    #[test]
    fn combine_picks_minimum_positive_send_or_receive() {
        assert_eq!(
            combine_estimates(Some(4_000_000), Some(3_000_000), 1_200_000),
            Some(1_200_000)
        );
        assert_eq!(combine_estimates(Some(0), None, 0), None);
        assert_eq!(combine_estimates(None, Some(2_500_000), 0), Some(2_500_000));
        // TURN-TCP ICE TWCC ~0.5 Mbps must not veto a healthy send rate,
        // and must not downshift when it is the only sample.
        assert_eq!(
            combine_estimates(Some(518_000), Some(3_000_000), 0),
            Some(3_000_000)
        );
        assert_eq!(combine_estimates(Some(518_000), None, 0), None);
    }

    #[test]
    fn downshift_1080_after_hold() {
        let start = t0();
        let mut ctl = BweController::new(1080, 1080, start);
        assert_eq!(ctl.observe(Some(1_000_000), start), BweDecision::Hold);
        assert_eq!(
            ctl.observe(Some(1_000_000), start + Duration::from_secs(2)),
            BweDecision::Hold
        );
        match ctl.observe(Some(1_000_000), start + Duration::from_secs(3)) {
            BweDecision::Downshift(rung) => {
                assert_eq!(rung, RUNG_720);
            }
            other => panic!("expected downshift, got {other:?}"),
        }
    }

    #[test]
    fn no_downshift_on_brief_dip() {
        let start = t0();
        let mut ctl = BweController::new(1080, 1080, start);
        assert_eq!(ctl.observe(Some(1_000_000), start), BweDecision::Hold);
        assert_eq!(
            ctl.observe(Some(4_000_000), start + Duration::from_secs(1)),
            BweDecision::Hold
        );
        assert_eq!(ctl.current_rung(), RUNG_1080);
    }

    #[test]
    fn floor_rung_never_downshifts() {
        let start = t0();
        let mut ctl = BweController::new(1080, 720, start);
        assert_eq!(
            ctl.observe(Some(100_000), start + Duration::from_secs(30)),
            BweDecision::Hold
        );
        assert_eq!(ctl.current_rung(), RUNG_720);
    }

    #[test]
    fn sku_cap_blocks_upshift() {
        let start = t0();
        let mut ctl = BweController::new(720, 720, start);
        assert_eq!(
            ctl.observe(Some(8_000_000), start + Duration::from_secs(30)),
            BweDecision::Hold
        );
        assert_eq!(ctl.current_rung(), RUNG_720);
    }

    #[test]
    fn set_cap_clamps_live_rung() {
        let start = t0();
        let mut ctl = BweController::new(1080, 1080, start);
        ctl.set_cap(720);
        assert_eq!(ctl.current_rung(), RUNG_720);
        assert_eq!(
            ctl.observe(Some(8_000_000), start + Duration::from_secs(30)),
            BweDecision::Hold
        );
    }

    #[test]
    fn upshift_requires_long_hysteresis() {
        let start = t0();
        let mut ctl = BweController::new(1080, 720, start);
        assert_eq!(
            ctl.observe(Some(4_000_000), start + Duration::from_secs(5)),
            BweDecision::Hold
        );
        // above_since armed at +5s; UP_HOLD is 10s.
        match ctl.observe(Some(4_000_000), start + Duration::from_secs(15)) {
            BweDecision::Upshift(rung) => assert_eq!(rung, RUNG_1080),
            other => panic!("expected upshift, got {other:?}"),
        }
    }

    #[test]
    fn min_gap_prevents_flap() {
        let start = t0();
        let mut ctl = BweController::new(1080, 1080, start);
        let down_at = start + DOWN_HOLD;
        assert!(matches!(
            ctl.observe(Some(1_000_000), start),
            BweDecision::Hold
        ));
        assert!(matches!(
            ctl.observe(Some(1_000_000), down_at),
            BweDecision::Downshift(_)
        ));
        // Immediately healthy again — upshift must wait MIN_SHIFT_GAP + UP_HOLD.
        assert_eq!(
            ctl.observe(Some(4_000_000), down_at + Duration::from_secs(1)),
            BweDecision::Hold
        );
        assert_eq!(ctl.current_rung(), RUNG_720);
    }

    #[test]
    fn apply_rung_clears_long_edge_override() {
        let mut cfg = ScrcpyServerConfig {
            max_width: 1080,
            bitrate: 4_000_000,
            scrcpy_max_size: Some(1920),
            ..ScrcpyServerConfig::default()
        };
        RUNG_720.apply(&mut cfg);
        assert_eq!(cfg.max_width, 720);
        assert_eq!(cfg.bitrate, 2_500_000);
        assert_eq!(cfg.scrcpy_max_size, None);
        assert_eq!(cfg.resolved_max_size(), 1280);
    }

    #[test]
    fn eof_during_restart_is_ignored() {
        assert_eq!(video_eof_action(true, true), EncoderEofAction::Ignore);
        assert_eq!(video_eof_action(false, false), EncoderEofAction::Ignore);
        assert_eq!(
            video_eof_action(false, true),
            EncoderEofAction::RestartKeepPc
        );
    }

    #[test]
    fn encoder_restart_keeps_peer() {
        assert_eq!(
            encoder_restart_kind(),
            EncoderRestartKind::KeepPeerConnection
        );
    }

    #[test]
    fn failed_720_generation_reverts_to_1080_cap() {
        assert_eq!(
            revert_rung_after_failed_generation(0, 720, 1080),
            Some(RUNG_1080)
        );
        assert_eq!(revert_rung_after_failed_generation(1, 720, 1080), None);
        assert_eq!(revert_rung_after_failed_generation(0, 1080, 1080), None);
        assert_eq!(revert_rung_after_failed_generation(0, 720, 720), None);
    }

    #[test]
    fn lock_rung_blocks_immediate_downshift() {
        let start = t0();
        let mut ctl = BweController::new(1080, 1080, start);
        ctl.lock_rung(start);
        assert_eq!(
            ctl.observe(Some(1_000_000), start + DOWN_HOLD),
            BweDecision::Hold
        );
        match ctl.observe(Some(1_000_000), start + MIN_SHIFT_GAP + DOWN_HOLD) {
            BweDecision::Downshift(rung) => assert_eq!(rung, RUNG_720),
            other => panic!("expected downshift after gap, got {other:?}"),
        }
    }

    #[test]
    fn set_floor_bans_720_after_failed_downshift() {
        let start = t0();
        let mut ctl = BweController::new(1080, 1080, start);
        assert!(matches!(
            ctl.observe(Some(1_000_000), start),
            BweDecision::Hold
        ));
        assert!(matches!(
            ctl.observe(Some(1_000_000), start + DOWN_HOLD),
            BweDecision::Downshift(_)
        ));
        assert_eq!(ctl.current_rung(), RUNG_720);
        ctl.set_floor(1080);
        assert_eq!(ctl.current_rung(), RUNG_1080);
        assert_eq!(
            ctl.observe(Some(100_000), start + Duration::from_secs(30)),
            BweDecision::Hold
        );
        assert_eq!(ctl.current_rung(), RUNG_1080);
    }
}
