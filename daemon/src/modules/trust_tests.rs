// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Trust Module Tests
//!
//! Covers the two regressions found in review: recovery being locked at the
//! bottom band (score stuck at 0 forever) and manual_verify not composing
//! correctly with tiered recovery.
//!
//! Note: TrustLevel::save() writes to the real C:\ProgramData\Invisibly\trust.json
//! path (no injectable path in the current design), so these tests have a real
//! but harmless disk side effect - they assert on the in-memory struct, not the file.

#[cfg(test)]
mod tests {
    use super::super::trust::*;

    #[test]
    fn test_recover_from_zero_is_not_locked() {
        let mut trust = TrustLevel {
            score: 0,
            history: vec![],
            last_updated: String::new(),
            recovery_state: RecoveryState::Fast,
        };
        trust.recover(0);
        assert!(trust.score > 0, "score stuck at 0 after recover() - the exact regression this test guards against");
    }

    #[test]
    fn test_recovery_is_faster_near_bottom_than_near_top() {
        let mut low = TrustLevel {
            score: 10,
            history: vec![],
            last_updated: String::new(),
            recovery_state: RecoveryState::Fast,
        };
        let mut high = TrustLevel {
            score: 95,
            history: vec![],
            last_updated: String::new(),
            recovery_state: RecoveryState::Locked,
        };
        low.recover(0);
        high.recover(0);
        let low_gain = low.score - 10;
        let high_gain = high.score - 95;
        assert!(low_gain > high_gain, "recovery near 0 ({}) should be faster than recovery near 100 ({})", low_gain, high_gain);
    }

    #[test]
    fn test_recover_never_exceeds_100() {
        let mut trust = TrustLevel {
            score: 99,
            history: vec![],
            last_updated: String::new(),
            recovery_state: RecoveryState::Locked,
        };
        trust.recover(0);
        assert!(trust.score <= 100);
    }

    #[test]
    fn test_deduction_saturates_at_zero() {
        let mut trust = TrustLevel {
            score: 5,
            history: vec![],
            last_updated: String::new(),
            recovery_state: RecoveryState::Fast,
        };
        trust.apply_deduction("test deduction larger than remaining score", 50, TrustEventType::Deduction);
        assert_eq!(trust.score, 0, "deduction should saturate at 0, not underflow");
    }

    #[test]
    fn test_manual_verify_sets_100_from_any_score() {
        let mut trust = TrustLevel {
            score: 0,
            history: vec![],
            last_updated: String::new(),
            recovery_state: RecoveryState::Fast,
        };
        trust.manual_verify("test", "unit-test");
        assert_eq!(trust.score, 100);
    }
}
