// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Integrity Module Tests

#[cfg(test)]
mod tests {
    use super::super::integrity::*;

    #[test]
    fn test_healthy_state_returns_100() {
        let issues = vec![];
        let report = calculate(&issues, false, true);
        assert_eq!(report.score, 100);
        assert_eq!(report.state, IntegrityState::Maintained);
        assert!(report.deductions.is_empty());
    }

    #[test]
    fn test_dns_change_deducts_correctly() {
        let issues = vec![("dns".to_string(), "DNS changed".to_string())];
        let report = calculate(&issues, false, true);
        // DNS is High severity = -12 points
        assert_eq!(report.score, 88);
        assert_eq!(report.state, IntegrityState::DriftDetected);
        assert_eq!(report.deductions.len(), 1);
        assert_eq!(report.deductions[0].points, 12);
    }

    #[test]
    fn test_firewall_disabled_deducts_correctly() {
        let issues = vec![("firewall".to_string(), "Firewall changed: OFF".to_string())];
        let report = calculate(&issues, false, true);
        // Firewall is Critical = -20 points
        assert_eq!(report.score, 80);
        assert_eq!(report.state, IntegrityState::Compromised);
        assert_eq!(report.deductions.len(), 1);
        assert_eq!(report.deductions[0].points, 20);
    }

    #[test]
    fn test_multiple_issues_deduct_correctly() {
        let issues = vec![
            ("dns".to_string(), "DNS changed".to_string()),
            ("firewall".to_string(), "Firewall changed: OFF".to_string()),
        ];
        let report = calculate(&issues, false, true);
        // DNS: -12, Firewall: -20 = -32 total → 68
        assert_eq!(report.score, 68);
        assert_eq!(report.state, IntegrityState::Compromised);
        assert_eq!(report.deductions.len(), 2);
    }

    #[test]
    fn test_lockdown_state_returns_100() {
        let issues = vec![("dns".to_string(), "DNS changed".to_string())];
        let report = calculate(&issues, true, true);
        // Lockdown always returns 100, regardless of issues
        assert_eq!(report.score, 100);
        assert_eq!(report.state, IntegrityState::Lockdown);
        assert!(report.deductions.is_empty());
    }

    #[test]
    fn test_invalid_baseline_returns_0() {
        let issues = vec![("dns".to_string(), "DNS changed".to_string())];
        let report = calculate(&issues, false, false);
        // Invalid baseline always returns 0
        assert_eq!(report.score, 0);
        assert_eq!(report.state, IntegrityState::Invalid);
        assert_eq!(report.deductions.len(), 1);
        assert_eq!(report.deductions[0].points, 100);
    }

    #[test]
    fn test_score_capped_at_zero() {
        // FIX: calculate() evaluates each category once regardless of how many
        // duplicate raw entries reference it, so repeating "firewall" 10x never
        // exceeded 100. Use 6 distinct Critical-severity categories instead
        // (20 pts each = 120 total) to actually exercise the >100 cap.
        let issues = vec![
            ("firewall".to_string(), "Firewall changed: OFF".to_string()),
            ("defender".to_string(), "OFF".to_string()),
            ("uac".to_string(), "UAC changed: OFF".to_string()),
            ("wu".to_string(), "Windows Update changed: OFF".to_string()),
            ("sr".to_string(), "OFF".to_string()),
            ("smartscreen".to_string(), "SmartScreen changed: OFF".to_string()),
        ];
        let report = calculate(&issues, false, true);
        assert_eq!(report.score, 0);
    }

    // ============================================
    // Regression tests for this session's scoring fixes
    // ============================================

    #[test]
    fn test_error_sentinel_does_not_deduct() {
        // A detection FAILURE must never be scored like a real compromise.
        // (It still logs a zero-point entry so the reason is visible on the dashboard.)
        let issues = vec![("dns".to_string(), "ERROR_DNS_DETECTION_FAILED".to_string())];
        let report = calculate(&issues, false, true);
        assert_eq!(report.score, 100);
        assert!(report.deductions.iter().all(|d| d.points == 0));
    }

    #[test]
    fn test_error_sentinel_on_formerly_medium_category_does_not_deduct() {
        let issues = vec![("vpn".to_string(), "ERROR_VPN_DETECTION_FAILED".to_string())];
        let report = calculate(&issues, false, true);
        assert_eq!(report.score, 100);
        assert!(report.deductions.iter().all(|d| d.points == 0));
    }

    #[test]
    fn test_arp_error_sentinel_does_not_deduct() {
        let issues = vec![("arp".to_string(), "ERROR_ARP_DETECTION_FAILED".to_string())];
        let report = calculate(&issues, false, true);
        assert_eq!(report.score, 100);
        assert!(report.deductions.iter().all(|d| d.points == 0));
    }

    #[test]
    fn test_arp_change_is_low_severity_not_high() {
        // ARP cache churns naturally during normal network use - it must not
        // be weighted the same as a real compromised control (was -12, now -2).
        let issues = vec![("arp".to_string(), "ARP table changed".to_string())];
        let report = calculate(&issues, false, true);
        assert_eq!(report.score, 98);
        assert_eq!(report.deductions[0].points, 2);
    }
}