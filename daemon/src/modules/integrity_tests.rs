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
        // Create many critical issues to exceed 100 deduction
        let mut issues = vec![];
        for _ in 0..10 {
            issues.push(("firewall".to_string(), "Firewall changed: OFF".to_string()));
        }
        let report = calculate(&issues, false, true);
        assert_eq!(report.score, 0);
    }
}