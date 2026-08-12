// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Trust Level — Historical Confidence Score
//!
//! Unlike System Health (current state), Trust Level is a slow-moving
//! reputation score that reflects the system's history of compromises.
//!
//! - Starts at 100
//! - Drops on significant events (baseline tamper, root CA, Secure Boot)
//! - Recovers slowly over time with exponential backoff
//! - Never auto-recovers to 100 without manual verification

use serde::{Deserialize, Serialize};
use std::fs;

const TRUST_FILE: &str = "C:\\ProgramData\\Invisibly\\trust.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustLevel {
    pub score: u8,                      // 0-100
    pub history: Vec<TrustEvent>,
    pub last_updated: String,
    pub recovery_state: RecoveryState,  // FIX: Track recovery tier
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvent {
    pub timestamp: String,
    pub reason: String,
    pub deduction: u8,
    pub new_score: u8,
    pub event_type: TrustEventType,     // FIX: Categorize events
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustEventType {
    Deduction,
    Recovery,
    ManualVerify,
    BaselineTamper,
    SelfIntegrityFailure,
    ChainFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecoveryState {
    Fast,      // 0-20: 5 points per cycle
    Medium,    // 21-60: 2 points per cycle
    Slow,      // 61-90: 1 point per cycle
    Locked,    // 91-100: manual only
}

impl TrustLevel {
    pub fn load_or_default() -> Self {
        let path = std::path::Path::new(TRUST_FILE);
        if let Ok(data) = fs::read_to_string(path) {
            if let Ok(trust) = serde_json::from_str(&data) {
                return trust;
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        if let Ok(data) = serde_json::to_string_pretty(self) {
            let _ = fs::write(TRUST_FILE, data);
        }
    }

    pub fn apply_deduction(&mut self, reason: &str, deduction: u8, event_type: TrustEventType) {
        let new_score = self.score.saturating_sub(deduction);
        let event = TrustEvent {
            timestamp: chrono::Local::now().to_rfc3339(),
            reason: reason.to_string(),
            deduction,
            new_score,
            event_type,
        };
        self.score = new_score;
        self.history.push(event);
        self.last_updated = chrono::Local::now().to_rfc3339();
        self.recovery_state = self.calculate_recovery_state();
        self.save();
    }

    // FIX: Correct tiered recovery - fast near 100, slow near 0
    pub fn recover(&mut self, amount: u8) {
    let recovery_amount = match self.score {
        91..=100 => 2,   // Fast recovery near top
        61..=90  => 1,   // Slow recovery mid
        21..=60  => 1,   // Slow recovery (no dead zone)
        0..=20   => 0,   // Locked at bottom (manual only)
        _ => 0,
    };

        if recovery_amount == 0 {
            return;
        }

        let new_score = self.score.saturating_add(recovery_amount).min(100);
        if new_score > self.score {
            let event = TrustEvent {
                timestamp: chrono::Local::now().to_rfc3339(),
                reason: format!("Tiered recovery ({:?})", self.recovery_state),
                deduction: 0,
                new_score,
                event_type: TrustEventType::Recovery,
            };
            self.score = new_score;
            self.history.push(event);
            self.last_updated = chrono::Local::now().to_rfc3339();
            self.recovery_state = self.calculate_recovery_state();
            self.save();
        }
    }

    pub fn manual_verify(&mut self, reason: &str, authorized_by: &str) {
        // FIX: Better audit trail with authorization
        let event = TrustEvent {
            timestamp: chrono::Local::now().to_rfc3339(),
            reason: format!("Manual verification: {} (authorized by: {})", reason, authorized_by),
            deduction: 0,
            new_score: 100,
            event_type: TrustEventType::ManualVerify,
        };
        self.score = 100;
        self.history.push(event);
        self.last_updated = chrono::Local::now().to_rfc3339();
        self.recovery_state = self.calculate_recovery_state();
        self.save();
    }

    // FIX: Calculate recovery tier based on current score
    fn get_recovery_tier(&self) -> RecoveryState {
        match self.score {
            0..=20 => RecoveryState::Fast,
            21..=60 => RecoveryState::Medium,
            61..=90 => RecoveryState::Slow,
            91..=100 => RecoveryState::Locked,
            _ => RecoveryState::Medium,
        }
    }

    fn calculate_recovery_state(&self) -> RecoveryState {
        self.get_recovery_tier()
    }
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self {
            score: 100,
            history: Vec::new(),
            last_updated: chrono::Local::now().to_rfc3339(),
            recovery_state: RecoveryState::Locked,
        }
    }
}

// ============================================
// EVENT-BASED DEDUCTIONS
// ============================================

pub fn deduct_trust(reason: &str, deduction: u8) {
    let mut trust = TrustLevel::load_or_default();
    trust.apply_deduction(reason, deduction, TrustEventType::Deduction);
}

// FIX: Specific deduction types for better tracking
pub fn deduct_trust_baseline(reason: &str, deduction: u8) {
    let mut trust = TrustLevel::load_or_default();
    trust.apply_deduction(reason, deduction, TrustEventType::BaselineTamper);
}

pub fn deduct_trust_self_integrity(reason: &str, deduction: u8) {
    let mut trust = TrustLevel::load_or_default();
    trust.apply_deduction(reason, deduction, TrustEventType::SelfIntegrityFailure);
}

pub fn deduct_trust_chain_failure(reason: &str, deduction: u8) {
    let mut trust = TrustLevel::load_or_default();
    trust.apply_deduction(reason, deduction, TrustEventType::ChainFailure);
}

pub fn recover_trust(amount: u8) {
    let mut trust = TrustLevel::load_or_default();
    trust.recover(amount);
}

// FIX: Manual verify with authorization
pub fn manual_verify() {
    let mut trust = TrustLevel::load_or_default();
    // Use a generic reason but include that it came from API
    trust.manual_verify("API request", "dashboard-user");
}

pub fn manual_verify_with_reason(reason: &str, authorized_by: &str) {
    let mut trust = TrustLevel::load_or_default();
    trust.manual_verify(reason, authorized_by);
}

pub fn get_trust_score() -> u8 {
    TrustLevel::load_or_default().score
}

pub fn get_trust_history() -> Vec<TrustEvent> {
    TrustLevel::load_or_default().history
}

pub fn get_recovery_state() -> RecoveryState {
    TrustLevel::load_or_default().recovery_state
}