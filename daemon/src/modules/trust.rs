// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Trust Level — Historical Confidence Score
//!
//! Unlike System Health (current state), Trust Level is a slow-moving
//! reputation score that reflects the system's history of compromises.
//!
//! - Starts at 100
//! - Drops on significant events (baseline tamper, root CA, Secure Boot)
//! - Recovers slowly over time
//! - Never auto-recovers to 100 without manual verification

use serde::{Deserialize, Serialize};
use std::fs;

const TRUST_FILE: &str = "C:\\ProgramData\\Invisibly\\trust.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustLevel {
    pub score: u8,                      // 0-100
    pub history: Vec<TrustEvent>,
    pub last_updated: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvent {
    pub timestamp: String,
    pub reason: String,
    pub deduction: u8,
    pub new_score: u8,
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

    // FIX #23: Use saturating_sub to prevent underflow
    pub fn apply_deduction(&mut self, reason: &str, deduction: u8) {
        // Use saturating_sub to prevent underflow (score can't go below 0)
        let new_score = self.score.saturating_sub(deduction);
        let event = TrustEvent {
            timestamp: chrono::Local::now().to_rfc3339(),
            reason: reason.to_string(),
            deduction,
            new_score,
        };
        self.score = new_score;
        self.history.push(event);
        self.last_updated = chrono::Local::now().to_rfc3339();
        self.save();
    }

    // FIX #23: Use saturating_add and min to prevent overflow
    pub fn recover(&mut self, amount: u8) {
        // Use saturating_add to prevent overflow, then clamp to 100
        let new_score = self.score.saturating_add(amount).min(100);
        if new_score > self.score {
            let event = TrustEvent {
                timestamp: chrono::Local::now().to_rfc3339(),
                reason: "Gradual recovery".to_string(),
                deduction: 0,
                new_score,
            };
            self.score = new_score;
            self.history.push(event);
            self.last_updated = chrono::Local::now().to_rfc3339();
            self.save();
        }
    }

    pub fn manual_verify(&mut self) {
        let new_score = 100;
        let event = TrustEvent {
            timestamp: chrono::Local::now().to_rfc3339(),
            reason: "Manual verification".to_string(),
            deduction: 0,
            new_score,
        };
        self.score = new_score;
        self.history.push(event);
        self.last_updated = chrono::Local::now().to_rfc3339();
        self.save();
    }
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self {
            score: 100,
            history: Vec::new(),
            last_updated: chrono::Local::now().to_rfc3339(),
        }
    }
}

// ============================================
// EVENT-BASED DEDUCTIONS
// ============================================

pub fn deduct_trust(reason: &str, deduction: u8) {
    let mut trust = TrustLevel::load_or_default();
    trust.apply_deduction(reason, deduction);
}

pub fn recover_trust(amount: u8) {
    let mut trust = TrustLevel::load_or_default();
    trust.recover(amount);
}

pub fn manual_verify() {
    let mut trust = TrustLevel::load_or_default();
    trust.manual_verify();
}

pub fn get_trust_score() -> u8 {
    TrustLevel::load_or_default().score
}