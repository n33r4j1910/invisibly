// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Policy Engine — Context-aware deductions and rules
//!
//! Applies contextual logic to severity deductions.
//! Example: VPN disconnected on public WiFi = high deduction.
//! VPN disconnected at home = no deduction.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================
// TYPES
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub is_public_wifi: bool,
    pub is_vpn_connected: bool,
    pub is_home_network: bool,
    pub is_locked_down: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub category: String,
    pub condition: String,
    pub severity: String,
    pub deduction: u8,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub deduction: u8,
    pub reason: String,
}

// ============================================
// CONTEXT DETECTION
// ============================================

pub fn detect_context() -> PolicyContext {
    let wifi_profile = crate::detect::get_wifi_profile_status();
    let vpn_status = crate::detect::get_vpn_status();
    let home_ssid = crate::config::load_home_ssid().unwrap_or_else(|| "Unknown".into());
    let current_ssid = crate::detect::get_wifi();
    let is_locked_down = crate::repair::is_ghost_active();

    PolicyContext {
        is_public_wifi: wifi_profile == "PUBLIC",
        is_vpn_connected: vpn_status == "CONNECTED",
        is_home_network: current_ssid == home_ssid,
        is_locked_down,
    }
}

// ============================================
// POLICY EVALUATION
// ============================================

pub fn evaluate(category: &str, context: &PolicyContext) -> PolicyResult {
    match category {
        "vpn" => evaluate_vpn(context),
        "wifi_profile" => evaluate_wifi_profile(context),
        "firewall" => evaluate_firewall(context),
        "defender" => evaluate_defender(context),
        _ => PolicyResult {
            deduction: 0,
            reason: "No policy applied".to_string(),
        },
    }
}

// ============================================
// SPECIFIC POLICY EVALUATORS
// ============================================

fn evaluate_vpn(context: &PolicyContext) -> PolicyResult {
    if context.is_public_wifi && !context.is_vpn_connected {
        // VPN disconnected on public WiFi → HIGH deduction
        PolicyResult {
            deduction: 12,
            reason: "VPN disconnected on public WiFi — traffic exposed".to_string(),
        }
    } else if context.is_public_wifi && context.is_vpn_connected {
        PolicyResult {
            deduction: 0,
            reason: "VPN connected on public WiFi — traffic protected".to_string(),
        }
    } else if context.is_home_network && !context.is_vpn_connected {
        PolicyResult {
            deduction: 0,
            reason: "No VPN needed on trusted home network".to_string(),
        }
    } else {
        PolicyResult {
            deduction: 0,
            reason: "VPN status normal".to_string(),
        }
    }
}

fn evaluate_wifi_profile(context: &PolicyContext) -> PolicyResult {
    if context.is_public_wifi {
        // Public WiFi on public network → LOW deduction
        PolicyResult {
            deduction: 2,
            reason: "WiFi profile is Public — device is discoverable".to_string(),
        }
    } else if context.is_public_wifi && !context.is_home_network {
        PolicyResult {
            deduction: 2,
            reason: "WiFi profile is Public — device is discoverable".to_string(),
        }
    } else {
        PolicyResult {
            deduction: 0,
            reason: "WiFi profile is Private — device hidden".to_string(),
        }
    }
}

fn evaluate_firewall(context: &PolicyContext) -> PolicyResult {
    // Firewall disabled is ALWAYS critical regardless of context
    PolicyResult {
        deduction: 20,
        reason: "Firewall is disabled — system exposed".to_string(),
    }
}

fn evaluate_defender(context: &PolicyContext) -> PolicyResult {
    // Defender disabled is ALWAYS critical regardless of context
    PolicyResult {
        deduction: 20,
        reason: "Windows Defender is disabled — no real-time protection".to_string(),
    }
}

// ============================================
// BATCH EVALUATION
// ============================================

pub fn evaluate_batch(categories: &[String], context: &PolicyContext) -> HashMap<String, PolicyResult> {
    let mut results = HashMap::new();
    for category in categories {
        let result = evaluate(category, context);
        if result.deduction > 0 {
            results.insert(category.clone(), result);
        }
    }
    results
}