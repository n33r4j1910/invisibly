// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Integrity Score & State Machine
//!
//! Calculates a weighted score (0–100) based on current system state.
//! Manages system states: Maintained, Drift Detected, Compromised, Lockdown, Invalid.
//!
//! IMPORTANT: Score is calculated from CURRENT STATE, not from detected issues.
//! This ensures that after a repair, the score reflects the healthy state.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";

// ============================================
// TYPES
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityState {
    Maintained,      // Everything is secure
    DriftDetected,   // Non-critical changes
    Compromised,     // Critical security issues
    Lockdown,        // Ghost Mode active
    Invalid,         // Baseline tampered — requires manual action
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub score: u8,                        // 0–100
    pub state: IntegrityState,
    pub control_status: HashMap<String, ControlStatus>,
    pub deductions: Vec<Deduction>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStatus {
    pub status: Status,
    pub reason: String,
    pub severity: Severity,
    pub weight: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Status {
    Healthy,
    Warning,
    Compromised,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deduction {
    pub category: String,
    pub severity: Severity,
    pub points: u8,
    pub reason: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,   // -20 points
    High,       // -12 points
    Medium,     // -6 points
    Low,        // -2 points
    None,       // 0 points
}

// ============================================
// WEIGHTS (Configurable) — FIX #11: Now actually used
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityWeights {
    pub critical: u8,   // default: 20
    pub high: u8,       // default: 12
    pub medium: u8,     // default: 6
    pub low: u8,        // default: 2
}

impl Default for IntegrityWeights {
    fn default() -> Self {
        Self {
            critical: 20,
            high: 12,
            medium: 6,
            low: 2,
        }
    }
}

impl IntegrityWeights {
    pub fn load() -> Self {
        let path = format!("{}\\weights.json", DATA_DIR);
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(weights) = serde_json::from_str::<IntegrityWeights>(&data) {
                // FIX #13: Clamp weights on load to prevent overflow
                return Self {
                    critical: weights.critical.min(100),
                    high: weights.high.min(100),
                    medium: weights.medium.min(100),
                    low: weights.low.min(100),
                };
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        let path = format!("{}\\weights.json", DATA_DIR);
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(&path, json);
        }
    }
}

// ============================================
// CONTEXT RULES (Policy-based deduction)
// ============================================

#[derive(Debug, Clone)]
pub struct Context {
    pub is_public_wifi: bool,
    pub is_vpn_connected: bool,
    pub is_home_network: bool,
}

impl Context {
    pub fn detect() -> Self {
        let wifi_profile = crate::detect::get_wifi_profile_status();
        let vpn_status = crate::detect::get_vpn_status();
        let home_ssid = crate::config::load_home_ssid().unwrap_or_else(|| "Unknown".into());
        let current_ssid = crate::detect::get_wifi();

        Self {
            is_public_wifi: wifi_profile == "PUBLIC",
            is_vpn_connected: vpn_status == "CONNECTED",
            is_home_network: current_ssid == home_ssid,
        }
    }

    pub fn deduction_multiplier(&self, category: &str) -> u8 {
        match category {
            "vpn" => {
                if self.is_public_wifi && !self.is_vpn_connected {
                    3 // VPN on public WiFi → high deduction
                } else if self.is_home_network && !self.is_vpn_connected {
                    0 // No VPN needed at home
                } else {
                    1
                }
            }
            "wifi_profile" => {
                if self.is_public_wifi {
                    2 // Public WiFi on public network → low deduction
                } else {
                    0 // Public WiFi at home → no deduction
                }
            }
            _ => 1,
        }
    }
}

// ============================================
// INTEGRITY SCORE CALCULATOR
// ============================================

pub fn calculate(
    issues: &[(String, String)],
    is_lockdown: bool,
    is_baseline_valid: bool,
) -> IntegrityReport {
    // If baseline is invalid → immediate Invalid state
    if !is_baseline_valid {
        return IntegrityReport {
            score: 0,
            state: IntegrityState::Invalid,
            control_status: HashMap::new(),
            deductions: vec![Deduction {
                category: "baseline".to_string(),
                severity: Severity::Critical,
                points: 100,
                reason: "Baseline integrity check failed".to_string(),
                context: "Baseline has been tampered with. Manual approval required.".to_string(),
            }],
            timestamp: chrono::Local::now().to_rfc3339(),
        };
    }

    // If Lockdown is active → Lockdown state
    if is_lockdown {
        return IntegrityReport {
            score: 100,
            state: IntegrityState::Lockdown,
            control_status: HashMap::new(),
            deductions: vec![],
            timestamp: chrono::Local::now().to_rfc3339(),
        };
    }

    let weights = IntegrityWeights::load();
    let context = Context::detect();
    let mut total_deduction: u16 = 0;
    let mut deductions: Vec<Deduction> = Vec::new();
    let mut control_status: HashMap<String, ControlStatus> = HashMap::new();

    // ============================================
    // EVALUATE EACH CONTROL FROM STATE
    // ============================================

    // 1. Firewall
    let firewall_status = get_firewall_status(issues);
    control_status.insert("firewall".to_string(), firewall_status.clone());
    if firewall_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "firewall", &firewall_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 2. Defender
    let defender_status = get_defender_status(issues);
    control_status.insert("defender".to_string(), defender_status.clone());
    if defender_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "defender", &defender_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 3. DNS
    let dns_status = get_dns_status(issues);
    control_status.insert("dns".to_string(), dns_status.clone());
    if dns_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "dns", &dns_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 4. Hosts
    let hosts_status = get_hosts_status(issues);
    control_status.insert("hosts".to_string(), hosts_status.clone());
    if hosts_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "hosts", &hosts_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 5. Proxy
    let proxy_status = get_proxy_status(issues);
    control_status.insert("proxy".to_string(), proxy_status.clone());
    if proxy_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "proxy", &proxy_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 6. UAC
    let uac_status = get_uac_status(issues);
    control_status.insert("uac".to_string(), uac_status.clone());
    if uac_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "uac", &uac_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 7. Windows Update
    let wu_status = get_windows_update_status(issues);
    control_status.insert("wu".to_string(), wu_status.clone());
    if wu_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "wu", &wu_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 8. System Restore
    let sr_status = get_system_restore_status(issues);
    control_status.insert("sr".to_string(), sr_status.clone());
    if sr_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "sr", &sr_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 9. SmartScreen
    let smartscreen_status = get_smart_screen_status(issues);
    control_status.insert("smartscreen".to_string(), smartscreen_status.clone());
    if smartscreen_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "smartscreen", &smartscreen_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 10. VPN
    let vpn_status = get_vpn_status(issues);
    control_status.insert("vpn".to_string(), vpn_status.clone());
    if vpn_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "vpn", &vpn_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 11. IPv6
    let ipv6_status = get_ipv6_status(issues);
    control_status.insert("ipv6".to_string(), ipv6_status.clone());
    if ipv6_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "ipv6", &ipv6_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 12. WiFi Profile
    let wifi_profile_status = get_wifi_profile_status(issues);
    control_status.insert("wifi_profile".to_string(), wifi_profile_status.clone());
    if wifi_profile_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "wifi_profile", &wifi_profile_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 13. DoH
    let doh_status = get_doh_status(issues);
    control_status.insert("doh".to_string(), doh_status.clone());
    if doh_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "doh", &doh_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 14. LAPS
    let laps_status = get_laps_status(issues);
    control_status.insert("laps".to_string(), laps_status.clone());
    if laps_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "laps", &laps_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 15. Secure Boot
    let secureboot_status = get_secure_boot_status(issues);
    control_status.insert("secureboot".to_string(), secureboot_status.clone());
    if secureboot_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "secureboot", &secureboot_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 16. Startup
    let startup_status = get_startup_status(issues);
    control_status.insert("startup".to_string(), startup_status.clone());
    if startup_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "startup", &startup_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 17. Services
    let services_status = get_services_status(issues);
    control_status.insert("services".to_string(), services_status.clone());
    if services_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "services", &services_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 18. Devices
    let devices_status = get_devices_status(issues);
    control_status.insert("devices".to_string(), devices_status.clone());
    if devices_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "devices", &devices_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 19. DHCP
    let dhcp_status = get_dhcp_status(issues);
    control_status.insert("dhcp".to_string(), dhcp_status.clone());
    if dhcp_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "dhcp", &dhcp_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 20. BitLocker
    let bitlocker_status = get_bitlocker_status(issues);
    control_status.insert("bitlocker".to_string(), bitlocker_status.clone());
    if bitlocker_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "bitlocker", &bitlocker_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 21. Credential Guard
    let credguard_status = get_credential_guard_status(issues);
    control_status.insert("credguard".to_string(), credguard_status.clone());
    if credguard_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "credguard", &credguard_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 22. RDP
    let rdp_status = get_rdp_status(issues);
    control_status.insert("rdp".to_string(), rdp_status.clone());
    if rdp_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "rdp", &rdp_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // ============================================
    // NEW: ADDITIONAL CATEGORY EVALUATORS
    // ============================================

    // 23. Brute Force
    let bruteforce_status = get_bruteforce_status(issues);
    control_status.insert("bruteforce".to_string(), bruteforce_status.clone());
    if bruteforce_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "bruteforce", &bruteforce_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 24. Trojan Source
    let trojan_status = get_trojan_source_status(issues);
    control_status.insert("trojan_source".to_string(), trojan_status.clone());
    if trojan_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "trojan_source", &trojan_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 25. HID Devices
    let hid_status = get_hid_status(issues);
    control_status.insert("hid".to_string(), hid_status.clone());
    if hid_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "hid", &hid_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 26. Bluetooth Devices
    let bt_status = get_bt_status(issues);
    control_status.insert("bt".to_string(), bt_status.clone());
    if bt_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "bt", &bt_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 27. Fake Extensions
    let fakeext_status = get_fakeext_status(issues);
    control_status.insert("fakeext".to_string(), fakeext_status.clone());
    if fakeext_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "fakeext", &fakeext_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 28. Bloatware
    let bloatware_status = get_bloatware_status(issues);
    control_status.insert("bloatware".to_string(), bloatware_status.clone());
    if bloatware_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "bloatware", &bloatware_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 29. Network Adapters
    let adapter_status = get_adapter_status(issues);
    control_status.insert("adapter".to_string(), adapter_status.clone());
    if adapter_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "adapter", &adapter_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 30. Scheduled Tasks
    let tasks_status = get_tasks_status(issues);
    control_status.insert("tasks".to_string(), tasks_status.clone());
    if tasks_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "tasks", &tasks_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 31. WiFi
    let wifi_status = get_wifi_status(issues);
    control_status.insert("wifi".to_string(), wifi_status.clone());
    if wifi_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "wifi", &wifi_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 32. ARP
    let arp_status = get_arp_status(issues);
    control_status.insert("arp".to_string(), arp_status.clone());
    if arp_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "arp", &arp_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 33. Homoglyph
    let homoglyph_status = get_homoglyph_status(issues);
    control_status.insert("homoglyph".to_string(), homoglyph_status.clone());
    if homoglyph_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "homoglyph", &homoglyph_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // 34. Suspicious Processes
    let susp_proc_status = get_susp_proc_status(issues);
    control_status.insert("susp_proc".to_string(), susp_proc_status.clone());
    if susp_proc_status.status != Status::Healthy {
        let deduction = apply_deduction(&mut deductions, "susp_proc", &susp_proc_status, &weights, &context);
        total_deduction += deduction as u16;
    }

    // Cap deduction at 100
    let final_score = if total_deduction >= 100 {
        0
    } else {
        (100 - total_deduction) as u8
    };

    let state = determine_state(&deductions, final_score);

    IntegrityReport {
        score: final_score,
        state,
        control_status,
        deductions,
        timestamp: chrono::Local::now().to_rfc3339(),
    }
}

// ============================================
// CONTROL STATUS EVALUATORS — FIX: ERROR_* sentinel checks
// ============================================

fn get_firewall_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "firewall" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Firewall detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "firewall" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "Firewall is disabled".to_string(),
                severity: Severity::Critical,
                weight: 20,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Firewall is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_defender_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "defender" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Defender detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "defender" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "Windows Defender is disabled".to_string(),
                severity: Severity::Critical,
                weight: 20,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Windows Defender is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_dns_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "dns" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("DNS detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "dns" {
            return ControlStatus {
                status: Status::Warning,
                reason: "DNS configuration changed".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "DNS is configured correctly".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_hosts_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "hosts" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Hosts detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "hosts" {
            return ControlStatus {
                status: Status::Warning,
                reason: "Hosts file modified".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Hosts file is intact".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_proxy_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "proxy" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Proxy detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "proxy" {
            return ControlStatus {
                status: Status::Warning,
                reason: "Proxy settings changed".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No proxy detected".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_uac_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "uac" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("UAC detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "uac" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "UAC is disabled".to_string(),
                severity: Severity::Critical,
                weight: 20,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "UAC is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_windows_update_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "wu" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Windows Update detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "wu" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "Windows Update is disabled".to_string(),
                severity: Severity::Critical,
                weight: 20,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Windows Update is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_system_restore_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "sr" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: "System Restore is not available on this system".to_string(),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "sr" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "System Restore is disabled".to_string(),
                severity: Severity::Critical,
                weight: 20,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "System Restore is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}
    
fn get_smart_screen_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "smartscreen" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("SmartScreen detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "smartscreen" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "SmartScreen is disabled".to_string(),
                severity: Severity::Critical,
                weight: 20,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "SmartScreen is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_vpn_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "vpn" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("VPN detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "vpn" && msg.contains("DISCONNECTED") {
            return ControlStatus {
                status: Status::Warning,
                reason: "VPN is disconnected".to_string(),
                severity: Severity::Low,
                weight: 2,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "VPN is connected".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_ipv6_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "ipv6" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("IPv6 detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "ipv6" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Warning,
                reason: "IPv6 is disabled".to_string(),
                severity: Severity::Low,
                weight: 2,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "IPv6 is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_wifi_profile_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "wifi_profile" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("WiFi profile detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "wifi_profile" && msg.contains("PUBLIC") {
            return ControlStatus {
                status: Status::Warning,
                reason: "WiFi profile is set to Public".to_string(),
                severity: Severity::Low,
                weight: 2,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "WiFi profile is Private".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_doh_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "doh" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("DoH detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "doh" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Warning,
                reason: "DNS over HTTPS is disabled".to_string(),
                severity: Severity::Medium,
                weight: 6,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "DNS over HTTPS is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_laps_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "laps" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("LAPS detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "laps" && msg.contains("DISABLED") {
            return ControlStatus {
                status: Status::Warning,
                reason: "LAPS is disabled".to_string(),
                severity: Severity::Medium,
                weight: 6,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "LAPS is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_secure_boot_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "secureboot" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Secure Boot detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "secureboot" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "Secure Boot is disabled".to_string(),
                severity: Severity::Critical,
                weight: 20,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Secure Boot is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_startup_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "startup" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Startup detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "startup" {
            return ControlStatus {
                status: Status::Warning,
                reason: "Startup entries changed".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Startup entries are clean".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_services_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "services" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Services detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "services" {
            return ControlStatus {
                status: Status::Warning,
                reason: "Windows Services changed".to_string(),
                severity: Severity::Medium,
                weight: 6,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Windows Services are unchanged".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_devices_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "devices" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Devices detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "devices" {
            return ControlStatus {
                status: Status::Warning,
                reason: "New network device detected".to_string(),
                severity: Severity::Medium,
                weight: 6,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No unknown network devices".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_dhcp_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "dhcp" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("DHCP detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "dhcp" {
            return ControlStatus {
                status: Status::Warning,
                reason: "DHCP server changed (possible spoofing)".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "DHCP server is consistent".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_bitlocker_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "bitlocker" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("BitLocker detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "bitlocker" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "BitLocker is disabled".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "BitLocker is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_credential_guard_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "credguard" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Credential Guard detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "credguard" && msg.contains("OFF") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "Credential Guard is disabled".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Credential Guard is enabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_rdp_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "rdp" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("RDP detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "rdp" && (msg.contains("LISTENING") || msg.contains("RUNNING")) {
            return ControlStatus {
                status: Status::Warning,
                reason: "RDP is enabled (port 3389 listening)".to_string(),
                severity: Severity::Medium,
                weight: 6,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "RDP is disabled".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

// ============================================
// NEW: ADDITIONAL CONTROL EVALUATORS
// ============================================

fn get_bruteforce_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "bruteforce" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Brute force detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "bruteforce" && msg.contains("HIGH") {
            return ControlStatus {
                status: Status::Compromised,
                reason: "Multiple login failures detected (brute force)".to_string(),
                severity: Severity::Critical,
                weight: 20,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No brute force attempts detected".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_trojan_source_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "trojan_source" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Trojan source detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "trojan_source" {
            return ControlStatus {
                status: Status::Compromised,
                reason: "Unicode bidi files detected (trojan source)".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No trojan source files detected".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_hid_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "hid" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("HID detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "hid" {
            return ControlStatus {
                status: Status::Warning,
                reason: "New HID devices detected".to_string(),
                severity: Severity::Medium,
                weight: 6,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No suspicious HID devices".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_bt_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "bt" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Bluetooth detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "bt" {
            return ControlStatus {
                status: Status::Warning,
                reason: "New Bluetooth devices detected".to_string(),
                severity: Severity::Low,
                weight: 2,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No unknown Bluetooth devices".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_fakeext_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "fakeext" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Fake extension detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "fakeext" {
            return ControlStatus {
                status: Status::Compromised,
                reason: "Fake file extensions detected".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No fake file extensions detected".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_bloatware_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "bloatware" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Bloatware detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "bloatware" {
            return ControlStatus {
                status: Status::Warning,
                reason: "New software detected (possible bloatware)".to_string(),
                severity: Severity::Low,
                weight: 2,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No bloatware detected".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_adapter_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "adapter" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Adapter detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "adapter" {
            return ControlStatus {
                status: Status::Warning,
                reason: "Network adapters changed".to_string(),
                severity: Severity::Medium,
                weight: 6,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Network adapters are unchanged".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_tasks_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "tasks" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Tasks detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "tasks" {
            return ControlStatus {
                status: Status::Warning,
                reason: "Scheduled tasks changed".to_string(),
                severity: Severity::Medium,
                weight: 6,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "Scheduled tasks are unchanged".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_wifi_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "wifi" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("WiFi detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "wifi" {
            return ControlStatus {
                status: Status::Warning,
                reason: "WiFi network changed".to_string(),
                severity: Severity::Low,
                weight: 2,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "WiFi network is unchanged".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_arp_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "arp" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("ARP detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "arp" {
            // FIX: ARP cache churns constantly during normal network use
            // (device wake/sleep, lease renewal) - it's a weak signal on
            // its own, not equivalent to a real compromised control.
            return ControlStatus {
                status: Status::Warning,
                reason: "ARP table changed (possible spoofing)".to_string(),
                severity: Severity::Low,
                weight: 2,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "ARP table is consistent".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_homoglyph_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "homoglyph" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Homoglyph detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "homoglyph" {
            return ControlStatus {
                status: Status::Warning,
                reason: "Homoglyph domains detected (typosquatting)".to_string(),
                severity: Severity::Medium,
                weight: 6,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No homoglyph domains detected".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn get_susp_proc_status(issues: &[(String, String)]) -> ControlStatus {
    for (category, msg) in issues {
        if category == "susp_proc" && msg.starts_with("ERROR_") {
            return ControlStatus {
                status: Status::Unknown,
                reason: format!("Suspicious process detection failed: {}", msg),
                severity: Severity::None,
                weight: 0,
            };
        }
        if category == "susp_proc" {
            return ControlStatus {
                status: Status::Warning,
                reason: "Suspicious processes detected".to_string(),
                severity: Severity::High,
                weight: 12,
            };
        }
    }
    ControlStatus {
        status: Status::Healthy,
        reason: "No suspicious processes detected".to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

// ============================================
// HELPERS — FIX #11: Weights now used
// ============================================

fn apply_deduction(
    deductions: &mut Vec<Deduction>,
    category: &str,
    status: &ControlStatus,
    weights: &IntegrityWeights,
    context: &Context,
) -> u8 {
    let multiplier = context.deduction_multiplier(category);
    
    // FIX #11: Use weights to determine base points based on severity
    // FIX #13: Use saturating_mul to prevent overflow
    let base_points = match status.severity {
        Severity::Critical => weights.critical,
        Severity::High => weights.high,
        Severity::Medium => weights.medium,
        Severity::Low => weights.low,
        Severity::None => 0,
    };
    
    let points = base_points.saturating_mul(multiplier).min(100);
    
    deductions.push(Deduction {
        category: category.to_string(),
        severity: status.severity.clone(),
        points: points as u8,
        reason: status.reason.clone(),
        context: status.reason.clone(),
    });
    
    points as u8
}

fn determine_state(deductions: &[Deduction], score: u8) -> IntegrityState {
    let has_critical = deductions.iter().any(|d| d.severity == Severity::Critical);

    if score >= 90 {
        IntegrityState::Maintained
    } else if has_critical {
        IntegrityState::Compromised
    } else if !deductions.is_empty() {
        IntegrityState::DriftDetected
    } else {
        IntegrityState::Maintained
    }
}

// ============================================
// EXPORT REPORT
// ============================================

pub fn export_report(report: &IntegrityReport, format: &str) -> String {
    match format {
        "json" => serde_json::to_string_pretty(report).unwrap_or_default(),
        "markdown" => format_report_markdown(report),
        _ => serde_json::to_string_pretty(report).unwrap_or_default(),
    }
}

fn format_report_markdown(report: &IntegrityReport) -> String {
    let state_str = match report.state {
        IntegrityState::Maintained => "✅ Maintained",
        IntegrityState::DriftDetected => "⚠️ Drift Detected",
        IntegrityState::Compromised => "🔴 Compromised",
        IntegrityState::Lockdown => "🔵 Lockdown",
        IntegrityState::Invalid => "❌ Invalid",
    };

    let mut output = format!(
        "# Integrity Report\n\n\
         **Score:** {}/100\n\
         **State:** {}\n\
         **Timestamp:** {}\n\n",
        report.score, state_str, report.timestamp
    );

    if report.control_status.is_empty() {
        output.push_str("✅ No controls to evaluate.\n");
    } else {
        output.push_str("## Control Status\n\n");
        for (name, status) in &report.control_status {
            let status_str = match status.status {
                Status::Healthy => "✅",
                Status::Warning => "⚠️",
                Status::Compromised => "🔴",
                Status::Unknown => "❓",
            };
            output.push_str(&format!(
                "- **{}** {} — {}\n",
                name, status_str, status.reason
            ));
        }
    }

    if !report.deductions.is_empty() {
        output.push_str("\n## Deductions\n\n");
        for d in &report.deductions {
            let severity_str = match d.severity {
                Severity::Critical => "🔴 Critical",
                Severity::High => "🟠 High",
                Severity::Medium => "🟡 Medium",
                Severity::Low => "🔵 Low",
                Severity::None => "⚪ Info",
            };
            output.push_str(&format!(
                "- **{}** ({}) -{} points\n  - {}\n",
                d.category, severity_str, d.points, d.reason
            ));
        }
    }

    output
}