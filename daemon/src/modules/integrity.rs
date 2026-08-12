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
// CONTROL EVALUATOR DEFINITIONS (TABLE-DRIVEN)
// ============================================

type EvaluatorFn = fn(&[(String, String)]) -> ControlStatus;

struct ControlEvaluator {
    category: &'static str,
    evaluator: EvaluatorFn,
}

// FIX: Table-driven approach replaces 34 duplicate functions
fn get_control_evaluators() -> Vec<ControlEvaluator> {
    vec![
        ControlEvaluator { category: "firewall", evaluator: evaluate_firewall },
        ControlEvaluator { category: "defender", evaluator: evaluate_defender },
        ControlEvaluator { category: "dns", evaluator: evaluate_dns },
        ControlEvaluator { category: "hosts", evaluator: evaluate_hosts },
        ControlEvaluator { category: "proxy", evaluator: evaluate_proxy },
        ControlEvaluator { category: "uac", evaluator: evaluate_uac },
        ControlEvaluator { category: "wu", evaluator: evaluate_wu },
        ControlEvaluator { category: "sr", evaluator: evaluate_sr },
        ControlEvaluator { category: "smartscreen", evaluator: evaluate_smartscreen },
        ControlEvaluator { category: "vpn", evaluator: evaluate_vpn },
        ControlEvaluator { category: "ipv6", evaluator: evaluate_ipv6 },
        ControlEvaluator { category: "wifi_profile", evaluator: evaluate_wifi_profile },
        ControlEvaluator { category: "doh", evaluator: evaluate_doh },
        ControlEvaluator { category: "laps", evaluator: evaluate_laps },
        ControlEvaluator { category: "secureboot", evaluator: evaluate_secureboot },
        ControlEvaluator { category: "startup", evaluator: evaluate_startup },
        ControlEvaluator { category: "services", evaluator: evaluate_services },
        ControlEvaluator { category: "devices", evaluator: evaluate_devices },
        ControlEvaluator { category: "dhcp", evaluator: evaluate_dhcp },
        ControlEvaluator { category: "bitlocker", evaluator: evaluate_bitlocker },
        ControlEvaluator { category: "credguard", evaluator: evaluate_credguard },
        ControlEvaluator { category: "rdp", evaluator: evaluate_rdp },
        ControlEvaluator { category: "bruteforce", evaluator: evaluate_bruteforce },
        ControlEvaluator { category: "trojan_source", evaluator: evaluate_trojan_source },
        ControlEvaluator { category: "hid", evaluator: evaluate_hid },
        ControlEvaluator { category: "bt", evaluator: evaluate_bt },
        ControlEvaluator { category: "fakeext", evaluator: evaluate_fakeext },
        ControlEvaluator { category: "bloatware", evaluator: evaluate_bloatware },
        ControlEvaluator { category: "adapter", evaluator: evaluate_adapter },
        ControlEvaluator { category: "tasks", evaluator: evaluate_tasks },
        ControlEvaluator { category: "wifi", evaluator: evaluate_wifi },
        ControlEvaluator { category: "arp", evaluator: evaluate_arp },
        ControlEvaluator { category: "homoglyph", evaluator: evaluate_homoglyph },
        ControlEvaluator { category: "susp_proc", evaluator: evaluate_susp_proc },
    ]
}

// ============================================
// GENERIC EVALUATOR HELPERS
// ============================================

fn find_issue<'a>(issues: &'a [(String, String)], category: &str) -> Option<&'a str> {
    issues.iter()
        .find(|(cat, _)| cat == category)
        .map(|(_, msg)| msg.as_str())
}

fn is_error(msg: &str) -> bool {
    msg.starts_with("ERROR_")
}

fn has_issue(issues: &[(String, String)], category: &str, condition: impl Fn(&str) -> bool) -> bool {
    find_issue(issues, category)
        .map(|msg| condition(msg))
        .unwrap_or(false)
}

fn healthy_status(reason: &str) -> ControlStatus {
    ControlStatus {
        status: Status::Healthy,
        reason: reason.to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn unknown_status(reason: &str) -> ControlStatus {
    ControlStatus {
        status: Status::Unknown,
        reason: reason.to_string(),
        severity: Severity::None,
        weight: 0,
    }
}

fn compromised_status(reason: &str, severity: Severity, weight: u8) -> ControlStatus {
    ControlStatus {
        status: Status::Compromised,
        reason: reason.to_string(),
        severity,
        weight,
    }
}

fn warning_status(reason: &str, severity: Severity, weight: u8) -> ControlStatus {
    ControlStatus {
        status: Status::Warning,
        reason: reason.to_string(),
        severity,
        weight,
    }
}

// ============================================
// INDIVIDUAL EVALUATORS
// ============================================

fn evaluate_firewall(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "firewall") {
        if is_error(msg) {
            return unknown_status(&format!("Firewall detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return compromised_status("Firewall is disabled", Severity::Critical, 20);
        }
    }
    healthy_status("Firewall is enabled")
}

fn evaluate_defender(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "defender") {
        if is_error(msg) {
            return unknown_status(&format!("Defender detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return compromised_status("Windows Defender is disabled", Severity::Critical, 20);
        }
    }
    healthy_status("Windows Defender is enabled")
}

fn evaluate_dns(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "dns") {
        if is_error(msg) {
            return unknown_status(&format!("DNS detection failed: {}", msg));
        }
        return warning_status("DNS configuration changed", Severity::High, 12);
    }
    healthy_status("DNS is configured correctly")
}

fn evaluate_hosts(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "hosts") {
        if is_error(msg) {
            return unknown_status(&format!("Hosts detection failed: {}", msg));
        }
        return warning_status("Hosts file modified", Severity::High, 12);
    }
    healthy_status("Hosts file is intact")
}

fn evaluate_proxy(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "proxy") {
        if is_error(msg) {
            return unknown_status(&format!("Proxy detection failed: {}", msg));
        }
        return warning_status("Proxy settings changed", Severity::High, 12);
    }
    healthy_status("No proxy detected")
}

fn evaluate_uac(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "uac") {
        if is_error(msg) {
            return unknown_status(&format!("UAC detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return compromised_status("UAC is disabled", Severity::Critical, 20);
        }
    }
    healthy_status("UAC is enabled")
}

fn evaluate_wu(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "wu") {
        if is_error(msg) {
            return unknown_status(&format!("Windows Update detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return compromised_status("Windows Update is disabled", Severity::Critical, 20);
        }
    }
    healthy_status("Windows Update is enabled")
}

fn evaluate_sr(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "sr") {
        if is_error(msg) {
            return unknown_status("System Restore is not available on this system");
        }
        if msg.contains("OFF") {
            return compromised_status("System Restore is disabled", Severity::Critical, 20);
        }
    }
    healthy_status("System Restore is enabled")
}

fn evaluate_smartscreen(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "smartscreen") {
        if is_error(msg) {
            return unknown_status(&format!("SmartScreen detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return compromised_status("SmartScreen is disabled", Severity::Critical, 20);
        }
    }
    healthy_status("SmartScreen is enabled")
}

fn evaluate_vpn(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "vpn") {
        if is_error(msg) {
            return unknown_status(&format!("VPN detection failed: {}", msg));
        }
        if msg.contains("DISCONNECTED") {
            return warning_status("VPN is disconnected", Severity::Low, 2);
        }
    }
    healthy_status("VPN is connected")
}

fn evaluate_ipv6(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "ipv6") {
        if is_error(msg) {
            return unknown_status(&format!("IPv6 detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return warning_status("IPv6 is disabled", Severity::Low, 2);
        }
    }
    healthy_status("IPv6 is enabled")
}

fn evaluate_wifi_profile(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "wifi_profile") {
        if is_error(msg) {
            return unknown_status(&format!("WiFi profile detection failed: {}", msg));
        }
        if msg.contains("PUBLIC") {
            return warning_status("WiFi profile is set to Public", Severity::Low, 2);
        }
    }
    healthy_status("WiFi profile is Private")
}

fn evaluate_doh(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "doh") {
        if is_error(msg) {
            return unknown_status(&format!("DoH detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return warning_status("DNS over HTTPS is disabled", Severity::Medium, 6);
        }
    }
    healthy_status("DNS over HTTPS is enabled")
}

fn evaluate_laps(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "laps") {
        if is_error(msg) {
            return unknown_status(&format!("LAPS detection failed: {}", msg));
        }
        if msg.contains("DISABLED") {
            return warning_status("LAPS is disabled", Severity::Medium, 6);
        }
    }
    healthy_status("LAPS is enabled")
}

fn evaluate_secureboot(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "secureboot") {
        if is_error(msg) {
            return unknown_status(&format!("Secure Boot detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return compromised_status("Secure Boot is disabled", Severity::Critical, 20);
        }
    }
    healthy_status("Secure Boot is enabled")
}

fn evaluate_startup(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "startup") {
        if is_error(msg) {
            return unknown_status(&format!("Startup detection failed: {}", msg));
        }
        return warning_status("Startup entries changed", Severity::High, 12);
    }
    healthy_status("Startup entries are clean")
}

fn evaluate_services(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "services") {
        if is_error(msg) {
            return unknown_status(&format!("Services detection failed: {}", msg));
        }
        return warning_status("Windows Services changed", Severity::Medium, 6);
    }
    healthy_status("Windows Services are unchanged")
}

fn evaluate_devices(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "devices") {
        if is_error(msg) {
            return unknown_status(&format!("Devices detection failed: {}", msg));
        }
        return warning_status("New network device detected", Severity::Medium, 6);
    }
    healthy_status("No unknown network devices")
}

fn evaluate_dhcp(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "dhcp") {
        if is_error(msg) {
            return unknown_status(&format!("DHCP detection failed: {}", msg));
        }
        return warning_status("DHCP server changed (possible spoofing)", Severity::High, 12);
    }
    healthy_status("DHCP server is consistent")
}

fn evaluate_bitlocker(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "bitlocker") {
        if is_error(msg) {
            return unknown_status(&format!("BitLocker detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return compromised_status("BitLocker is disabled", Severity::High, 12);
        }
    }
    healthy_status("BitLocker is enabled")
}

fn evaluate_credguard(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "credguard") {
        if is_error(msg) {
            return unknown_status(&format!("Credential Guard detection failed: {}", msg));
        }
        if msg.contains("OFF") {
            return compromised_status("Credential Guard is disabled", Severity::High, 12);
        }
    }
    healthy_status("Credential Guard is enabled")
}

fn evaluate_rdp(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "rdp") {
        if is_error(msg) {
            return unknown_status(&format!("RDP detection failed: {}", msg));
        }
        if msg.contains("LISTENING") || msg.contains("RUNNING") {
            return warning_status("RDP is enabled (port 3389 listening)", Severity::Medium, 6);
        }
    }
    healthy_status("RDP is disabled")
}

fn evaluate_bruteforce(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "bruteforce") {
        if is_error(msg) {
            return unknown_status(&format!("Brute force detection failed: {}", msg));
        }
        if msg.contains("HIGH") {
            return compromised_status("Multiple login failures detected (brute force)", Severity::Critical, 20);
        }
    }
    healthy_status("No brute force attempts detected")
}

fn evaluate_trojan_source(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "trojan_source") {
        if is_error(msg) {
            return unknown_status(&format!("Trojan source detection failed: {}", msg));
        }
        return compromised_status("Unicode bidi files detected (trojan source)", Severity::High, 12);
    }
    healthy_status("No trojan source files detected")
}

fn evaluate_hid(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "hid") {
        if is_error(msg) {
            return unknown_status(&format!("HID detection failed: {}", msg));
        }
        return warning_status("New HID devices detected", Severity::Medium, 6);
    }
    healthy_status("No suspicious HID devices")
}

fn evaluate_bt(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "bt") {
        if is_error(msg) {
            return unknown_status(&format!("Bluetooth detection failed: {}", msg));
        }
        return warning_status("New Bluetooth devices detected", Severity::Low, 2);
    }
    healthy_status("No unknown Bluetooth devices")
}

fn evaluate_fakeext(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "fakeext") {
        if is_error(msg) {
            return unknown_status(&format!("Fake extension detection failed: {}", msg));
        }
        return compromised_status("Fake file extensions detected", Severity::High, 12);
    }
    healthy_status("No fake file extensions detected")
}

fn evaluate_bloatware(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "bloatware") {
        if is_error(msg) {
            return unknown_status(&format!("Bloatware detection failed: {}", msg));
        }
        return warning_status("New software detected (possible bloatware)", Severity::Low, 2);
    }
    healthy_status("No bloatware detected")
}

fn evaluate_adapter(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "adapter") {
        if is_error(msg) {
            return unknown_status(&format!("Adapter detection failed: {}", msg));
        }
        return warning_status("Network adapters changed", Severity::Medium, 6);
    }
    healthy_status("Network adapters are unchanged")
}

fn evaluate_tasks(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "tasks") {
        if is_error(msg) {
            return unknown_status(&format!("Tasks detection failed: {}", msg));
        }
        return warning_status("Scheduled tasks changed", Severity::Medium, 6);
    }
    healthy_status("Scheduled tasks are unchanged")
}

fn evaluate_wifi(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "wifi") {
        if is_error(msg) {
            return unknown_status(&format!("WiFi detection failed: {}", msg));
        }
        return warning_status("WiFi network changed", Severity::Low, 2);
    }
    healthy_status("WiFi network is unchanged")
}

fn evaluate_arp(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "arp") {
        if is_error(msg) {
            return unknown_status(&format!("ARP detection failed: {}", msg));
        }
        return warning_status("ARP table changed (possible spoofing)", Severity::Low, 2);
    }
    healthy_status("ARP table is consistent")
}

fn evaluate_homoglyph(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "homoglyph") {
        if is_error(msg) {
            return unknown_status(&format!("Homoglyph detection failed: {}", msg));
        }
        return warning_status("Homoglyph domains detected (typosquatting)", Severity::Medium, 6);
    }
    healthy_status("No homoglyph domains detected")
}

fn evaluate_susp_proc(issues: &[(String, String)]) -> ControlStatus {
    if let Some(msg) = find_issue(issues, "susp_proc") {
        if is_error(msg) {
            return unknown_status(&format!("Suspicious process detection failed: {}", msg));
        }
        return warning_status("Suspicious processes detected", Severity::High, 12);
    }
    healthy_status("No suspicious processes detected")
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
    // EVALUATE EACH CONTROL USING TABLE-DRIVEN APPROACH
    // ============================================
    
    for evaluator in get_control_evaluators() {
        let status = (evaluator.evaluator)(issues);
        control_status.insert(evaluator.category.to_string(), status.clone());
        
        if status.status != Status::Healthy && status.status != Status::Unknown {
            let deduction = apply_deduction(
                &mut deductions,
                evaluator.category,
                &status,
                &weights,
                &context,
            );
            total_deduction += deduction as u16;
        }
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
// HELPERS
// ============================================

fn apply_deduction(
    deductions: &mut Vec<Deduction>,
    category: &str,
    status: &ControlStatus,
    weights: &IntegrityWeights,
    context: &Context,
) -> u8 {
    let multiplier = context.deduction_multiplier(category);
    
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