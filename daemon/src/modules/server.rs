// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Local HTTP API Server — Hybrid with Integrity Score + Trust Level
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::path::Path;
use std::time::Duration;
use std::sync::atomic::AtomicPtr;

use crate::modules::integrity::IntegrityReport;
use crate::BASELINE;
use crate::modules::trust;
use crate::modules::config;
use crate::modules::baseline;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";
const PORT: u16 = 12790;
const BIND_ADDR: &str = "127.0.0.1";
const READ_TIMEOUT_SECS: u64 = 10;

// ============================================
// TRUST STATE (Legacy)
// ============================================

static TRUST_STATE: AtomicPtr<&'static str> = AtomicPtr::new("Trusted\0".as_ptr() as *mut _);

pub fn set_trust_state(state: &'static str) {
    let ptr = state.as_ptr() as *mut _;
    TRUST_STATE.store(ptr, Ordering::Release);
}

pub fn get_trust_state() -> String {
    let ptr = TRUST_STATE.load(Ordering::Acquire);
    if ptr.is_null() {
        "Trusted".to_string()
    } else {
        unsafe {
            let bytes = std::ffi::CStr::from_ptr(ptr as *const i8);
            bytes.to_string_lossy().into_owned()
        }
    }
}

// ============================================
// GHOST STATE
// ============================================

static GHOST_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn set_ghost_active(active: bool) {
    GHOST_ACTIVE.store(active, Ordering::Release);
}

pub fn is_ghost_active() -> bool {
    GHOST_ACTIVE.load(Ordering::Acquire)
}

// ============================================
// TS2 TOGGLE (ON/OFF)
// ============================================

static TS2_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_ts2_enabled(enabled: bool) {
    TS2_ENABLED.store(enabled, Ordering::Release);
}

pub fn is_ts2_enabled() -> bool {
    TS2_ENABLED.load(Ordering::Acquire)
}

// ============================================
// INTEGRITY REPORT (FIX #6: Arc<Mutex> instead of AtomicPtr)
// ============================================

static INTEGRITY_REPORT: once_cell::sync::Lazy<Arc<Mutex<Option<IntegrityReport>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(None)));

pub fn set_integrity_report(report: IntegrityReport) {
    let mut guard = INTEGRITY_REPORT.lock().unwrap();
    *guard = Some(report);
}

pub fn get_integrity_report() -> Option<IntegrityReport> {
    let guard = INTEGRITY_REPORT.lock().unwrap();
    guard.clone()
}

// ============================================
// TRUST LEVEL (Historical) (FIX #6: AtomicU8 instead of AtomicPtr)
// ============================================

static TRUST_LEVEL: AtomicU8 = AtomicU8::new(100);

pub fn set_trust_level(score: u8) {
    TRUST_LEVEL.store(score, Ordering::Release);
}

pub fn get_trust_level() -> u8 {
    let val = TRUST_LEVEL.load(Ordering::Acquire);
    if val == 0 {
        trust::get_trust_score()
    } else {
        val
    }
}

// ============================================
// TOKEN
// ============================================

fn get_token() -> String {
    let token_path = format!("{}\\agent.token", DATA_DIR);
    if let Ok(token) = fs::read_to_string(&token_path) {
        token.trim().to_string()
    } else {
        let token = format!("{:x}", rand::random::<u128>());
        let _ = fs::write(&token_path, &token);
        token
    }
}

// ============================================
// CORS — Restricted to localhost only
// ============================================

fn cors_allowed_origin() -> &'static str {
    "http://127.0.0.1:12790"
}

fn cors_headers() -> String {
    format!(
        "Access-Control-Allow-Origin: {}\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, Authorization\r\n",
        cors_allowed_origin()
    )
}

// ============================================
// HTTP HELPERS
// ============================================

fn json_response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status_string(status),
        cors_headers(),
        body.len(),
        body
    )
}

fn status_string(code: u16) -> &'static str {
    match code {
        200 => "200 OK",
        400 => "400 Bad Request",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        500 => "500 Internal Server Error",
        _ => "500 Internal Server Error"
    }
}

fn html_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n{}Content-Type: text/html\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\nContent-Length: {}\r\n\r\n{}",
        cors_headers(),
        body.len(),
        body
    )
}

fn unauthorized() -> String {
    json_response(403, r#"{"error":"Unauthorized - Invalid token"}"#)
}

// ============================================
// PARSE QUERY PARAM
// ============================================

fn parse_query_param(request: &str, param: &str) -> Option<String> {
    if let Some(pos) = request.find(&format!("{}=", param)) {
        let start = pos + param.len() + 1;
        let end = request[start..].find(&['&', ' '][..])
            .map(|i| start + i)
            .unwrap_or(request.len());
        let value = request[start..end].trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

// ============================================
// ROLLBACK FUNCTION — FIX #21: Sanitized errors
// ============================================

pub fn rollback_changes() -> String {
    let mut results = Vec::new();

    // 1. Restore hosts file from backup
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let backup = format!("{}\\hosts.backup", DATA_DIR);
    if Path::new(&backup).exists() {
        match fs::copy(&backup, hosts) {
            Ok(_) => results.push("Hosts file restored".to_string()),
            Err(_) => results.push("Hosts restore failed: permission denied or file in use".to_string()),
        }
    } else {
        results.push("No hosts backup found".to_string());
    }

    // FIX: Report what actually happened instead of assuming success
    let ran_ok = |out: std::io::Result<std::process::Output>| -> bool {
        matches!(out, Ok(o) if o.status.success())
    };

    // 2. Reset firewall to default
    let ok = ran_ok(std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-NetFirewallProfile -All -DefaultInboundAction Allow; Set-NetFirewallProfile -All -DefaultOutboundAction Allow"])
        .output());
    results.push(if ok { "Firewall reset to default".to_string() } else { "Firewall reset FAILED".to_string() });

    // 3. Remove proxy
    let ok = ran_ok(std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue"])
        .output());
    results.push(if ok { "Proxy removed".to_string() } else { "Proxy removal FAILED".to_string() });

    // 4. Reset DNS to DHCP
    // FIX: Don't hardcode "Wi-Fi" - target whatever adapter is actually up
    let ok = ran_ok(std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }"])
        .output());
    results.push(if ok { "DNS reset to DHCP (active adapter)".to_string() } else { "DNS reset FAILED".to_string() });

    // 5. Enable Defender
    let ok = ran_ok(std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"])
        .output());
    results.push(if ok { "Defender re-enabled".to_string() } else { "Defender re-enable FAILED".to_string() });

    // 6. Disable Ghost Mode if active
    if is_ghost_active() {
        let ok = ran_ok(std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "Get-NetFirewallRule -DisplayName 'TS-VPN-Only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
                "Get-NetFirewallRule -DisplayName 'TS-Block-ICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
                "Get-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"])
            .output());
        set_ghost_active(false);
        let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
        let _ = fs::remove_file(&ghost_flag);
        results.push(if ok { "Ghost Mode disabled".to_string() } else { "Ghost Mode firewall rules FAILED to remove (flag cleared anyway)".to_string() });
    }

    results.join("; ")
}

// ============================================
// SERVER — FIX #16: Read timeout added
// ============================================

pub fn run() -> std::io::Result<()> {
    println!("🔌 Server: Attempting to bind to {}:{}", BIND_ADDR, PORT);
    let addr = format!("{}:{}", BIND_ADDR, PORT);
    let listener = TcpListener::bind(&addr)?;
    println!("✅ Server: Successfully bound to port {}", PORT);
    println!("📡 API running on http://{}", addr);

    let token = get_token();
    println!("🔑 Auth token: {}", token);

    let dashboard_html = include_str!("../web/dashboard.html");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let token_clone = token.clone();
                let dashboard_clone = dashboard_html.to_string();
                std::thread::spawn(move || {
                    handle_connection(stream, &token_clone, &dashboard_clone);
                });
            }
            Err(e) => {
                eprintln!("Connection error: {}", e);
            }
        }
    }
    Ok(())
}

// ============================================
// AUTH VALIDATOR — FIX #30: Case-insensitive
// ============================================

fn validate_auth(headers: &str, token: &str) -> bool {
    let lower_headers = headers.to_lowercase();
    let lower_bearer = format!("bearer {}", token.to_lowercase());
    let lower_token = format!("token {}", token.to_lowercase());
    lower_headers.contains(&lower_bearer) || lower_headers.contains(&lower_token)
}

// ============================================
// CONNECTION HANDLER — FIX #16: Read timeout
// ============================================

fn handle_connection(mut stream: TcpStream, token: &str, dashboard_html: &str) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));
    
    let mut buffer = [0; 4096];
    if let Ok(n) = stream.read(&mut buffer) {
        if n == 0 { return; }

        let request = String::from_utf8_lossy(&buffer[0..n]);
        let (method, path, headers) = parse_request(&request);

        // CORS preflight check
        if method == "OPTIONS" {
            let resp = format!(
                "HTTP/1.1 200 OK\r\n{}Content-Length: 0\r\n\r\n",
                cors_headers()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
            return;
        }

        // FIX: Don't require auth for dashboard and token on loopback
        let is_auth_required = !matches!(path.as_str(), "/" | "/dashboard" | "/token");
        
        if is_auth_required && !validate_auth(&headers, token) {
            let _ = stream.write_all(unauthorized().as_bytes());
            let _ = stream.flush();
            return;
        }

        let response = match (method.as_str(), path.as_str()) {
            // ============================================
            // GET ENDPOINTS
            // ============================================
            ("GET", "/token") => {
                // FIX: No auth needed on loopback
                json_response(200, &format!(r#"{{"token":"{}"}}"#, token))
            }
            ("GET", "/") => {
                let trust_state = get_trust_state();
                let ghost = is_ghost_active();
                let enabled = is_ts2_enabled();
                let report = get_integrity_report();
                let score = report.as_ref().map(|r| r.score).unwrap_or(0);
                let state_str = report.as_ref().map(|r| format!("{:?}", r.state)).unwrap_or_else(|| "Unknown".to_string());
                let trust_level = get_trust_level();

                json_response(200, &format!(
                    r#"{{"status":"ok","trust_state":"{}","ghost":{},"enabled":{},"integrity_score":{},"integrity_state":"{}","trust_level":{}}}"#,
                    trust_state,
                    ghost,
                    enabled,
                    score,
                    state_str,
                    trust_level
                ))
            }
            ("GET", "/dashboard") => {
                // FIX: No auth needed for dashboard on loopback
                html_response(dashboard_html)
            }
            ("GET", "/status") => {
                // FIX #5: Auth required
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let trust_state = get_trust_state();
                    let ghost = is_ghost_active();
                    let enabled = is_ts2_enabled();
                    let report = get_integrity_report();
                    let score = report.as_ref().map(|r| r.score).unwrap_or(0);
                    let trust_level = get_trust_level();
                    json_response(200, &format!(
                        r#"{{"trust_state":"{}","ghost":{},"enabled":{},"integrity_score":{},"trust_level":{}}}"#,
                        trust_state,
                        ghost,
                        enabled,
                        score,
                        trust_level
                    ))
                }
            }
            ("GET", "/timeline") => {
                // FIX #5: Auth required
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let format = parse_query_param(&request, "format").unwrap_or_else(|| "json".to_string());
                    let data = crate::modules::timeline::export_timeline(&format);
                    json_response(200, &data)
                }
            }
            ("GET", "/report") => {
                // FIX #5: Auth required
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let format = parse_query_param(&request, "format").unwrap_or_else(|| "json".to_string());
                    if let Some(report) = get_integrity_report() {
                        let data = crate::modules::integrity::export_report(&report, &format);
                        json_response(200, &data)
                    } else {
                        json_response(404, r#"{"error":"No report available"}"#)
                    }
                }
            }

            // ============================================
            // POST ENDPOINTS (All require token)
            // ============================================
            ("POST", "/reset") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    // FIX #10: Recreate baseline from current state
                    let state = crate::detect::collect_state();
                    match baseline::create_baseline(&state) {
                        Ok(_) => {
                            // FIX: Refresh the in-memory cache too - otherwise the daemon
                            // keeps scoring against the OLD baseline (stale deductions)
                            // until Run Auto-Repair happens to force a reload, or the
                            // process restarts.
                            let mut guard = crate::BASELINE.lock().unwrap();
                            *guard = Some(state);
                            json_response(200, r#"{"status":"ok","message":"Baseline reset and recreated"}"#)
                        }
                        Err(e) => json_response(500, &format!(r#"{{"error":"Failed to create baseline: {}"}}"#, json_escape(&e))),
                    }
                }
            }
            ("POST", "/repair") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let result = run_auto_repair();
                    json_response(200, &format!(r#"{{"status":"ok","message":"{}"}}"#, json_escape(&result)))
                }
            }
            ("POST", "/sanitize") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let result = run_scan_only();
                    json_response(200, &format!(r#"{{"status":"ok","message":"{}"}}"#, json_escape(&result)))
                }
            }
            ("POST", "/ghost") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else if crate::modules::repair::ghost_mode_on() {
                    set_ghost_active(true);
                    let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
                    let _ = fs::write(&ghost_flag, "1");
                    set_trust_state("Ghost");
                    json_response(200, r#"{"status":"ok","message":"Ghost Mode enabled"}"#)
                } else {
                    json_response(500, r#"{"status":"error","message":"Ghost Mode failed to apply - system state unchanged, check daemon logs"}"#)
                }
            }
            ("POST", "/unghost") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else if crate::modules::repair::ghost_mode_off() {
                    set_ghost_active(false);
                    let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
                    let _ = fs::remove_file(&ghost_flag);
                    set_trust_state("Trusted");
                    json_response(200, r#"{"status":"ok","message":"Ghost Mode disabled"}"#)
                } else {
                    json_response(500, r#"{"status":"error","message":"Ghost Mode revert failed - firewall state may be inconsistent, retry or check daemon logs"}"#)
                }
            }
            ("POST", "/home") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let ssid = parse_home_ssid(&request);
                    if !ssid.is_empty() {
                        config::save_home_ssid(&ssid);
                        json_response(200, &format!(r#"{{"status":"ok","ssid":"{}"}}"#, json_escape(&ssid)))
                    } else {
                        json_response(400, r#"{"error":"Invalid SSID"}"#)
                    }
                }
            }
            ("POST", "/enable") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    set_ts2_enabled(true);
                    json_response(200, r#"{"status":"ok","message":"Invisibly enabled"}"#)
                }
            }
            ("POST", "/disable") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    set_ts2_enabled(false);
                    json_response(200, r#"{"status":"ok","message":"Invisibly disabled"}"#)
                }
            }
            ("POST", "/rollback") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let result = rollback_changes();
                    json_response(200, &format!(r#"{{"status":"ok","message":"{}"}}"#, json_escape(&result)))
                }
            }
            ("POST", "/restart") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    // FIX: Exit after a short delay so this response reaches the
                    // browser first. Tray's supervision (relaunch on unresponsive
                    // daemon) brings it back within seconds.
                    std::thread::spawn(|| {
                        std::thread::sleep(Duration::from_millis(500));
                        std::process::exit(0);
                    });
                    json_response(200, r#"{"status":"ok","message":"Restarting - daemon will be back within ~10 seconds"}"#)
                }
            }
            ("POST", "/verify_trust") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    crate::modules::trust::manual_verify();
                    let trust_level = get_trust_level();
                    json_response(200, &format!(
                        r#"{{"status":"ok","trust_level":{}}}"#,
                        trust_level
                    ))
                }
            }
            _ => {
                json_response(404, r#"{"error":"Not found"}"#)
            }
        };

        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }
}

// ============================================
// JSON ESCAPE HELPER
// ============================================

fn json_escape(s: &str) -> String {
    let mut escaped = String::new();
    for c in s.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(c),
        }
    }
    escaped
}

// ============================================
// PARSERS
// ============================================

fn parse_request(request: &str) -> (String, String, String) {
    let lines: Vec<&str> = request.lines().collect();
    if lines.is_empty() {
        return ("GET".to_string(), "/".to_string(), String::new());
    }

    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    let method = parts.get(0).unwrap_or(&"GET").to_string();
    let full_path = parts.get(1).unwrap_or(&"/").to_string();
    let path = full_path.split('?').next().unwrap_or("/").to_string();

    let auth = lines.iter()
        .find(|l| l.starts_with("Authorization:"))
        .map(|l| l.replace("Authorization: ", ""))
        .unwrap_or_default();

    (method, path, auth)
}

// ============================================
// PARSE HOME SSID
// ============================================

fn parse_home_ssid(request: &str) -> String {
    if let Some(pos) = request.find("ssid=") {
        let start = pos + 5;
        let end = request[start..].find(&['&', '\n', '\r'][..])
            .map(|i| start + i)
            .unwrap_or(request.len());
        let ssid = request[start..end].trim();
        if !ssid.is_empty() && ssid.len() < 64 {
            return ssid.to_string();
        }
    }
    String::new()
}

// ============================================
// AUTO-REPAIR TRIGGER
// ============================================

pub fn run_auto_repair() -> String {
    use crate::modules::{detect, behavior, repair, integrity, baseline, trust};
    
    // FIX: Force reload baseline from disk
    let baseline_state = match baseline::load_baseline_state() {
        Ok(s) => s,
        Err(e) => return format!("Failed to load baseline: {}", e),
    };
    
    // FIX: Update global baseline cache
    {
        let mut guard = crate::BASELINE.lock().unwrap();
        *guard = Some(baseline_state.clone());
    }
    
    let current = detect::collect_state();
    
    let issues = behavior::detect_all_changes(&baseline_state, &current)
        .into_iter()
        .map(|(cat, details, _)| (cat, details))
        .collect::<Vec<(String, String)>>();
    
    if issues.is_empty() {
        return "No changes detected".to_string();
    }
    
    let mut repaired = Vec::new();
    let mut alerted = Vec::new();
    let mut failed = Vec::new();

    // FIX: These categories only log an alert - they never change system state,
    // so a "success" here must not be reported as "repaired".
    let alert_only = [
        "vpn", "doh", "laps", "eventlog", "dhcp", "bitlocker", "credguard",
        "secureboot", "bloatware", "arp", "wifi", "devices", "tasks",
        "services", "homoglyph", "susp_proc",
    ];

    for (category, _) in &issues {
        let success = match category.as_str() {
            "dns" => repair::flag_dns_changed(),
            "hosts" => repair::restore_hosts(),
            "firewall" => repair::flag_firewall_changed(),
            "proxy" => repair::remove_proxy(),
            "defender" => repair::enable_defender(),
            "uac" => repair::enable_uac(),
            "wu" => repair::enable_windows_update(),
            "sr" => repair::enable_system_restore(),
            "smartscreen" => repair::enable_smart_screen(),
            "ipv6" => repair::enable_ipv6(),
            "wifi_profile" => repair::set_wifi_private(),
            "rdp" => repair::disable_rdp(),
            "vpn" => { repair::alert_vpn_disconnected(); true }
            "doh" => { repair::alert_doh_changed(); true }
            "laps" => { repair::alert_laps_changed(); true }
            "eventlog" => { repair::alert_event_log_cleared(); true }
            "dhcp" => { repair::alert_dhcp_spoofing(); true }
            "bitlocker" => { repair::alert_bitlocker_off(); true }
            "credguard" => { repair::alert_credential_guard_off(); true }
            "secureboot" => { repair::alert_secure_boot(); true }
            "bloatware" => { repair::alert_bloatware(); true }
            "arp" => { repair::alert_service_change(); true }
            "wifi" => { repair::alert_new_device(); true }
            "devices" => { repair::alert_new_device(); true }
            "tasks" => { repair::alert_service_change(); true }
            "services" => { repair::alert_service_change(); true }
            "trojan_source" => { repair::clean_unicode_bidi(); true }
            "homoglyph" => { repair::alert_suspicious_process(); true }
            "susp_proc" => { repair::alert_suspicious_process(); true }
            "fakeext" => repair::flag_fake_extensions(),
            "hid" => repair::disable_hid_devices(),
            "bt" => repair::disable_bt_devices(),
            "adapter" => repair::disable_unknown_adapters(),
            "startup" => repair::flag_startup_changed(),
            "bruteforce" => repair::flag_bruteforce_detected(),
            _ => true,
        };

        if !success {
            failed.push(category.clone());
        } else if alert_only.contains(&category.as_str()) {
            alerted.push(category.clone());
        } else {
            repaired.push(category.clone());
        }
    }
    
    let current_after = detect::collect_state();

    // FIX: Once a repair is verified to have actually changed system state,
    // sync the baseline for that field - otherwise the same drift gets
    // re-flagged (and re-deducted) on every future scan even though it was
    // genuinely fixed. Only synced for the well-defined "automatic" tier
    // (see repair.rs module doc) - never for confirm-required/quarantine
    // categories, so those stay visible for manual review.
    let rebaseline_safe = [
        "dns", "hosts", "firewall", "proxy", "defender", "uac", "wu", "sr",
        "smartscreen", "ipv6", "wifi_profile", "rdp", "trojan_source",
    ];
    let mut synced_baseline = baseline_state.clone();
    let mut did_sync = false;
    for category in &repaired {
        if !rebaseline_safe.contains(&category.as_str()) {
            continue;
        }
        did_sync = true;
        match category.as_str() {
            "dns" => synced_baseline.dns_servers = current_after.dns_servers.clone(),
            "hosts" => synced_baseline.hosts_hash = current_after.hosts_hash.clone(),
            "firewall" => synced_baseline.firewall_profiles = current_after.firewall_profiles.clone(),
            "proxy" => synced_baseline.proxy_settings = current_after.proxy_settings.clone(),
            "defender" => synced_baseline.defender_status = current_after.defender_status.clone(),
            "uac" => synced_baseline.uac_status = current_after.uac_status.clone(),
            "wu" => synced_baseline.windows_update_status = current_after.windows_update_status.clone(),
            "sr" => synced_baseline.system_restore_status = current_after.system_restore_status.clone(),
            "smartscreen" => synced_baseline.smart_screen_status = current_after.smart_screen_status.clone(),
            "ipv6" => synced_baseline.ipv6_status = current_after.ipv6_status.clone(),
            "wifi_profile" => synced_baseline.wifi_profile_status = current_after.wifi_profile_status.clone(),
            "rdp" => synced_baseline.rdp_status = current_after.rdp_status.clone(),
            "trojan_source" => synced_baseline.unicode_bidi_files = current_after.unicode_bidi_files.clone(),
            _ => {}
        }
    }
    if did_sync {
        if baseline::create_baseline(&synced_baseline).is_ok() {
            let mut guard = crate::BASELINE.lock().unwrap();
            *guard = Some(synced_baseline.clone());
        } else {
            did_sync = false;
        }
    }
    let baseline_for_check = if did_sync { &synced_baseline } else { &baseline_state };

    let issues_after = behavior::detect_all_changes(baseline_for_check, &current_after)
        .into_iter()
        .map(|(cat, details, _)| (cat, details))
        .collect::<Vec<(String, String)>>();
    let is_lockdown = repair::is_ghost_active();
    let report = integrity::calculate(&issues_after, is_lockdown, true);
    set_integrity_report(report.clone());
    set_trust_level(trust::get_trust_score());

    format!(
        "Repaired: {:?} | Alerted (no fix applied - needs manual review): {:?} | Failed: {:?} | New Score: {}",
        repaired, alerted, failed, report.score
    )
}

// ============================================
// SCAN ONLY - read-only version of run_auto_repair().
// Refreshes the report immediately but never changes system state.
// ============================================

pub fn run_scan_only() -> String {
    use crate::modules::{detect, behavior, integrity, baseline, repair, trust};

    let baseline_status = baseline::verify_baseline();
    if !baseline_status.valid {
        let report = integrity::calculate(&[], false, false);
        set_integrity_report(report.clone());
        return "Scanned 34 signals | Baseline INVALID - manual review required".to_string();
    }

    let baseline_state = match baseline::load_baseline_state() {
        Ok(s) => s,
        Err(e) => return format!("Failed to load baseline: {}", e),
    };

    let current = detect::collect_state();
    let issues = behavior::detect_all_changes(&baseline_state, &current)
        .into_iter()
        .map(|(cat, details, _)| (cat, details))
        .collect::<Vec<(String, String)>>();

    let is_lockdown = repair::is_ghost_active();
    let report = integrity::calculate(&issues, is_lockdown, true);
    set_integrity_report(report.clone());
    set_trust_level(trust::get_trust_score());

    let categories: Vec<&String> = issues.iter().map(|(cat, _)| cat).collect();
    if categories.is_empty() {
        format!("Scanned 34 signals | No issues found | Score: {}", report.score)
    } else {
        format!("Scanned 34 signals | {} issue(s) found: {:?} | Score: {}", categories.len(), categories, report.score)
    }
}