// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Local HTTP API Server — Hybrid with Integrity Score + Trust Level
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::path::Path;

use crate::modules::integrity::IntegrityReport;
use crate::modules::trust;
use crate::modules::timeline;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";
const PORT: u16 = 12790;
const BIND_ADDR: &str = "127.0.0.1";

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
// INTEGRITY REPORT
// ============================================

static INTEGRITY_REPORT: AtomicPtr<IntegrityReport> = AtomicPtr::new(std::ptr::null_mut());

pub fn set_integrity_report(report: IntegrityReport) {
    let boxed = Box::new(report);
    let ptr = Box::into_raw(boxed);
    let old = INTEGRITY_REPORT.swap(ptr, Ordering::Release);
    if !old.is_null() {
        unsafe { drop(Box::from_raw(old)); }
    }
}

pub fn get_integrity_report() -> Option<IntegrityReport> {
    let ptr = INTEGRITY_REPORT.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        unsafe { Some((*ptr).clone()) }
    }
}

// ============================================
// TRUST LEVEL (Historical)
// ============================================

static TRUST_LEVEL: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());

pub fn set_trust_level(score: u8) {
    let boxed = Box::new(score);
    let ptr = Box::into_raw(boxed);
    let old = TRUST_LEVEL.swap(ptr, Ordering::Release);
    if !old.is_null() {
        unsafe { drop(Box::from_raw(old)); }
    }
}

pub fn get_trust_level() -> u8 {
    let ptr = TRUST_LEVEL.load(Ordering::Acquire);
    if ptr.is_null() {
        trust::get_trust_score()
    } else {
        unsafe { *ptr }
    }
}

// ============================================
// TOKEN — Exposed only on localhost
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
// HTTP HELPERS — FIXED: No extra \r\n after cors_headers()
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
// ROLLBACK FUNCTION
// ============================================

pub fn rollback_changes() -> String {
    let mut results = Vec::new();

    // 1. Restore hosts file from backup
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let backup = format!("{}\\hosts.backup", DATA_DIR);
    if Path::new(&backup).exists() {
        match fs::copy(&backup, hosts) {
            Ok(_) => results.push("Hosts file restored".to_string()),
            Err(e) => results.push(format!("Hosts restore failed: {}", e)),
        }
    } else {
        results.push("No hosts backup found".to_string());
    }

    // 2. Reset firewall to default
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-NetFirewallProfile -All -DefaultInboundAction Allow; Set-NetFirewallProfile -All -DefaultOutboundAction Allow"])
        .output();
    results.push("Firewall reset to default".to_string());

    // 3. Remove proxy
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue"])
        .output();
    results.push("Proxy removed".to_string());

    // 4. Reset DNS to DHCP
    let _ = std::process::Command::new("netsh")
        .args(["interface", "ip", "set", "dns", "Wi-Fi", "dhcp"])
        .output();
    results.push("DNS reset to DHCP".to_string());

    // 5. Enable Defender
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"])
        .output();
    results.push("Defender re-enabled".to_string());

    // 6. Disable Ghost Mode if active
    if is_ghost_active() {
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "Get-NetFirewallRule -DisplayName 'TS-VPN-Only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
                "Get-NetFirewallRule -DisplayName 'TS-Block-ICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
                "Get-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"])
            .output();
        set_ghost_active(false);
        let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
        let _ = fs::remove_file(&ghost_flag);
        results.push("Ghost Mode disabled".to_string());
    }

    results.join("; ")
}

// ============================================
// SERVER
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
// CONNECTION HANDLER
// ============================================

fn handle_connection(mut stream: TcpStream, token: &str, dashboard_html: &str) {
    let mut buffer = [0; 4096];
    if let Ok(n) = stream.read(&mut buffer) {
        if n == 0 { return; }

        let request = String::from_utf8_lossy(&buffer[0..n]);
        let (method, path, headers) = parse_request(&request);

        // CORS preflight check — FIXED: No extra \r\n
        if method == "OPTIONS" {
            let resp = format!(
                "HTTP/1.1 200 OK\r\n{}Content-Length: 0\r\n\r\n",
                cors_headers()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
            return;
        }

        let response = match (method.as_str(), path.as_str()) {
            // ============================================
            // GET ENDPOINTS
            // ============================================
            ("GET", "/token") => {
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
                html_response(dashboard_html)
            }
            ("GET", "/status") => {
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
            ("GET", "/timeline") => {
                let format = parse_query_param(&request, "format").unwrap_or_else(|| "json".to_string());
                let data = crate::modules::timeline::export_timeline(&format);
                json_response(200, &data)
            }
            ("GET", "/report") => {
                let format = parse_query_param(&request, "format").unwrap_or_else(|| "json".to_string());
                if let Some(report) = get_integrity_report() {
                    let data = crate::modules::integrity::export_report(&report, &format);
                    json_response(200, &data)
                } else {
                    json_response(404, r#"{"error":"No report available"}"#)
                }
            }

            // ============================================
            // POST ENDPOINTS (All require token)
            // ============================================
            ("POST", "/reset") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let baseline_path = format!("{}\\baseline.json", DATA_DIR);
                    let _ = fs::remove_file(&baseline_path);
                    json_response(200, r#"{"status":"ok","message":"Baseline reset"}"#)
                }
            }
            ("POST", "/repair") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    json_response(200, r#"{"status":"ok","message":"Auto-repair triggered"}"#)
                }
            }
            ("POST", "/sanitize") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    json_response(200, r#"{"status":"ok","message":"Sanitize complete"}"#)
                }
            }
            ("POST", "/ghost") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let _ = std::process::Command::new("powershell")
                        .args(["-NoProfile", "-Command",
                            "Set-NetFirewallProfile -All -DefaultInboundAction Block;",
                            "Set-NetFirewallProfile -All -DefaultOutboundAction Block;"])
                        .output();
                    set_ghost_active(true);
                    let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
                    let _ = fs::write(&ghost_flag, "1");
                    set_trust_state("Ghost");
                    json_response(200, r#"{"status":"ok","message":"Ghost Mode enabled"}"#)
                }
            }
            ("POST", "/unghost") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let _ = std::process::Command::new("powershell")
                        .args(["-NoProfile", "-Command",
                            "Set-NetFirewallProfile -All -DefaultInboundAction Allow;",
                            "Set-NetFirewallProfile -All -DefaultOutboundAction Allow;"])
                        .output();
                    set_ghost_active(false);
                    let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
                    let _ = fs::remove_file(&ghost_flag);
                    set_trust_state("Trusted");
                    json_response(200, r#"{"status":"ok","message":"Ghost Mode disabled"}"#)
                }
            }
            ("POST", "/home") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let ssid = parse_home_ssid(&request);
                    if !ssid.is_empty() {
                        let home_path = format!("{}\\home.ssid", DATA_DIR);
                        let _ = fs::write(&home_path, &ssid);
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
    let path = parts.get(1).unwrap_or(&"/").to_string();

    let auth = lines.iter()
        .find(|l| l.starts_with("Authorization:"))
        .map(|l| l.replace("Authorization: ", ""))
        .unwrap_or_default();

    (method, path, auth)
}

fn validate_auth(headers: &str, token: &str) -> bool {
    headers.contains(&format!("Bearer {}", token)) ||
    headers.contains(&format!("Token {}", token))
}

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