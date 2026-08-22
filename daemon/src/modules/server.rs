// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Local HTTP API Server — Hybrid with Integrity Score + Trust Level
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::os::windows::process::CommandExt;
use std::fs;

const CREATE_NO_WINDOW: u32 = 0x08000000;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::path::Path;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;

use crate::modules::integrity::IntegrityReport;
use crate::BASELINE;
use crate::modules::trust;
use crate::modules::config;
use crate::modules::baseline;
use crate::modules::timeline;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";
const PORT: u16 = 12790;
const BIND_ADDR: &str = "127.0.0.1";
const READ_TIMEOUT_SECS: u64 = 10;
const MAX_CONCURRENT_CONNECTIONS: usize = 10;
const TOKEN_COUNTER_FILE: &str = "C:\\ProgramData\\Invisibly\\token_counter.txt";

// ============================================
// CONNECTION COUNTER (Rate Limiting)
// ============================================

static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

// ============================================
// TRUST STATE (Legacy)
// ============================================

// FIX: this used to store a &'static str as a raw AtomicPtr<()> and read it
// back via CStr::from_ptr - but a Rust &str is a (pointer, length) pair, not
// a null-terminated C string. CStr::from_ptr ignored the real length and
// scanned memory for the next zero byte, reading straight past "Trusted"
// into whatever string literal the compiler placed next in .rdata (observed
// live: get_trust_state() returned "Trusted" followed by an unrelated error
// message from elsewhere in the binary). That garbage then went straight
// into unescaped JSON in the /status response, breaking the tray's parser
// and making a perfectly healthy daemon look "offline".
static TRUST_STATE: Mutex<&'static str> = Mutex::new("Trusted");

pub fn set_trust_state(state: &'static str) {
    *TRUST_STATE.lock().unwrap() = state;
}

pub fn get_trust_state() -> String {
    TRUST_STATE.lock().unwrap().to_string()
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
// FIRST-RUN CONSENT
// ============================================

// Defaults to true (awaiting) until main.rs checks the on-disk flag at
// startup and flips it - assume no consent has been given until proven
// otherwise, never the reverse.
static AWAITING_CONSENT: AtomicBool = AtomicBool::new(true);

pub fn set_awaiting_consent(awaiting: bool) {
    AWAITING_CONSENT.store(awaiting, Ordering::Release);
}

pub fn is_awaiting_consent() -> bool {
    AWAITING_CONSENT.load(Ordering::Acquire)
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
// RANSOMWARE ALERT (real-time watcher, see watcher.rs) - reflects current
// state, auto-clears itself once activity settles, same pattern as
// TAMPER_DETECTED above.
// ============================================

static RANSOMWARE_ALERT: AtomicBool = AtomicBool::new(false);

pub fn set_ransomware_alert(active: bool) {
    RANSOMWARE_ALERT.store(active, Ordering::Release);
}

pub fn is_ransomware_alert() -> bool {
    RANSOMWARE_ALERT.load(Ordering::Acquire)
}

// ============================================
// INTEGRITY REPORT
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
// ELEVATION STATE (for tray UX - see run_daemon())
// ============================================

static ELEVATED: AtomicBool = AtomicBool::new(true);

pub fn set_elevated(elevated: bool) {
    ELEVATED.store(elevated, Ordering::Release);
}

pub fn is_elevated() -> bool {
    ELEVATED.load(Ordering::Acquire)
}

// ============================================
// TAMPER DETECTION (self-integrity) - reflects the current check result,
// same as ELEVATED/GHOST_ACTIVE above. This is the one state the tool
// surfaces to a human instead of silently auto-repairing.
// ============================================

static TAMPER_DETECTED: AtomicBool = AtomicBool::new(false);

pub fn set_tamper_detected(detected: bool) {
    TAMPER_DETECTED.store(detected, Ordering::Release);
}

pub fn is_tamper_detected() -> bool {
    TAMPER_DETECTED.load(Ordering::Acquire)
}

// ============================================
// TRUST LEVEL
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
// TOKEN - Persist rotation counter to disk
// ============================================

fn get_token() -> String {
    let token_path = format!("{}\\agent.token", DATA_DIR);
    
    let counter = fs::read_to_string(TOKEN_COUNTER_FILE)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0);
    
    if counter >= 100 {
        let new_token = format!("{:x}", rand::random::<u128>()) + &format!("{:x}", rand::random::<u128>());
        let encrypted = crate::crypto::encrypt_data(new_token.as_bytes(), &crate::crypto::get_xor_key());
        let _ = fs::write(&token_path, encrypted);
        let _ = fs::write(TOKEN_COUNTER_FILE, "0");
        return new_token;
    }
    
    if let Ok(encrypted) = fs::read(&token_path) {
        if let Ok(decrypted) = crate::crypto::decrypt_data(&encrypted, &crate::crypto::get_xor_key()) {
            if let Ok(token) = String::from_utf8(decrypted) {
                let _ = fs::write(TOKEN_COUNTER_FILE, &(counter + 1).to_string());
                return token.trim().to_string();
            }
        }
    }
    
    let new_token = format!("{:x}", rand::random::<u128>()) + &format!("{:x}", rand::random::<u128>());
    let encrypted = crate::crypto::encrypt_data(new_token.as_bytes(), &crate::crypto::get_xor_key());
    let _ = fs::write(&token_path, encrypted);
    let _ = fs::write(TOKEN_COUNTER_FILE, "1");
    new_token
}

// NEW: config::ensure_data_dir() deliberately grants the plain logged-in
// user FullControl across all of C:\ProgramData\Invisibly (recursively),
// so the daemon can still read its own files if it's ever running
// unelevated - that grant meant any *other* local process running as the
// same user (e.g. malware, the exact threat model this product exists to
// catch) could read+decrypt agent.token straight off disk, bypassing the
// /token HTTP gate entirely. agent.token specifically doesn't need that
// grant: the daemon's normal, steady-state deployment is elevated (the
// Scheduled Task runs at Highest), and get_token()'s existing fallback
// (regenerate an in-memory token, `let _ = fs::write(...)` tolerating a
// failed persist) already degrades gracefully if a rare unelevated run
// can't read/write it - so this can be locked to Administrators/SYSTEM
// only without breaking that fallback path. Re-applied on every call
// (single call, at server startup) so it can't be silently re-widened by
// a later ensure_data_dir() pass.
fn restrict_token_file_acl(path: &str) {
    // ensure_data_dir() grants this as an explicit (non-inherited) ACE, so
    // /inheritance:r alone won't strip it - it has to be removed by name.
    let username = std::env::var("USERNAME").unwrap_or_default();
    let mut args: Vec<String> = vec![
        path.to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(), "SYSTEM:F".to_string(),
        "/grant:r".to_string(), "Administrators:F".to_string(),
        "/remove".to_string(), "Users".to_string(),
        "/remove".to_string(), "Everyone".to_string(),
    ];
    if !username.is_empty() {
        args.push("/remove".to_string());
        args.push(username);
    }

    let result = std::process::Command::new("icacls")
        .args(&args)
        .creation_flags(CREATE_NO_WINDOW)
        .status();

    match result {
        Ok(status) if status.success() => {}
        Ok(status) => {
            crate::modules::config::log_acl_failure(&format!(
                "agent.token ACL restriction failed with exit code: {}", status.code().unwrap_or(-1)
            ));
        }
        Err(e) => {
            crate::modules::config::log_acl_failure(&format!("Failed to run icacls on agent.token: {}", e));
        }
    }
}

// ============================================
// CORS
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

// NEW: ZAP flagged /dashboard as missing clickjacking protection and a CSP -
// a malicious page a user has open in another tab could iframe the dashboard
// and trick them into clicking a real control underneath a fake overlay.
// frame-ancestors 'none' (+ X-Frame-Options for older browsers) closes that.
// 'unsafe-inline' is needed for script-src/style-src since dashboard.html's
// JS and some styling are inline, not external files - a real limitation,
// not a full CSP, but still blocks loading any attacker-controlled remote
// script/resource, which is the bigger win here. nosniff also closes the
// X-Content-Type-Options findings.
fn security_headers() -> &'static str {
    "X-Frame-Options: DENY\r\n\
     Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'\r\n\
     X-Content-Type-Options: nosniff\r\n"
}

fn json_response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\n{}{}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status_string(status),
        cors_headers(),
        security_headers(),
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
        429 => "429 Too Many Requests",
        500 => "500 Internal Server Error",
        _ => "500 Internal Server Error"
    }
}

fn html_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n{}{}Content-Type: text/html\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\nContent-Length: {}\r\n\r\n{}",
        cors_headers(),
        security_headers(),
        body.len(),
        body
    )
}

fn unauthorized() -> String {
    json_response(403, r#"{"error":"Unauthorized - Invalid token"}"#)
}

fn rate_limited() -> String {
    json_response(429, r#"{"error":"Too many concurrent connections"}"#)
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
// PARSE REQUEST BODY
// ============================================

fn parse_request_body(request: &str, param: &str) -> Option<String> {
    if let Some(body) = request.split("\r\n\r\n").nth(1) {
        if let Some(pos) = body.find(&format!("\"{}\":\"", param)) {
            let start = pos + param.len() + 3;
            if let Some(end) = body[start..].find('"') {
                return Some(body[start..start + end].to_string());
            }
        }
        if let Some(pos) = body.find(&format!("{}=", param)) {
            let start = pos + param.len() + 1;
            let end = body[start..].find(&['&', '\n', '\r'][..])
                .map(|i| start + i)
                .unwrap_or(body.len());
            return Some(body[start..end].to_string());
        }
    }
    None
}

// ============================================
// ROLLBACK FUNCTION
// ============================================

pub fn rollback_changes() -> String {
    let mut results = Vec::new();

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

    let ran_ok = |out: std::io::Result<std::process::Output>| -> bool {
        matches!(out, Ok(o) if o.status.success())
    };

    let ok = ran_ok(std::process::Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Set-NetFirewallProfile -All -DefaultInboundAction Allow; Set-NetFirewallProfile -All -DefaultOutboundAction Allow"])
        .output());
    results.push(if ok { "Firewall reset to default".to_string() } else { "Firewall reset FAILED".to_string() });

    let ok = ran_ok(std::process::Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command",
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue"])
        .output());
    results.push(if ok { "Proxy removed".to_string() } else { "Proxy removal FAILED".to_string() });

    let ok = ran_ok(std::process::Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command",
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }"])
        .output());
    results.push(if ok { "DNS reset to DHCP (active adapter)".to_string() } else { "DNS reset FAILED".to_string() });

    let ok = ran_ok(std::process::Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"])
        .output());
    results.push(if ok { "Defender re-enabled".to_string() } else { "Defender re-enable FAILED".to_string() });

    if is_ghost_active() {
        let ok = ran_ok(std::process::Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
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
    restrict_token_file_acl(&format!("{}\\agent.token", DATA_DIR));

    let dashboard_html = include_str!("../web/dashboard.html");
    let consent_html = build_consent_html();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let token_clone = token.clone();
                let dashboard_clone = dashboard_html.to_string();
                let consent_clone = consent_html.clone();
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let current = ACTIVE_CONNECTIONS.load(Ordering::SeqCst);
                    if current >= MAX_CONCURRENT_CONNECTIONS {
                        let _ = stream.write_all(rate_limited().as_bytes());
                        let _ = stream.flush();
                        return;
                    }
                    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
                    handle_connection(stream, &token_clone, &dashboard_clone, &consent_clone);
                    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
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
// CONSENT PAGE
// ============================================

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Builds the first-run consent page by embedding the actual shipped
/// Privacy Policy and EULA text (single source of truth - these files,
/// not a copy pasted into the page) so what the user reads here always
/// matches what's in the package.
fn build_consent_html() -> String {
    let template = include_str!("../web/consent.html");
    let privacy = include_str!("../../../msix_package/privacy.html");
    let license = include_str!("../../../LICENSE.txt");
    template
        .replace("__PRIVACY_POLICY_TEXT__", &html_escape(privacy))
        .replace("__LICENSE_TEXT__", &html_escape(license))
}

// ============================================
// AUTH VALIDATOR
// ============================================

fn validate_auth(headers: &str, token: &str) -> bool {
    let lower_headers = headers.to_lowercase();
    let lower_bearer = format!("bearer {}", token.to_lowercase());
    let lower_token = format!("token {}", token.to_lowercase());
    lower_headers.contains(&lower_bearer) || lower_headers.contains(&lower_token)
}

// NEW: GET /token used to hand the real bearer token to any local caller
// with zero credentials - the Authorization check on every other endpoint
// was then trivially bypassable by any other process on the machine (the
// exact "malware already running locally" threat model this product exists
// to catch) just by calling /token first. Since the dashboard is loaded
// straight in a browser with no pre-shared secret, and the tray fetches its
// own token the same way over HTTP, app-layer credentials alone can't
// distinguish "the real dashboard/tray" from "any other local process" -
// the one thing that can is *which OS process* is on the other end of the
// loopback connection. Resolve the caller's PID from the connection's
// remote port and only hand out the token to our own tray.exe or a real
// browser (what the dashboard is meant to be opened in). Anything else -
// a bare script, curl, PowerShell, malware - gets refused. Not perfect
// (a fully privileged/renamed attacker could still spoof this), but it
// closes the zero-effort "just curl /token" path.
fn caller_process_path(peer_port: u16) -> Option<String> {
    let script = format!(
        "$c = Get-NetTCPConnection -LocalPort {} -RemotePort {} -State Established -ErrorAction SilentlyContinue | Select-Object -First 1; if ($c) {{ (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).Path }}",
        PORT, peer_port
    );
    let out = std::process::Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", &script])
        .output().ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() { None } else { Some(path) }
}

fn is_trusted_token_caller(peer_addr: Option<std::net::SocketAddr>) -> bool {
    // Browsers can legitimately live in many install locations, so they're
    // matched by filename only - a weaker check, but browsers aren't what
    // malware typically renames itself to. Our OWN tray binary, on the
    // other hand, always ships as invisibly-tray.exe right next to
    // invisibly-daemon.exe, so it's matched by exact full path - filename-
    // only would let anything renamed "invisibly-tray.exe" from any folder
    // pass as trusted, which defeats the point of this check.
    const TRUSTED_BROWSER_SUFFIXES: [&str; 6] = [
        "\\chrome.exe", "\\msedge.exe", "\\firefox.exe",
        "\\brave.exe", "\\opera.exe", "\\iexplore.exe",
    ];
    let Some(addr) = peer_addr else { return false; };
    let Some(path) = caller_process_path(addr.port()) else { return false; };
    let lower = path.to_lowercase();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let expected_tray = dir.join("invisibly-tray.exe");
            if let Some(expected) = expected_tray.to_str() {
                if lower == expected.to_lowercase() {
                    return true;
                }
            }
        }
    }

    TRUSTED_BROWSER_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

// ============================================
// CONNECTION HANDLER
// ============================================

fn handle_connection(mut stream: TcpStream, token: &str, dashboard_html: &str, consent_html: &str) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));

    let mut buffer = [0; 4096];
    if let Ok(n) = stream.read(&mut buffer) {
        if n == 0 { return; }

        let request = String::from_utf8_lossy(&buffer[0..n]);
        let (method, path, headers) = parse_request(&request);

        if method == "OPTIONS" {
            let resp = format!(
                "HTTP/1.1 200 OK\r\n{}Content-Length: 0\r\n\r\n",
                cors_headers()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
            return;
        }

        let is_auth_required = !matches!(path.as_str(), "/" | "/dashboard" | "/token" | "/accept_consent");

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
                if is_trusted_token_caller(stream.peer_addr().ok()) {
                    json_response(200, &format!(r#"{{"token":"{}"}}"#, token))
                } else {
                    unauthorized()
                }
            }
            ("GET", "/") => {
                let trust_state = get_trust_state();
                let ghost = is_ghost_active();
                let enabled = is_ts2_enabled();
                let report = get_integrity_report();
                let score = report.as_ref().map(|r| r.score).unwrap_or(0);
                let state_str = report.as_ref().map(|r| format!("{:?}", r.state)).unwrap_or_else(|| "Unknown".to_string());
                let trust_level = get_trust_level();
                let elevated = is_elevated();
                let tamper_detected = is_tamper_detected();
                let ransomware_alert = is_ransomware_alert();

                json_response(200, &format!(
                    r#"{{"status":"ok","trust_state":"{}","ghost":{},"enabled":{},"integrity_score":{},"integrity_state":"{}","trust_level":{},"elevated":{},"tamper_detected":{},"ransomware_alert":{},"awaiting_consent":{},"is_pro":{}}}"#,
                    trust_state,
                    ghost,
                    enabled,
                    score,
                    state_str,
                    trust_level,
                    elevated,
                    tamper_detected,
                    ransomware_alert,
                    is_awaiting_consent(),
                    crate::modules::license::is_pro_licensed()
                ))
            }
            ("GET", "/dashboard") => {
                if is_awaiting_consent() {
                    html_response(consent_html)
                } else {
                    html_response(dashboard_html)
                }
            }
            ("POST", "/accept_consent") => {
                let path = format!("{}\\consent_accepted.txt", DATA_DIR);
                let record = format!(
                    "Accepted at {} (Privacy Policy + Terms of Use, active opt-in)\n",
                    chrono::Local::now().to_rfc3339()
                );
                match fs::write(&path, record) {
                    Ok(_) => {
                        set_awaiting_consent(false);
                        json_response(200, r#"{"status":"ok"}"#)
                    }
                    Err(e) => json_response(500, &format!(r#"{{"error":"{}"}}"#, e))
                }
            }
            ("GET", "/status") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let trust_state = get_trust_state();
                    let ghost = is_ghost_active();
                    let enabled = is_ts2_enabled();
                    let report = get_integrity_report();
                    let score = report.as_ref().map(|r| r.score).unwrap_or(0);
                    let trust_level = get_trust_level();
                    let elevated = is_elevated();
                    let tamper_detected = is_tamper_detected();
                    let ransomware_alert = is_ransomware_alert();
                    let is_pro = crate::modules::license::is_pro_licensed();
                    json_response(200, &format!(
                        r#"{{"trust_state":"{}","ghost":{},"enabled":{},"integrity_score":{},"trust_level":{},"elevated":{},"tamper_detected":{},"ransomware_alert":{},"is_pro":{}}}"#,
                        trust_state,
                        ghost,
                        enabled,
                        score,
                        trust_level,
                        elevated,
                        tamper_detected,
                        ransomware_alert,
                        is_pro
                    ))
                }
            }
            ("GET", "/timeline") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let format = parse_query_param(&request, "format").unwrap_or_else(|| "json".to_string());
                    let data = crate::modules::timeline::export_timeline(&format);
                    json_response(200, &data)
                }
            }
            ("GET", "/report") => {
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
            // POST ENDPOINTS
            // ============================================
            ("POST", "/reset") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let state = crate::detect::collect_state();
                    match baseline::create_baseline(&state) {
                        Ok(_) => {
                            let mut guard = crate::BASELINE.lock().unwrap();
                            *guard = Some(state.clone());
                            
                            let issues = crate::modules::behavior::detect_all_changes(&state, &state);
                            let issues_for_score: Vec<(String, String)> = issues.iter()
                                .map(|(cat, details, _)| (cat.clone(), details.clone()))
                                .collect();
                            let report = crate::modules::integrity::calculate(&issues_for_score, false, true);
                            set_integrity_report(report);
                            
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
                } else if !crate::modules::license::is_pro_licensed() {
                    json_response(402, r#"{"status":"error","message":"Ghost Mode requires an active Pro subscription"}"#)
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
            ("GET", "/watched-folders") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let folders = crate::modules::config::load_watched_folders();
                    let list = folders.iter().map(|f| format!("\"{}\"", json_escape(f))).collect::<Vec<_>>().join(",");
                    json_response(200, &format!(r#"{{"folders":[{}]}}"#, list))
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
                    let reason = parse_request_body(&request, "reason").unwrap_or_else(|| "API request".to_string());
                    crate::modules::trust::manual_verify_with_reason(&reason, "dashboard-user");
                    // FIX: Sync the atomic immediately after trust mutation
                    set_trust_level(crate::modules::trust::get_trust_score());
                    let trust_level = get_trust_level();
                    json_response(200, &format!(
                        r#"{{"status":"ok","trust_level":{}}}"#,
                        trust_level
                    ))
                }
            }
            // ============================================
            // NEW: /approve endpoint for confirm-required items
            // ============================================
            ("POST", "/approve") => {
                if !validate_auth(&headers, token) {
                    unauthorized()
                } else {
                    let category = parse_query_param(&request, "category").unwrap_or_default();
                    if category.is_empty() {
                        json_response(400, r#"{"error":"Category parameter required"}"#)
                    } else {
                        let pending = check_pending_approval(&category);
                        if !pending {
                            json_response(400, &format!(r#"{{"error":"Category '{}' is not pending approval"}}"#, json_escape(&category)))
                        } else {
                            let result = crate::modules::repair::execute_confirmed_repair(&category);
                            let _ = timeline::add_entry(
                                &category,
                                "approved",
                                "pending_approval",
                                &result,
                                timeline::RepairResult::Success
                            );
                            json_response(200, &format!(r#"{{"status":"ok","message":"{}"}}"#, json_escape(&result)))
                        }
                    }
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
    
    let baseline_state = match baseline::load_baseline_state() {
        Ok(s) => s,
        Err(e) => return format!("Failed to load baseline: {}", e),
    };
    
    {
        let mut guard = crate::BASELINE.lock().unwrap();
        *guard = Some(baseline_state.clone());
    }
    
    let current = detect::collect_state();
    
    let issues = behavior::detect_all_changes(&baseline_state, &current);
    
    if issues.is_empty() {
        return "No changes detected".to_string();
    }
    
    let mut repaired = Vec::new();
    let mut alerted = Vec::new();
    let mut failed = Vec::new();
    let mut pending_confirm = Vec::new();

    let alert_only = [
        "vpn", "doh", "laps", "eventlog", "dhcp", "bitlocker", "credguard",
        "secureboot", "bloatware", "arp", "wifi", "devices", "tasks",
        "services", "homoglyph", "susp_proc",
    ];

    for (category, details, action_type) in &issues {
        match action_type.as_str() {
            "automatic" => {
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
                    "trojan_source" => repair::clean_unicode_bidi(),
                    _ => true,
                };
                if success {
                    repaired.push(category.clone());
                } else {
                    failed.push(category.clone());
                }
            }
            "confirm" => {
                pending_confirm.push(category.clone());
                let _ = timeline::add_entry(
                    category,
                    "pending_approval",
                    details,
                    "awaiting user confirmation",
                    timeline::RepairResult::AwaitingApproval
                );
            }
            "alert" => {
                alerted.push(category.clone());
                match category.as_str() {
                    "vpn" => { repair::alert_vpn_disconnected(); }
                    "doh" => { repair::alert_doh_changed(); }
                    "laps" => { repair::alert_laps_changed(); }
                    "eventlog" => { repair::alert_event_log_cleared(); }
                    "dhcp" => { repair::alert_dhcp_spoofing(); }
                    "bitlocker" => { repair::alert_bitlocker_off(); }
                    "credguard" => { repair::alert_credential_guard_off(); }
                    "secureboot" => { repair::alert_secure_boot(); }
                    "bloatware" => { repair::alert_bloatware(); }
                    "arp" => { repair::alert_service_change(); }
                    "wifi" => { repair::alert_new_device(); }
                    "devices" => { repair::alert_new_device(); }
                    "tasks" => { repair::alert_service_change(); }
                    "services" => { repair::alert_service_change(); }
                    "homoglyph" => { repair::alert_suspicious_process(); }
                    "susp_proc" => { repair::alert_suspicious_process(); }
                    _ => {}
                }
            }
            "manual" => {
                failed.push(category.clone());
            }
            _ => {}
        }
    }
    
    let current_after = detect::collect_state();

    let rebaseline_safe = [
        "hosts", "proxy", "defender", "uac", "wu", "sr",
        "smartscreen", "ipv6", "wifi_profile", "trojan_source",
    ];
    let mut synced_baseline = baseline_state.clone();
    let mut did_sync = false;
    for category in &repaired {
        if !rebaseline_safe.contains(&category.as_str()) {
            continue;
        }
        did_sync = true;
        match category.as_str() {
            "hosts" => synced_baseline.hosts_hash = current_after.hosts_hash.clone(),
            "proxy" => synced_baseline.proxy_settings = current_after.proxy_settings.clone(),
            "defender" => synced_baseline.defender_status = current_after.defender_status.clone(),
            "uac" => synced_baseline.uac_status = current_after.uac_status.clone(),
            "wu" => synced_baseline.windows_update_status = current_after.windows_update_status.clone(),
            "sr" => synced_baseline.system_restore_status = current_after.system_restore_status.clone(),
            "smartscreen" => synced_baseline.smart_screen_status = current_after.smart_screen_status.clone(),
            "ipv6" => synced_baseline.ipv6_status = current_after.ipv6_status.clone(),
            "wifi_profile" => synced_baseline.wifi_profile_status = current_after.wifi_profile_status.clone(),
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

    let issues_after = behavior::detect_all_changes(baseline_for_check, &current_after);
    let is_lockdown = repair::is_ghost_active();
    let issues_for_score: Vec<(String, String)> = issues_after.iter()
        .map(|(cat, details, _)| (cat.clone(), details.clone()))
        .collect();
    let report = integrity::calculate(&issues_for_score, is_lockdown, true);
    set_integrity_report(report.clone());
    set_trust_level(trust::get_trust_score());

    let mut message = format!(
        "Repaired: {:?} | Alerted: {:?} | Failed: {:?} | Pending Confirm: {:?} | New Score: {}",
        repaired, alerted, failed, pending_confirm, report.score
    );
    if !pending_confirm.is_empty() {
        message.push_str(" | ⚠️ Some changes require manual confirmation");
    }
    message
}

// ============================================
// SCAN ONLY - read-only version of run_auto_repair().
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
    let issues = behavior::detect_all_changes(&baseline_state, &current);
    let issues_for_score: Vec<(String, String)> = issues.iter()
        .map(|(cat, details, _)| (cat.clone(), details.clone()))
        .collect();

    let is_lockdown = repair::is_ghost_active();
    let report = integrity::calculate(&issues_for_score, is_lockdown, true);
    set_integrity_report(report.clone());
    set_trust_level(trust::get_trust_score());

    let categories: Vec<&String> = issues.iter().map(|(cat, _, _)| cat).collect();
    if categories.is_empty() {
        format!("Scanned 34 signals | No issues found | Score: {}", report.score)
    } else {
        format!("Scanned 34 signals | {} issue(s) found: {:?} | Score: {}", categories.len(), categories, report.score)
    }
}

// ============================================
// CHECK PENDING APPROVAL
// ============================================

fn check_pending_approval(category: &str) -> bool {
    use crate::modules::timeline;
    
    let timeline_data = timeline::export_timeline("json");
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&timeline_data) {
        if let Some(entries) = json.as_array() {
            for entry in entries {
                if let (Some(entry_category), Some(action), Some(result)) = (
                    entry.get("category").and_then(|v| v.as_str()),
                    entry.get("action").and_then(|v| v.as_str()),
                    entry.get("result").and_then(|v| v.as_str()),
                ) {
                    if entry_category == category 
                        && action == "pending_approval" 
                        && result == "AwaitingApproval" {
                        return true;
                    }
                }
            }
        }
    }
    false
}