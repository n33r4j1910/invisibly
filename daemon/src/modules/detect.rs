// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

use serde::{Serialize, Deserialize};
use std::process::Command;
use std::os::windows::process::CommandExt;
use std::collections::HashMap;
use std::fs;

const CREATE_NO_WINDOW: u32 = 0x08000000;

// ============================================
// SYSTEM STATE STRUCT
// ============================================

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SystemState {
    // Network
    pub dns_servers: Vec<String>,
    pub hosts_hash: String,
    pub arp_table: Vec<String>,
    pub wifi_ssid: String,
    pub proxy_settings: Vec<String>,
    pub network_devices: Vec<String>,
    pub network_adapters: Vec<String>,
    pub listening_ports: Vec<String>,

    // System Security
    pub startup_entries: Vec<String>,
    pub firewall_profiles: Vec<String>,
    pub scheduled_tasks: Vec<String>,
    pub services_list: Vec<String>,
    pub defender_status: String,
    pub secure_boot: String,
    pub login_failures: String,
    pub suspicious_processes: Vec<String>,
    pub root_cas: Vec<String>,

    // Hardware
    pub bt_devices: Vec<String>,
    pub hid_devices: Vec<String>,

    // Software & Files
    pub installed_software: Vec<String>,
    pub fake_extensions: Vec<String>,
    pub unicode_bidi_files: Vec<String>,

    // Social Engineering
    pub homoglyph_domains: Vec<String>,

    // NEW: 10 Integrity signals
    pub uac_status: String,
    pub windows_update_status: String,
    pub system_restore_status: String,
    pub event_log_status: String,
    pub smart_screen_status: String,
    pub vpn_status: String,
    pub ipv6_status: String,
    pub wifi_profile_status: String,
    pub doh_status: String,
    pub laps_status: String,

    // NEW: 4 Additional detections
    pub dhcp_server: String,
    pub bitlocker_status: String,
    pub credential_guard_status: String,
    pub rdp_status: String,
}

// ============================================
// COLLECT STATE
// ============================================

pub fn collect_state() -> SystemState {
    SystemState {
        dns_servers: get_dns(),
        hosts_hash: get_hosts_hash(),
        arp_table: get_arp(),
        wifi_ssid: get_wifi(),
        proxy_settings: get_proxy(),
        network_devices: get_network_devices(),
        network_adapters: get_network_adapters(),
        listening_ports: get_ports(),

        startup_entries: get_startup(),
        firewall_profiles: get_firewall(),
        scheduled_tasks: get_scheduled_tasks(),
        services_list: get_services(),
        defender_status: get_defender_status(),
        secure_boot: get_secure_boot(),
        login_failures: get_login_failures(),
        suspicious_processes: get_suspicious_processes(),
        root_cas: get_root_cas(),

        bt_devices: get_bt_devices(),
        hid_devices: get_hid_devices(),

        installed_software: get_installed_software(),
        fake_extensions: get_fake_extensions(),
        unicode_bidi_files: get_unicode_bidi_files(),

        homoglyph_domains: get_homoglyph_domains(),

        uac_status: get_uac_status(),
        windows_update_status: get_windows_update_status(),
        system_restore_status: get_system_restore_status(),
        event_log_status: get_event_log_status(),
        smart_screen_status: get_smart_screen_status(),
        vpn_status: get_vpn_status(),
        ipv6_status: get_ipv6_status(),
        wifi_profile_status: get_wifi_profile_status(),
        doh_status: get_doh_status(),
        laps_status: get_laps_status(),

        // NEW: 4 Additional detections
        dhcp_server: get_dhcp_server(),
        bitlocker_status: get_bitlocker_status(),
        credential_guard_status: get_credential_guard_status(),
        rdp_status: get_rdp_status(),
    }
}

// ============================================
// NETWORK DETECTIONS — FIX #3: Fail-open fixed
// ============================================

pub fn get_dns() -> Vec<String> {
    let mut d = Vec::new();
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | ForEach-Object {$_.ServerAddresses -join ','}"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            for a in l.split(',') {
                let a = a.trim().to_string();
                if !a.is_empty() && !d.contains(&a) { d.push(a); }
            }
        }
    }
    // FIX: If detection fails, return ERROR state, not "Unknown"
    if d.is_empty() { d.push("ERROR_DNS_DETECTION_FAILED".into()); }
    d
}

pub fn get_hosts_hash() -> String {
    if let Ok(c) = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts") {
        hex::encode(ring::digest::digest(&ring::digest::SHA256, c.as_bytes()))
    } else {
        "ERROR_HOSTS_UNREADABLE".into()
    }
}

pub fn get_arp() -> Vec<String> {
    let mut a = Vec::new();
    if let Ok(o) = Command::new("arp").creation_flags(CREATE_NO_WINDOW).args(["-a"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            // FIX #15: Broader pattern matching for non-English Windows
            if l.contains("dynamic") || l.contains("static") || l.contains("dynamique") || l.contains("statique") || l.contains("dinámico") || l.contains("estático") {
                a.push(l.trim().to_string());
            }
        }
    }
    // FIX: Sort so a stable ARP cache doesn't register as "changed" just
    // because the OS returned entries in a different order this time.
    a.sort();
    // FIX: If detection fails, return ERROR state
    if a.is_empty() { a.push("ERROR_ARP_DETECTION_FAILED".into()); }
    a
}

pub fn get_wifi() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","(Get-NetConnectionProfile | Where-Object {$_.InterfaceAlias -like '*Wi*' -or $_.InterfaceAlias -like '*Wireless*'} | Select-Object -First 1).Name"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() { return s; }
    }
    "ERROR_WIFI_DETECTION_FAILED".into()
}

pub fn get_proxy() -> Vec<String> {
    let mut p = Vec::new();
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyServer, ProxyEnable | ForEach-Object { $_.ProxyEnable.ToString() + ':' + $_.ProxyServer }"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { p.push(l.trim().to_string()); }
        }
    }
    if p.is_empty() { p.push("ERROR_PROXY_DETECTION_FAILED".into()); }
    p
}

pub fn get_network_devices() -> Vec<String> {
    let mut d = Vec::new();
    if let Ok(o) = Command::new("arp").creation_flags(CREATE_NO_WINDOW).args(["-a"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            // FIX #15: Broader pattern matching
            if l.contains("dynamic") || l.contains("dynamique") || l.contains("dinámico") {
                if let Some(ip) = l.split_whitespace().next() {
                    d.push(ip.to_string());
                }
            }
        }
    }
    // FIX: Sort for the same reason as get_arp() - avoid order-only false diffs
    d.sort();
    if d.is_empty() { d.push("ERROR_DEVICE_DETECTION_FAILED".into()); }
    d
}

pub fn get_network_adapters() -> Vec<String> {
    let mut n = Vec::new();
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-NetAdapter | Select-Object -ExpandProperty Name"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { n.push(l.trim().to_string()); }
        }
    }
    if n.is_empty() { n.push("ERROR_ADAPTER_DETECTION_FAILED".into()); }
    n
}

pub fn get_ports() -> Vec<String> {
    let mut p = Vec::new();
    if let Ok(o) = Command::new("netstat").creation_flags(CREATE_NO_WINDOW).args(["-ano","-p","TCP"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) {
            // FIX #15: Broader pattern matching for LISTENING
            if l.contains("LISTENING") || l.contains("LISTEN") || l.contains("ECOUTE") || l.contains("ESCUCHA") {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 4 {
                    let a = parts[1].to_string();
                    if a != "0.0.0.0:0" && !a.ends_with(":12790") {
                        p.push(a);
                    }
                }
            }
        }
    }
    p.sort();
    p.dedup();
    p
}

// ============================================
// SYSTEM SECURITY DETECTIONS — FIX #3: Fail-open fixed
// ============================================

pub fn get_startup() -> Vec<String> {
    let mut e = Vec::new();
    let sf = std::env::var("APPDATA").unwrap_or_default()
        + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    if let Ok(d) = fs::read_dir(&sf) {
        for f in d.flatten() {
            e.push(f.file_name().to_string_lossy().to_string());
        }
    }
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run').PSObject.Properties | Where-Object {$_.Name -ne 'PSPath'} | Select-Object -ExpandProperty Name"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { e.push(l.trim().to_string()); }
        }
    }
    if e.is_empty() { e.push("ERROR_STARTUP_DETECTION_FAILED".into()); }
    e
}

// ============================================
// FIX: FIREWALL DETECTION - Working PowerShell syntax
// ============================================

pub fn get_firewall() -> Vec<String> {
    let mut p = Vec::new();
    
    // FIX: Use the working PowerShell syntax confirmed on target system
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetFirewallProfile | ForEach-Object { $_.Name + ':' + $($(if ($_.Enabled) { 'ON' } else { 'OFF' })) }"
        ])
        .output() {
        let output = String::from_utf8_lossy(&o.stdout);
        for l in output.lines() {
            let trimmed = l.trim();
            if !trimmed.is_empty() && trimmed.contains(':') {
                p.push(trimmed.to_string());
            }
        }
    }
    
    // Fallback: Alternative method if the first one fails
    if p.is_empty() {
        if let Ok(o2) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetFirewallProfile | ForEach-Object { $_.Name + ':' + @{$true='ON';$false='OFF'}[$_.Enabled] }"
            ])
            .output() {
            let output = String::from_utf8_lossy(&o2.stdout);
            for l in output.lines() {
                let trimmed = l.trim();
                if !trimmed.is_empty() && trimmed.contains(':') {
                    p.push(trimmed.to_string());
                }
            }
        }
    }
    
    if p.is_empty() {
        p.push("ERROR_FIREWALL_DETECTION_FAILED".into());
    }
    
    p
}

pub fn get_scheduled_tasks() -> Vec<String> {
    let mut t = Vec::new();
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object -ExpandProperty TaskName | Sort-Object"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { t.push(l.trim().to_string()); }
        }
    }
    if t.is_empty() { t.push("ERROR_TASKS_DETECTION_FAILED".into()); }
    t
}

pub fn get_services() -> Vec<String> {
    let mut s = Vec::new();
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.StartType -eq 'Automatic'} | Select-Object -ExpandProperty Name | Sort-Object"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { s.push(l.trim().to_string()); }
        }
    }
    if s.is_empty() { s.push("ERROR_SERVICES_DETECTION_FAILED".into()); }
    s
}

pub fn get_defender_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"])
        .output() {
        match String::from_utf8_lossy(&o.stdout).trim() {
            "True" => "ON",
            "False" => "OFF",
            _ => "UNKNOWN"
        }.into()
    } else {
        "ERROR_DEFENDER_DETECTION_FAILED".into()
    }
}

pub fn get_secure_boot() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Confirm-SecureBootUEFI | Select-Object -ExpandProperty Supported"])
        .output() {
        match String::from_utf8_lossy(&o.stdout).trim() {
            "True" => "ON",
            _ => "OFF"
        }.into()
    } else {
        "ERROR_SECUREBOOT_DETECTION_FAILED".into()
    }
}

pub fn get_login_failures() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let c = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(n) = c.parse::<i32>() {
            if n > 5 { return format!("HIGH: {} failures", n); }
        }
        return c;
    }
    "ERROR_LOGIN_FAILURES_DETECTION_FAILED".into()
}

pub fn get_suspicious_processes() -> Vec<String> {
    let mut sp = Vec::new();
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-Process | Where-Object {$_.Path -match 'Temp|Downloads|Desktop'} | Select-Object -ExpandProperty ProcessName -Unique"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { sp.push(l.trim().to_string()); }
        }
    }
    if sp.is_empty() { sp.push("ERROR_SUSPICIOUS_PROCESS_DETECTION_FAILED".into()); }
    sp
}

pub fn get_root_cas() -> Vec<String> {
    let mut c = Vec::new();
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-ChildItem Cert:\\LocalMachine\\Root, Cert:\\CurrentUser\\Root | Select-Object -ExpandProperty Subject | Sort-Object"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { c.push(l.trim().to_string()); }
        }
    }
    if c.is_empty() { c.push("ERROR_ROOT_CA_DETECTION_FAILED".into()); }
    c
}

// ============================================
// HARDWARE DETECTIONS — FIX #3: Fail-open fixed
// ============================================

pub fn get_bt_devices() -> Vec<String> {
    let mut b = Vec::new();
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-PnpDevice -Class Bluetooth | Where-Object {$_.Status -eq 'OK'} | Select-Object -ExpandProperty FriendlyName"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { b.push(l.trim().to_string()); }
        }
    }
    if b.is_empty() { b.push("ERROR_BT_DETECTION_FAILED".into()); }
    b
}

pub fn get_hid_devices() -> Vec<String> {
    let mut h = Vec::new();
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-PnpDevice -Class Keyboard,Mouse | Where-Object {$_.Status -eq 'OK'} | Select-Object -ExpandProperty FriendlyName"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { h.push(l.trim().to_string()); }
        }
    }
    if h.is_empty() { h.push("ERROR_HID_DETECTION_FAILED".into()); }
    h
}

// ============================================
// SOFTWARE & FILE DETECTIONS — FIX #3: Fail-open fixed
// ============================================

pub fn get_installed_software() -> Vec<String> {
    let mut s = Vec::new();
    let bloat = [
        "mcafee", "norton", "ccleaner", "driver booster", "driver updater",
        "registry cleaner", "pc optimizer", "speedup", "tuneup", "candy crush",
        "farmville", "bubble witch", "mycleanpc", "advanced systemcare",
        "wise care", "glary utilities"
    ];
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile","-Command","Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            let lower = l.trim().to_lowercase();
            if bloat.iter().any(|b| lower.contains(b)) {
                s.push(l.trim().to_string());
            }
        }
    }
    if s.is_empty() { s.push("ERROR_SOFTWARE_DETECTION_FAILED".into()); }
    s
}

pub fn get_fake_extensions() -> Vec<String> {
    let mut f = Vec::new();
    let dirs = ["Desktop", "Downloads"];
    for dir in &dirs {
        let path = format!("{}\\{}", std::env::var("USERPROFILE").unwrap_or_default(), dir);
        if let Ok(entries) = fs::read_dir(&path) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                if name.ends_with(".pdf.exe") || name.ends_with(".doc.exe") ||
                   name.ends_with(".jpg.exe") || name.ends_with(".txt.exe") ||
                   name.contains(".exe.") {
                    f.push(e.file_name().to_string_lossy().to_string());
                }
            }
        }
    }
    if f.is_empty() { f.push("ERROR_FAKEEXT_DETECTION_FAILED".into()); }
    f
}

pub fn get_unicode_bidi_files() -> Vec<String> {
    let mut u = Vec::new();
    let bidi_chars = [
        '\u{202E}', '\u{202D}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{FEFF}',
        '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}', '\u{202A}',
        '\u{202B}', '\u{202C}', '\u{00AD}'
    ];
    let files_to_check = ["C:\\Windows\\System32\\drivers\\etc\\hosts"];
    for path in &files_to_check {
        if let Ok(content) = fs::read_to_string(path) {
            if content.chars().any(|c| bidi_chars.contains(&c)) {
                u.push(path.to_string());
            }
        }
    }
    let startup = std::env::var("APPDATA").unwrap_or_default()
        + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    if let Ok(dir) = fs::read_dir(&startup) {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.chars().any(|c| bidi_chars.contains(&c)) {
                u.push(format!("Startup: {}", name));
            }
        }
    }
    if u.is_empty() { u.push("ERROR_BIDI_DETECTION_FAILED".into()); }
    u
}

// ============================================
// SOCIAL ENGINEERING DETECTIONS — FIX #3: Fail-open fixed
// ============================================

pub fn get_homoglyph_domains() -> Vec<String> {
    let mut h = Vec::new();
    let suspicious_scripts = ['а','е','о','р','с','у','і','x'];
    let dns = get_dns();
    for d in &dns {
        if d.chars().any(|c| suspicious_scripts.contains(&c)) {
            h.push(d.clone());
        }
    }
    if let Ok(hosts) = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts") {
        for line in hosts.lines() {
            if line.chars().any(|c| suspicious_scripts.contains(&c)) && !line.starts_with('#') {
                h.push(line.trim().to_string());
            }
        }
    }
    if h.is_empty() { h.push("ERROR_HOMOGLYPH_DETECTION_FAILED".into()); }
    h
}

// ============================================
// NEW: 10 INTEGRITY SIGNALS — FIX #3: Fail-open fixed
// ============================================

pub fn get_uac_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "1" { return "ON".to_string(); }
        if s == "0" { return "OFF".to_string(); }
    }
    "ERROR_UAC_DETECTION_FAILED".into()
}

pub fn get_windows_update_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-Service wuauserv | Select-Object -ExpandProperty Status"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "Running" { return "ON".to_string(); }
        if s == "Stopped" { return "OFF".to_string(); }
    }
    "ERROR_WU_DETECTION_FAILED".into()
}

// FIX: Properly detect System Restore status
pub fn get_system_restore_status() -> String {
    // First check: does the srservice exist?
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-Service -Name srservice -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() && s == "srservice" {
            // Service exists, check if it's running
            if let Ok(o2) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
                .args(["-NoProfile", "-Command", "Get-Service srservice | Select-Object -ExpandProperty Status"])
                .output() {
                let status = String::from_utf8_lossy(&o2.stdout).trim().to_string();
                if status == "Running" {
                    return "ON".to_string();
                }
                // Service exists but not running
                return "OFF".to_string();
            }
        } else {
            // FIX: Service is confirmed absent - report "not available" directly
            // instead of falling through to the restore-point count below, which
            // returns a successful (non-error) "OFF" for count=0 and would
            // wrongly score a genuinely-unsupported feature as a real compromise.
            return "ERROR_SR_DETECTION_FAILED_NOT_FOUND".into();
        }
    }
    
    // Fallback: check if System Restore has restore points
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(count) = s.parse::<i32>() {
            if count > 0 { return "ON".to_string(); }
            // Count is 0 — service may exist but no restore points
            return "OFF".to_string();
        }
    }
    
    // Service doesn't exist at all
    "ERROR_SR_DETECTION_FAILED_NOT_FOUND".into()
}

// ============================================
// FIX: IMPROVED EVENT LOG DETECTION
// ============================================

pub fn get_event_log_status() -> String {
    // First check if the Security log service is running
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-Service -Name EventLog -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"])
        .output() {
        let status = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if status != "Running" {
            return format!("ERROR_EVENTLOG_SERVICE_{}", status.to_uppercase());
        }
    }
    
    // Check if Security log exists and has events
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "0" { 
            // Could be empty or cleared - check if log exists
            if let Ok(o2) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
                .args(["-NoProfile", "-Command", "Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LogName"])
                .output() {
                let log_name = String::from_utf8_lossy(&o2.stdout).trim().to_string();
                if log_name.is_empty() {
                    return "ERROR_EVENTLOG_NOT_FOUND".into();
                }
            }
            return "EMPTY".to_string(); 
        }
        return "OK".to_string();
    }
    "ERROR_EVENTLOG_DETECTION_FAILED".into()
}

pub fn get_smart_screen_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer').SmartScreenEnabled"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "RequireAdmin" || s == "Enabled" { return "ON".to_string(); }
        if s == "Off" { return "OFF".to_string(); }
    }
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-MpPreference | Select-Object -ExpandProperty EnableSmartScreen"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "True" { return "ON".to_string(); }
        if s == "False" { return "OFF".to_string(); }
    }
    "ERROR_SMARTSCREEN_DETECTION_FAILED".into()
}

pub fn get_vpn_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-NetAdapter | Where-Object {$_.Name -like '*VPN*' -or $_.Name -like '*WireGuard*' -or $_.Name -like '*OpenVPN*'} | Where-Object {$_.Status -eq 'Up'} | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(count) = s.parse::<i32>() {
            if count > 0 { return "CONNECTED".to_string(); }
        }
    }
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-Process | Where-Object {$_.ProcessName -match 'vpn|wireguard|openvpn|pia|expressvpn|nordvpn'} | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(count) = s.parse::<i32>() {
            if count > 0 { return "CONNECTED".to_string(); }
        }
    }
    "ERROR_VPN_DETECTION_FAILED".into()
}

pub fn get_ipv6_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(count) = s.parse::<i32>() {
            if count > 0 { return "ON".to_string(); }
        }
    }
    "ERROR_IPV6_DETECTION_FAILED".into()
}

pub fn get_wifi_profile_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() {
            if s == "Public" { return "PUBLIC".to_string(); }
            if s == "Private" { return "PRIVATE".to_string(); }
            if s == "Domain" { return "DOMAIN".to_string(); }
        }
    }
    "ERROR_WIFI_PROFILE_DETECTION_FAILED".into()
}

pub fn get_doh_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-DnsClient | Select-Object -ExpandProperty UseDoH"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "True" { return "ON".to_string(); }
        if s == "False" { return "OFF".to_string(); }
    }
    "ERROR_DOH_DETECTION_FAILED".into()
}

pub fn get_laps_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Enabled'"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "1" { return "ENABLED".to_string(); }
        if s == "0" { return "DISABLED".to_string(); }
    }
    "ERROR_LAPS_DETECTION_FAILED".into()
}

// ============================================
// NEW: 4 ADDITIONAL DETECTIONS — FIX #3: Fail-open fixed
// ============================================

/// Detects DHCP spoofing by checking the DHCP server IP
pub fn get_dhcp_server() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-NetIPConfiguration | Where-Object {$_.InterfaceAlias -like '*Wi*' -or $_.InterfaceAlias -like '*Wireless*'} | Select-Object -ExpandProperty DhcpServer"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() && s != "0.0.0.0" {
            return s;
        }
    }
    // Fallback: check DHCP server via ipconfig
    if let Ok(o) = Command::new("ipconfig").creation_flags(CREATE_NO_WINDOW)
        .args(["/all"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if l.contains("DHCP Server") || l.contains("Serveur DHCP") || l.contains("Servidor DHCP") {
                if let Some(ip) = l.split(':').nth(1) {
                    let ip = ip.trim().to_string();
                    if !ip.is_empty() && ip != "0.0.0.0" {
                        return ip;
                    }
                }
            }
        }
    }
    "ERROR_DHCP_DETECTION_FAILED".into()
}

/// Checks if BitLocker is enabled on the system drive
pub fn get_bitlocker_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProtectionStatus"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "On" { return "ON".to_string(); }
        if s == "Off" { return "OFF".to_string(); }
    }
    // Fallback: check registry
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\BitLocker\\Status\\C:' -ErrorAction SilentlyContinue).EncryptionStatus"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "1" { return "ON".to_string(); }
        if s == "0" { return "OFF".to_string(); }
    }
    "ERROR_BITLOCKER_DETECTION_FAILED".into()
}

/// Checks if Credential Guard is enabled
pub fn get_credential_guard_status() -> String {
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "(Get-ComputerInfo).DeviceGuardCredentialGuardStatus"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "Running" { return "ON".to_string(); }
        if s == "Off" { return "OFF".to_string(); }
    }
    // Fallback: check registry
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard' -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "1" { return "ON".to_string(); }
        if s == "0" { return "OFF".to_string(); }
    }
    "ERROR_CREDGUARD_DETECTION_FAILED".into()
}

/// Checks if RDP (port 3389) is listening
pub fn get_rdp_status() -> String {
    if let Ok(o) = Command::new("netstat").creation_flags(CREATE_NO_WINDOW)
        .args(["-ano", "-p", "TCP"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if l.contains("3389") && (l.contains("LISTENING") || l.contains("LISTEN") || l.contains("ECOUTE") || l.contains("ESCUCHA")) {
                return "LISTENING".to_string();
            }
        }
    }
    // Also check if RDP service is running
    if let Ok(o) = Command::new("powershell").creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-Command", "Get-Service -Name TermService -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "Running" { return "RUNNING".to_string(); }
    }
    "ERROR_RDP_DETECTION_FAILED".into()
}