// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

use serde::{Serialize, Deserialize};
use std::process::Command;
use std::collections::HashMap;
use std::fs;

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
        root_cas: get_filtered_root_cas(),

        bt_devices: get_bt_devices(),
        hid_devices: get_hid_devices(),

        installed_software: get_installed_software(),
        fake_extensions: get_fake_extensions(),
        unicode_bidi_files: get_unicode_bidi_files(),

        homoglyph_domains: get_homoglyph_domains(),

        // NEW: 10 Integrity signals
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
    }
}

// ============================================
// NETWORK DETECTIONS
// ============================================

pub fn get_dns() -> Vec<String> {
    let mut d = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | ForEach-Object {$_.ServerAddresses -join ','}"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            for a in l.split(',') {
                let a = a.trim().to_string();
                if !a.is_empty() && !d.contains(&a) { d.push(a); }
            }
        }
    }
    if d.is_empty() { d.push("Unknown".into()); }
    d
}

pub fn get_hosts_hash() -> String {
    if let Ok(c) = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts") {
        hex::encode(ring::digest::digest(&ring::digest::SHA256, c.as_bytes()))
    } else {
        "unreadable".into()
    }
}

pub fn get_arp() -> Vec<String> {
    let mut a = Vec::new();
    if let Ok(o) = Command::new("arp").args(["-a"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if l.contains("dynamic") || l.contains("static") {
                a.push(l.trim().to_string());
            }
        }
    }
    if a.is_empty() { a.push("None".into()); }
    a
}

pub fn get_wifi() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","(Get-NetConnectionProfile | Where-Object {$_.InterfaceAlias -like '*Wi*' -or $_.InterfaceAlias -like '*Wireless*'} | Select-Object -First 1).Name"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() { return s; }
    }
    "Unknown".into()
}

pub fn get_proxy() -> Vec<String> {
    let mut p = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyServer, ProxyEnable | ForEach-Object { $_.ProxyEnable.ToString() + ':' + $_.ProxyServer }"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { p.push(l.trim().to_string()); }
        }
    }
    if p.is_empty() { p.push("None".into()); }
    p
}

pub fn get_network_devices() -> Vec<String> {
    let mut d = Vec::new();
    if let Ok(o) = Command::new("arp").args(["-a"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if l.contains("dynamic") {
                if let Some(ip) = l.split_whitespace().next() {
                    d.push(ip.to_string());
                }
            }
        }
    }
    if d.is_empty() { d.push("None".into()); }
    d
}

pub fn get_network_adapters() -> Vec<String> {
    let mut n = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-NetAdapter | Select-Object -ExpandProperty Name"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { n.push(l.trim().to_string()); }
        }
    }
    if n.is_empty() { n.push("None".into()); }
    n
}

pub fn get_ports() -> Vec<String> {
    let mut p = Vec::new();
    if let Ok(o) = Command::new("netstat").args(["-ano","-p","TCP"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 4 && parts[3] == "LISTENING" {
                let a = parts[1].to_string();
                if a != "0.0.0.0:0" && !a.ends_with(":12790") {
                    p.push(a);
                }
            }
        }
    }
    p.sort();
    p.dedup();
    p
}

// ============================================
// SYSTEM SECURITY DETECTIONS
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
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run').PSObject.Properties | Where-Object {$_.Name -ne 'PSPath'} | Select-Object -ExpandProperty Name"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { e.push(l.trim().to_string()); }
        }
    }
    if e.is_empty() { e.push("None".into()); }
    e
}

pub fn get_firewall() -> Vec<String> {
    let mut p = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-NetFirewallProfile | ForEach-Object {$_.Name+':'+($_.Enabled ? 'ON':'OFF')}"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { p.push(l.trim().to_string()); }
        }
    }
    if p.is_empty() { p.push("Unknown".into()); }
    p
}

pub fn get_scheduled_tasks() -> Vec<String> {
    let mut t = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object -ExpandProperty TaskName | Sort-Object"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { t.push(l.trim().to_string()); }
        }
    }
    if t.is_empty() { t.push("None".into()); }
    t
}

pub fn get_services() -> Vec<String> {
    let mut s = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.StartType -eq 'Automatic'} | Select-Object -ExpandProperty Name | Sort-Object"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { s.push(l.trim().to_string()); }
        }
    }
    if s.is_empty() { s.push("None".into()); }
    s
}

pub fn get_defender_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"])
        .output() {
        match String::from_utf8_lossy(&o.stdout).trim() {
            "True" => "ON",
            "False" => "OFF",
            _ => "Unknown"
        }.into()
    } else {
        "Unknown".into()
    }
}

pub fn get_secure_boot() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Confirm-SecureBootUEFI | Select-Object -ExpandProperty Supported"])
        .output() {
        match String::from_utf8_lossy(&o.stdout).trim() {
            "True" => "ON",
            _ => "OFF"
        }.into()
    } else {
        "Unknown".into()
    }
}

pub fn get_login_failures() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let c = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(n) = c.parse::<i32>() {
            if n > 5 { return format!("HIGH: {} failures", n); }
        }
        return c;
    }
    "0".into()
}

pub fn get_suspicious_processes() -> Vec<String> {
    let mut sp = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-Process | Where-Object {$_.Path -match 'Temp|Downloads|Desktop'} | Select-Object -ExpandProperty ProcessName -Unique"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { sp.push(l.trim().to_string()); }
        }
    }
    if sp.is_empty() { sp.push("None".into()); }
    sp
}

pub fn get_root_cas() -> Vec<String> {
    let mut c = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-ChildItem Cert:\\LocalMachine\\Root, Cert:\\CurrentUser\\Root | Select-Object -ExpandProperty Subject | Sort-Object"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { c.push(l.trim().to_string()); }
        }
    }
    if c.is_empty() { c.push("None".into()); }
    c
}

// DISABLED - Root CA detection removed per user request
pub fn get_filtered_root_cas() -> Vec<String> {
    vec!["None".to_string()]
}

// ============================================
// HARDWARE DETECTIONS
// ============================================

pub fn get_bt_devices() -> Vec<String> {
    let mut b = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-PnpDevice -Class Bluetooth | Where-Object {$_.Status -eq 'OK'} | Select-Object -ExpandProperty FriendlyName"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { b.push(l.trim().to_string()); }
        }
    }
    if b.is_empty() { b.push("None".into()); }
    b
}

pub fn get_hid_devices() -> Vec<String> {
    let mut h = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-PnpDevice -Class Keyboard,Mouse | Where-Object {$_.Status -eq 'OK'} | Select-Object -ExpandProperty FriendlyName"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if !l.trim().is_empty() { h.push(l.trim().to_string()); }
        }
    }
    if h.is_empty() { h.push("None".into()); }
    h
}

// ============================================
// SOFTWARE & FILE DETECTIONS
// ============================================

pub fn get_installed_software() -> Vec<String> {
    let mut s = Vec::new();
    let bloat = [
        "mcafee", "norton", "ccleaner", "driver booster", "driver updater",
        "registry cleaner", "pc optimizer", "speedup", "tuneup", "candy crush",
        "farmville", "bubble witch", "mycleanpc", "advanced systemcare",
        "wise care", "glary utilities"
    ];
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue"])
        .output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            let lower = l.trim().to_lowercase();
            if bloat.iter().any(|b| lower.contains(b)) {
                s.push(l.trim().to_string());
            }
        }
    }
    if s.is_empty() { s.push("None".into()); }
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
    if f.is_empty() { f.push("None".into()); }
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
    if u.is_empty() { u.push("None".into()); }
    u
}

// ============================================
// SOCIAL ENGINEERING DETECTIONS
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
    if h.is_empty() { h.push("None".into()); }
    h
}

// ============================================
// NEW: 10 INTEGRITY SIGNALS
// ============================================

pub fn get_uac_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "1" { return "ON".to_string(); }
        if s == "0" { return "OFF".to_string(); }
    }
    "Unknown".into()
}

pub fn get_windows_update_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-Service wuauserv | Select-Object -ExpandProperty Status"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "Running" { return "ON".to_string(); }
        if s == "Stopped" { return "OFF".to_string(); }
    }
    "Unknown".into()
}

pub fn get_system_restore_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-Service srservice | Select-Object -ExpandProperty Status"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "Running" { return "ON".to_string(); }
    }
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-ComputerRestorePoint | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(count) = s.parse::<i32>() {
            if count > 0 { return "ON".to_string(); }
        }
    }
    "OFF".into()
}

pub fn get_event_log_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "0" { return "EMPTY".to_string(); }
        return "OK".to_string();
    }
    "Unknown".into()
}

pub fn get_smart_screen_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer').SmartScreenEnabled"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "RequireAdmin" || s == "Enabled" { return "ON".to_string(); }
        if s == "Off" { return "OFF".to_string(); }
    }
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-MpPreference | Select-Object -ExpandProperty EnableSmartScreen"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "True" { return "ON".to_string(); }
        if s == "False" { return "OFF".to_string(); }
    }
    "Unknown".into()
}

pub fn get_vpn_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-NetAdapter | Where-Object {$_.Name -like '*VPN*' -or $_.Name -like '*WireGuard*' -or $_.Name -like '*OpenVPN*'} | Where-Object {$_.Status -eq 'Up'} | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(count) = s.parse::<i32>() {
            if count > 0 { return "CONNECTED".to_string(); }
        }
    }
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-Process | Where-Object {$_.ProcessName -match 'vpn|wireguard|openvpn|pia|expressvpn|nordvpn'} | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(count) = s.parse::<i32>() {
            if count > 0 { return "CONNECTED".to_string(); }
        }
    }
    "DISCONNECTED".into()
}

pub fn get_ipv6_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if let Ok(count) = s.parse::<i32>() {
            if count > 0 { return "ON".to_string(); }
        }
    }
    "OFF".into()
}

pub fn get_wifi_profile_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() {
            if s == "Public" { return "PUBLIC".to_string(); }
            if s == "Private" { return "PRIVATE".to_string(); }
            if s == "Domain" { return "DOMAIN".to_string(); }
        }
    }
    "Unknown".into()
}

pub fn get_doh_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-DnsClient | Select-Object -ExpandProperty UseDoH"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "True" { return "ON".to_string(); }
        if s == "False" { return "OFF".to_string(); }
    }
    "Unknown".into()
}

pub fn get_laps_status() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Enabled'"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if s == "1" { return "ENABLED".to_string(); }
        if s == "0" { return "DISABLED".to_string(); }
    }
    "NOT_INSTALLED".into()
}

// ============================================
// THREAT DETECTION FUNCTIONS
// ============================================

pub fn check_ransomware() -> bool {
    let canary_dir = std::path::PathBuf::from("C:\\ProgramData\\Invisibly\\canary");
    let _ = fs::create_dir_all(&canary_dir);
    let files = ["test.docx", "test.pdf", "test.jpg", "test.txt", "test.xlsx"];
    let mut modified = 0;
    let now = std::time::SystemTime::now();
    for f in &files {
        let p = canary_dir.join(f);
        if !p.exists() { let _ = fs::write(&p, b"TS_CANARY"); }
        if let Ok(meta) = fs::metadata(&p) {
            if let Ok(mt) = meta.modified() {
                if let Ok(d) = now.duration_since(mt) {
                    if d.as_secs() < 30 { modified += 1; }
                }
            }
        }
    }
    modified >= 5
}

pub fn detect_port_scan(threshold: usize) -> String {
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    if let Ok(o) = Command::new("netstat").args(["-ano","-p","TCP"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 3 && parts[3] == "ESTABLISHED" {
                if let Some(ip) = parts[2].rsplitn(2, ':').nth(1) {
                    if !ip.starts_with("127.") && !ip.starts_with("192.168.") &&
                       !ip.starts_with("10.") && !ip.starts_with("23.") {
                        *ip_counts.entry(ip.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }
    }
    for (ip, count) in &ip_counts {
        if *count > threshold { return ip.clone(); }
    }
    String::new()
}

pub fn check_usb() -> String {
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile","-Command","Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName -match 'storage|flash|drive|mass'} | Select-Object -ExpandProperty FriendlyName"])
        .output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() { return s; }
    }
    String::new()
}

// ============================================
// DIFF FUNCTION
// ============================================

pub fn diff(a: &SystemState, b: &SystemState) -> Vec<(String, String)> {
    let mut d = Vec::new();

    // Network
    if a.dns_servers != b.dns_servers { d.push(("dns".into(), "DNS changed".into())); }
    if a.hosts_hash != b.hosts_hash { d.push(("hosts".into(), "Hosts modified".into())); }
    if a.arp_table != b.arp_table { d.push(("arp".into(), "ARP changed".into())); }
    if a.wifi_ssid != b.wifi_ssid { d.push(("wifi".into(), "WiFi changed".into())); }
    if a.proxy_settings != b.proxy_settings { d.push(("proxy".into(), "Proxy changed".into())); }
    if a.network_devices != b.network_devices { d.push(("devices".into(), "New device".into())); }
    if a.network_adapters != b.network_adapters { d.push(("adapter".into(), "New network adapter".into())); }
    if a.listening_ports != b.listening_ports { d.push(("ports".into(), "Ports changed".into())); }

    // System Security
    if a.startup_entries != b.startup_entries { d.push(("startup".into(), "Startup changed".into())); }
    if a.firewall_profiles != b.firewall_profiles { d.push(("firewall".into(), "Firewall changed".into())); }
    if a.scheduled_tasks != b.scheduled_tasks { d.push(("tasks".into(), "Tasks changed".into())); }
    if a.services_list != b.services_list { d.push(("services".into(), "Services changed".into())); }
    if a.defender_status != b.defender_status { d.push(("defender".into(), "Defender changed".into())); }
    if a.secure_boot != b.secure_boot { d.push(("secureboot".into(), "Secure Boot changed".into())); }
    if a.login_failures.contains("HIGH") && a.login_failures != b.login_failures {
        d.push(("bruteforce".into(), "Brute force attack detected".into()));
    }
    if a.suspicious_processes != b.suspicious_processes &&
       b.suspicious_processes.iter().any(|s| s != "None") {
        d.push(("susp_proc".into(), "Suspicious process running".into()));
    }
    if a.root_cas != b.root_cas { d.push(("rootca".into(), "Root CA changed".into())); }

    // Hardware
    if a.bt_devices != b.bt_devices { d.push(("bt".into(), "New Bluetooth device".into())); }
    if a.hid_devices != b.hid_devices { d.push(("hid".into(), "New HID device - possible BadUSB".into())); }

    // Software & Files
    if a.installed_software != b.installed_software &&
       b.installed_software.iter().any(|s| s != "None") {
        d.push(("bloatware".into(), "Bloatware/PUP detected".into()));
    }
    if a.fake_extensions != b.fake_extensions &&
       b.fake_extensions.iter().any(|s| s != "None") {
        d.push(("fakeext".into(), "Fake file extension found".into()));
    }
    if a.unicode_bidi_files != b.unicode_bidi_files &&
       b.unicode_bidi_files.iter().any(|s| s != "None") {
        d.push(("trojan_source".into(), "Unicode bidi attack detected".into()));
    }

    // Social Engineering
    if a.homoglyph_domains != b.homoglyph_domains &&
       b.homoglyph_domains.iter().any(|s| s != "None") {
        d.push(("homoglyph".into(), "Homoglyph domain detected".into()));
    }

    // NEW: 10 Integrity signals
    if a.uac_status != b.uac_status {
        d.push(("uac".into(), format!("UAC: {}", b.uac_status)));
    }
    if a.windows_update_status != b.windows_update_status {
        d.push(("wu".into(), format!("Windows Update: {}", b.windows_update_status)));
    }
    if a.system_restore_status != b.system_restore_status {
        d.push(("sr".into(), format!("System Restore: {}", b.system_restore_status)));
    }
    if a.event_log_status != b.event_log_status {
        d.push(("eventlog".into(), format!("Event Log: {}", b.event_log_status)));
    }
    if a.smart_screen_status != b.smart_screen_status {
        d.push(("smartscreen".into(), format!("SmartScreen: {}", b.smart_screen_status)));
    }
    if a.vpn_status != b.vpn_status {
        d.push(("vpn".into(), format!("VPN: {}", b.vpn_status)));
    }
    if a.ipv6_status != b.ipv6_status {
        d.push(("ipv6".into(), format!("IPv6: {}", b.ipv6_status)));
    }
    if a.wifi_profile_status != b.wifi_profile_status {
        d.push(("wifi_profile".into(), format!("WiFi Profile: {}", b.wifi_profile_status)));
    }
    if a.doh_status != b.doh_status {
        d.push(("doh".into(), format!("DoH: {}", b.doh_status)));
    }
    if a.laps_status != b.laps_status {
        d.push(("laps".into(), format!("LAPS: {}", b.laps_status)));
    }

    d
}

// ============================================
// SANITIZE
// ============================================

pub fn first_run_sanitize() -> Vec<String> {
    let mut issues = Vec::new();
    if get_defender_status() != "ON" { issues.push("DEFENDER_OFF".into()); }
    if get_firewall().iter().any(|f| f.contains("OFF")) { issues.push("FIREWALL_OFF".into()); }
    if get_secure_boot() == "OFF" { issues.push("SECURE_BOOT_OFF".into()); }
    if get_proxy().len() > 1 && get_proxy()[0] != "None" { issues.push("PROXY_SET".into()); }
    if get_login_failures().contains("HIGH") { issues.push("BRUTE_FORCE".into()); }
    issues
}