// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Auto-Repair Module — Silent with Safety Levels
//! - Automatic: DNS, Firewall, Proxy, Defender, UAC, Windows Update, System Restore, SmartScreen, IPv6
//! - Alert Only: VPN, DoH, LAPS, Event Log
//! - Confirm Required: HID, BT, Adapter, Startup, Brute Force
//! - Never Auto (Quarantine): Fake Extensions

use std::process::Command;
use std::fs;
use std::path::Path;
use chrono::Local;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";

// ============================================
// AUTOMATIC REPAIRS (No user input)
// ============================================

pub fn reset_dns() {
    let _ = Command::new("netsh").args(["interface", "ip", "set", "dns", "Wi-Fi", "dhcp"]).output();
    log_repair("DNS", "Reset to DHCP");
    log_incident("DNS", "Reset", "DNS reset to DHCP");
}

pub fn restore_hosts() {
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let backup = format!("{}\\hosts.backup", DATA_DIR);
    if Path::new(&backup).exists() {
        let _ = fs::copy(&backup, hosts);
        log_repair("Hosts", "Restored from backup");
        log_incident("Hosts", "Restored", "Hosts file restored from backup");
    }
}

pub fn enable_firewall() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-NetFirewallProfile -All -Enabled True"])
        .output();
    log_repair("Firewall", "Re-enabled all profiles");
    log_incident("Firewall", "Re-enabled", "Firewall re-enabled");
}

pub fn remove_proxy() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue; Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0"])
        .output();
    log_repair("Proxy", "Removed proxy settings");
    log_incident("Proxy", "Removed", "Proxy settings removed");
}

pub fn enable_defender() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"])
        .output();
    log_repair("Defender", "Re-enabled realtime protection");
    log_incident("Defender", "Re-enabled", "Windows Defender re-enabled");
}

pub fn enable_uac() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1"])
        .output();
    log_repair("UAC", "Re-enabled");
    log_incident("UAC", "Re-enabled", "UAC re-enabled");
}

pub fn enable_windows_update() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Set-Service -Name wuauserv -StartupType Automatic -Status Running"])
        .output();
    log_repair("WindowsUpdate", "Re-enabled");
    log_incident("WindowsUpdate", "Re-enabled", "Windows Update re-enabled");
}

pub fn enable_system_restore() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Enable-ComputerRestore -Drive 'C:\\'"])
        .output();
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Set-Service -Name srservice -StartupType Automatic -Status Running"])
        .output();
    log_repair("SystemRestore", "Re-enabled");
    log_incident("SystemRestore", "Re-enabled", "System Restore re-enabled");
}

pub fn enable_smart_screen() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -Value 'RequireAdmin'"])
        .output();
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Set-MpPreference -EnableSmartScreen $true"])
        .output();
    log_repair("SmartScreen", "Re-enabled");
    log_incident("SmartScreen", "Re-enabled", "SmartScreen re-enabled");
}

pub fn enable_ipv6() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6"])
        .output();
    log_repair("IPv6", "Re-enabled");
    log_incident("IPv6", "Re-enabled", "IPv6 re-enabled");
}

pub fn set_wifi_private() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Set-NetConnectionProfile -NetworkCategory Private"])
        .output();
    log_repair("WiFiProfile", "Set to Private");
    log_incident("WiFiProfile", "Changed", "WiFi profile set to Private");
}

pub fn block_ip(ip: &str) {
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "add", "rule",
               "name=TS-Block-IP", "dir=in", "action=block",
               &format!("remoteip={}", ip)])
        .output();
    log_repair("BlockIP", &format!("Blocked IP: {}", ip));
    log_incident("BlockIP", "Blocked", &format!("IP blocked: {}", ip));
}

pub fn network_kill() {
    let _ = Command::new("netsh").args(["advfirewall", "set", "allprofiles", "state", "on"]).output();
    log_repair("NetworkKill", "All firewall profiles enabled");
    log_incident("NetworkKill", "Enabled", "Network kill - all firewall profiles enabled");
}

pub fn block_bruteforce_ips() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object { $_.Properties[19].Value } | Where-Object {$_ -match '\\d+\\.\\d+\\.\\d+\\.\\d+'} | Group-Object | Where-Object {$_.Count -gt 5} | Select-Object -ExpandProperty Name | ForEach-Object { New-NetFirewallRule -DisplayName 'TS-Block-Brute-' + $_ -Direction Inbound -RemoteAddress $_ -Action Block }"])
        .output();
    log_repair("BruteForce", "Blocked brute force IPs");
    log_incident("BruteForce", "Blocked", "Brute force IPs blocked");
}

// ============================================
// CONFIRM REQUIRED / QUARANTINE REPAIRS
// ============================================

pub fn quarantine_startup() {
    let startup = format!("{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        std::env::var("APPDATA").unwrap_or_default());
    if let Ok(entries) = fs::read_dir(&startup) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().unwrap().to_string_lossy();
                let quar = format!("{}\\quarantine\\{}", DATA_DIR, name);
                let _ = fs::create_dir_all(format!("{}\\quarantine", DATA_DIR));
                let _ = fs::rename(&path, &quar);
                log_repair("Startup", &format!("Quarantined: {}", name));
                log_incident("Startup", "Quarantined", &format!("Startup entry quarantined: {}", name));
            }
        }
    }
}

pub fn delete_fake_files() {
    // QUARANTINE instead of delete for safety
    let dirs = ["Desktop", "Downloads"];
    for dir in &dirs {
        let path = format!("{}\\{}", std::env::var("USERPROFILE").unwrap_or_default(), dir);
        if let Ok(entries) = fs::read_dir(&path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_lowercase();
                if name.ends_with(".pdf.exe") || name.ends_with(".doc.exe") ||
                   name.ends_with(".jpg.exe") || name.ends_with(".txt.exe") ||
                   name.contains(".exe.") {
                    let quar = format!("{}\\quarantine\\{}", DATA_DIR, name);
                    let _ = fs::create_dir_all(format!("{}\\quarantine", DATA_DIR));
                    let _ = fs::rename(entry.path(), &quar);
                    log_repair("FakeFiles", &format!("Quarantined: {}", name));
                    log_incident("FakeFiles", "Quarantined", &format!("Fake file quarantined: {}", name));
                }
            }
        }
    }
}

pub fn eject_usb(device: &str) {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            &format!("Get-PnpDevice -FriendlyName '{}' | Disable-PnpDevice -Confirm:$false", device)])
        .output();
    log_repair("USB", &format!("Ejected: {}", device));
    log_incident("USB", "Ejected", &format!("USB device ejected: {}", device));
}

pub fn disable_bt_devices() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-PnpDevice -Class Bluetooth | Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName -notmatch 'Intel|Qualcomm|Realtek|Broadcom|MediaTek|Microsoft'} | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"])
        .output();
    log_repair("Bluetooth", "Disabled unknown BT devices");
    log_incident("Bluetooth", "Disabled", "Unknown Bluetooth devices disabled");
}

pub fn disable_hid_devices() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-PnpDevice -Class Keyboard,Mouse | Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName -notmatch 'Microsoft|Logitech|Razer|Dell|HP|Lenovo|Synaptics|Intel'} | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"])
        .output();
    log_repair("HID", "Disabled unknown HID devices");
    log_incident("HID", "Disabled", "Unknown HID devices disabled");
}

pub fn disable_unknown_adapters() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-NetAdapter | Where-Object {$_.Name -notmatch 'Wi-Fi|Ethernet|Bluetooth|vEthernet|Loopback'} | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue"])
        .output();
    log_repair("Adapter", "Disabled unknown adapters");
    log_incident("Adapter", "Disabled", "Unknown network adapters disabled");
}

pub fn clean_unicode_bidi() {
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    if let Ok(content) = fs::read_to_string(hosts) {
        let cleaned: String = content.chars()
            .filter(|c| !['\u{202E}', '\u{202D}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
                         '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{FEFF}',
                         '\u{202A}', '\u{202B}', '\u{202C}', '\u{00AD}'].contains(c))
            .collect();
        let _ = fs::write(hosts, cleaned);
        log_repair("Bidi", "Cleaned Unicode bidi characters");
        log_incident("Bidi", "Cleaned", "Unicode bidi characters cleaned from hosts");
    }
}

// ============================================
// ALERT ONLY REPAIRS
// ============================================

pub fn alert_bloatware() {
    log_repair("Bloatware", "Bloatware/PUP detected");
    log_incident("Bloatware", "Detected", "Bloatware/PUP detected");
}

pub fn alert_suspicious_process() {
    log_repair("SuspiciousProcess", "Suspicious process detected from Temp/Downloads");
    log_incident("SuspiciousProcess", "Detected", "Suspicious process detected");
}

pub fn alert_new_device() {
    log_repair("NewDevice", "New network device detected");
    log_incident("NewDevice", "Detected", "New network device detected");
}

pub fn alert_secure_boot() {
    log_repair("SecureBoot", "Secure Boot is OFF");
    log_incident("SecureBoot", "Alert", "Secure Boot is OFF");
}

pub fn alert_service_change() {
    log_repair("ServiceChange", "Windows Service changed");
    log_incident("ServiceChange", "Alert", "Windows Service changed");
}

pub fn alert_event_log_cleared() {
    log_repair("EventLog", "Alert - Event log was cleared");
    log_incident("EventLog", "Alert", "Event log was cleared - investigation recommended");
}

pub fn alert_vpn_disconnected() {
    log_repair("VPN", "Alert - VPN disconnected");
    log_incident("VPN", "Alert", "VPN disconnected - check your connection");
}

pub fn alert_doh_changed() {
    log_repair("DoH", "Alert - DNS over HTTPS changed");
    log_incident("DoH", "Alert", "DNS over HTTPS setting changed");
}

pub fn alert_laps_changed() {
    log_repair("LAPS", "Alert - LAPS status changed");
    log_incident("LAPS", "Alert", "LAPS status changed");
}

// ============================================
// GHOST MODE
// ============================================

pub fn ghost_mode_on() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-NetFirewallRule -DisplayName 'TS-VPN-Only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
            "Get-NetFirewallRule -DisplayName 'TS-Block-ICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
            "Get-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"])
        .output();

    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Set-NetFirewallProfile -All -DefaultInboundAction Block;",
            "Set-NetFirewallProfile -All -DefaultOutboundAction Block;",
            "New-NetFirewallRule -DisplayName 'TS-VPN-Only' -Direction Outbound -RemotePort 443,1194,51820 -Protocol TCP,UDP -Action Allow;",
            "New-NetFirewallRule -DisplayName 'TS-Block-ICMP' -Direction Inbound -Protocol ICMPv4 -Action Block;",
            "New-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -Direction Inbound -LocalPort 4444,5555,6667,8080,8888,31337,3389,5900,5800,5938,21,23,25,110,143,993,995,3306,5432,1433,1521,27017,6379,11211,5000,4500,5060 -Action Block;",
            "Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Disable-NetFirewallRule;",
            "Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Disable-NetFirewallRule;",
            "Stop-Service -Name 'FDResPub','SSDPSRV','upnphost','bthserv' -Force;",
            "Set-Service -Name 'FDResPub','SSDPSRV','upnphost','bthserv' -StartupType Disabled;"])
        .output();

    log_repair("GhostMode", "Enabled - Full lockdown active");
    log_incident("GhostMode", "Enabled", "Ghost Mode enabled - Full lockdown");
}

pub fn ghost_mode_off() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-NetFirewallRule -DisplayName 'TS-VPN-Only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
            "Get-NetFirewallRule -DisplayName 'TS-Block-ICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
            "Get-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"])
        .output();

    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Set-NetFirewallProfile -All -DefaultInboundAction Allow;",
            "Set-NetFirewallProfile -All -DefaultOutboundAction Allow;",
            "Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Enable-NetFirewallRule;",
            "Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Enable-NetFirewallRule;",
            "Set-Service -Name 'FDResPub','SSDPSRV','upnphost','bthserv' -StartupType Manual;"])
        .output();

    log_repair("GhostMode", "Disabled - Normal operation restored");
    log_incident("GhostMode", "Disabled", "Ghost Mode disabled - Normal operation");
}

pub fn is_ghost_active() -> bool {
    let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
    Path::new(&ghost_flag).exists()
}

// ============================================
// UTILITIES
// ============================================

fn log_repair(action: &str, details: &str) {
    let log_path = format!("{}\\repair.log", DATA_DIR);
    let entry = format!("{}|{}|{}\n",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        action,
        details
    );
    let _ = fs::write(&log_path, entry);
}

fn log_incident(category: &str, action: &str, details: &str) {
    let user_dir = format!("{}\\Invisibly\\incidents", std::env::var("USERPROFILE").unwrap_or_default());
    let _ = fs::create_dir_all(&user_dir);
    
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let filename = format!("{}\\{}_{}_{}.txt", user_dir, timestamp, category, action);
    
    let content = format!(
        "========================================\n\
         INVISIBLY INCIDENT REPORT\n\
         ========================================\n\
         Date: {}\n\
         Category: {}\n\
         Action: {}\n\
         Severity: High\n\
         \n\
         DETAILS:\n\
         {}\n\
         \n\
         ========================================\n",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        category,
        action,
        details
    );
    
    let _ = fs::write(&filename, content);
}