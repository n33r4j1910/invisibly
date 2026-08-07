// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Auto-Repair Module — Silent with Safety Levels
//! - Automatic: DNS, Firewall, Proxy, Defender, UAC, Windows Update, System Restore, SmartScreen, IPv6, RDP
//! - Alert Only: VPN, DoH, LAPS, Event Log
//! - Confirm Required: HID, BT, Adapter, Startup, Brute Force
//! - Never Auto (Quarantine): Fake Extensions

use std::process::Command;
use std::fs;
use std::path::Path;
use chrono::Local;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";

// ============================================
// HELPER: Run command and log success/failure
// ============================================

fn run_command(cmd: &mut Command, action: &str, details: &str) -> bool {
    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                log_repair(action, &format!("✅ {}", details));
                log_incident(action, "Success", &format!("{}", details));
                true
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log_repair(action, &format!("❌ Failed: {} - {}", details, stderr));
                log_incident(action, "Failed", &format!("{} - {}", details, stderr));
                false
            }
        }
        Err(e) => {
            log_repair(action, &format!("❌ Error: {} - {}", details, e));
            log_incident(action, "Error", &format!("{} - {}", details, e));
            false
        }
    }
}

// ============================================
// APPEND MODE FOR LOGGING
// ============================================

fn log_repair(action: &str, details: &str) {
    let log_path = format!("{}\\repair.log", DATA_DIR);
    let entry = format!("{}|{}|{}\n",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        action,
        details
    );
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(entry.as_bytes())
        });
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

// ============================================
// AUTOMATIC REPAIRS (No user input)
// ============================================

pub fn reset_dns() {
    let mut cmd = Command::new("netsh");
    cmd.args(["interface", "ip", "set", "dns", "Wi-Fi", "dhcp"]);
    run_command(&mut cmd, "DNS", "Reset to DHCP");
}

pub fn restore_hosts() {
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let backup = format!("{}\\hosts.backup", DATA_DIR);
    if Path::new(&backup).exists() {
        match fs::copy(&backup, hosts) {
            Ok(_) => {
                log_repair("Hosts", "✅ Restored from backup");
                log_incident("Hosts", "Success", "Hosts file restored from backup");
            }
            Err(e) => {
                log_repair("Hosts", &format!("❌ Failed: {}", e));
                log_incident("Hosts", "Failed", &format!("Hosts restore failed: {}", e));
            }
        }
    } else {
        log_repair("Hosts", "⚠️ No backup found");
    }
}

pub fn enable_firewall() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command", "Set-NetFirewallProfile -All -Enabled True"]);
    run_command(&mut cmd, "Firewall", "Re-enabled all profiles");
}

pub fn remove_proxy() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue; Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0"]);
    run_command(&mut cmd, "Proxy", "Removed proxy settings");
}

pub fn enable_defender() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"]);
    run_command(&mut cmd, "Defender", "Re-enabled realtime protection");
}

pub fn enable_uac() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1"]);
    run_command(&mut cmd, "UAC", "Re-enabled");
}

pub fn enable_windows_update() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Set-Service -Name wuauserv -StartupType Automatic -Status Running"]);
    run_command(&mut cmd, "WindowsUpdate", "Re-enabled");
}

pub fn enable_system_restore() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Enable-ComputerRestore -Drive 'C:\\'"]);
    run_command(&mut cmd, "SystemRestore", "Re-enabled");
    
    let mut cmd2 = Command::new("powershell");
    cmd2.args(["-NoProfile", "-Command",
        "Set-Service -Name srservice -StartupType Automatic -Status Running"]);
    run_command(&mut cmd2, "SystemRestore", "Service started");
}

pub fn enable_smart_screen() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -Value 'RequireAdmin'"]);
    run_command(&mut cmd, "SmartScreen", "Re-enabled");
    
    let mut cmd2 = Command::new("powershell");
    cmd2.args(["-NoProfile", "-Command",
        "Set-MpPreference -EnableSmartScreen $true"]);
    run_command(&mut cmd2, "SmartScreen", "MP preference updated");
}

pub fn enable_ipv6() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6"]);
    run_command(&mut cmd, "IPv6", "Re-enabled");
}

pub fn set_wifi_private() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Set-NetConnectionProfile -NetworkCategory Private"]);
    run_command(&mut cmd, "WiFiProfile", "Set to Private");
}

pub fn block_ip(ip: &str) {
    let mut cmd = Command::new("netsh");
    cmd.args(["advfirewall", "firewall", "add", "rule",
               "name=TS-Block-IP", "dir=in", "action=block",
               &format!("remoteip={}", ip)]);
    run_command(&mut cmd, "BlockIP", &format!("Blocked IP: {}", ip));
}

pub fn network_kill() {
    let mut cmd = Command::new("netsh");
    cmd.args(["advfirewall", "set", "allprofiles", "state", "on"]);
    run_command(&mut cmd, "NetworkKill", "All firewall profiles enabled");
}

pub fn block_bruteforce_ips() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object { $_.Properties[19].Value } | Where-Object {$_ -match '\\d+\\.\\d+\\.\\d+\\.\\d+'} | Group-Object | Where-Object {$_.Count -gt 5} | Select-Object -ExpandProperty Name | ForEach-Object { New-NetFirewallRule -DisplayName 'TS-Block-Brute-' + $_ -Direction Inbound -RemoteAddress $_ -Action Block }"]);
    run_command(&mut cmd, "BruteForce", "Blocked brute force IPs");
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
                match fs::rename(&path, &quar) {
                    Ok(_) => {
                        log_repair("Startup", &format!("✅ Quarantined: {}", name));
                        log_incident("Startup", "Quarantined", &format!("Startup entry quarantined: {}", name));
                    }
                    Err(e) => {
                        log_repair("Startup", &format!("❌ Failed to quarantine {}: {}", name, e));
                    }
                }
            }
        }
    }
}

pub fn delete_fake_files() {
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
                    match fs::rename(entry.path(), &quar) {
                        Ok(_) => {
                            log_repair("FakeFiles", &format!("✅ Quarantined: {}", name));
                            log_incident("FakeFiles", "Quarantined", &format!("Fake file quarantined: {}", name));
                        }
                        Err(e) => {
                            log_repair("FakeFiles", &format!("❌ Failed to quarantine {}: {}", name, e));
                        }
                    }
                }
            }
        }
    }
}

pub fn eject_usb(device: &str) {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        &format!("Get-PnpDevice -FriendlyName '{}' | Disable-PnpDevice -Confirm:$false", device)]);
    run_command(&mut cmd, "USB", &format!("Ejected: {}", device));
}

pub fn disable_bt_devices() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Get-PnpDevice -Class Bluetooth | Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName -notmatch 'Intel|Qualcomm|Realtek|Broadcom|MediaTek|Microsoft'} | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"]);
    run_command(&mut cmd, "Bluetooth", "Disabled unknown BT devices");
}

pub fn disable_hid_devices() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Get-PnpDevice -Class Keyboard,Mouse | Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName -notmatch 'Microsoft|Logitech|Razer|Dell|HP|Lenovo|Synaptics|Intel'} | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"]);
    run_command(&mut cmd, "HID", "Disabled unknown HID devices");
}

pub fn disable_unknown_adapters() {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Get-NetAdapter | Where-Object {$_.Name -notmatch 'Wi-Fi|Ethernet|Bluetooth|vEthernet|Loopback'} | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue"]);
    run_command(&mut cmd, "Adapter", "Disabled unknown adapters");
}

pub fn clean_unicode_bidi() {
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    if let Ok(content) = fs::read_to_string(hosts) {
        let cleaned: String = content.chars()
            .filter(|c| !['\u{202E}', '\u{202D}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
                         '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{FEFF}',
                         '\u{202A}', '\u{202B}', '\u{202C}', '\u{00AD}'].contains(c))
            .collect();
        match fs::write(hosts, cleaned) {
            Ok(_) => {
                log_repair("Bidi", "✅ Cleaned Unicode bidi characters");
                log_incident("Bidi", "Cleaned", "Unicode bidi characters cleaned from hosts");
            }
            Err(e) => {
                log_repair("Bidi", &format!("❌ Failed: {}", e));
            }
        }
    }
}

// ============================================
// NEW: RDP AUTO-REPAIR
// ============================================

/// Disables RDP by stopping the Remote Desktop Service and blocking port 3389
pub fn disable_rdp() {
    // Stop and disable Remote Desktop Service
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-Command",
        "Set-Service -Name TermService -StartupType Disabled -Status Stopped"]);
    let result1 = run_command(&mut cmd, "RDP", "Disabled Remote Desktop Service");

    // Block port 3389 in Windows Firewall
    let mut cmd2 = Command::new("netsh");
    cmd2.args(["advfirewall", "firewall", "add", "rule",
               "name=TS-Block-RDP", "dir=in", "action=block",
               "protocol=TCP", "localport=3389"]);
    let result2 = run_command(&mut cmd2, "RDP", "Blocked RDP port 3389");

    if result1 && result2 {
        log_repair("RDP", "✅ RDP disabled successfully");
        log_incident("RDP", "Disabled", "RDP was disabled (port 3389 blocked, service stopped)");
    } else {
        log_repair("RDP", "⚠️ RDP disable partially failed");
        log_incident("RDP", "Partial", "RDP disable partially failed - manual review recommended");
    }
}

// ============================================
// ALERT ONLY REPAIRS
// ============================================

pub fn alert_bloatware() {
    log_repair("Bloatware", "⚠️ Bloatware/PUP detected");
    log_incident("Bloatware", "Detected", "Bloatware/PUP detected");
}

pub fn alert_suspicious_process() {
    log_repair("SuspiciousProcess", "⚠️ Suspicious process detected from Temp/Downloads");
    log_incident("SuspiciousProcess", "Detected", "Suspicious process detected");
}

pub fn alert_new_device() {
    log_repair("NewDevice", "⚠️ New network device detected");
    log_incident("NewDevice", "Detected", "New network device detected");
}

pub fn alert_secure_boot() {
    log_repair("SecureBoot", "⚠️ Secure Boot is OFF");
    log_incident("SecureBoot", "Alert", "Secure Boot is OFF");
}

pub fn alert_service_change() {
    log_repair("ServiceChange", "⚠️ Windows Service changed");
    log_incident("ServiceChange", "Alert", "Windows Service changed");
}

pub fn alert_event_log_cleared() {
    log_repair("EventLog", "⚠️ Event log was cleared");
    log_incident("EventLog", "Alert", "Event log was cleared - investigation recommended");
}

pub fn alert_vpn_disconnected() {
    log_repair("VPN", "⚠️ VPN disconnected");
    log_incident("VPN", "Alert", "VPN disconnected - check your connection");
}

pub fn alert_doh_changed() {
    log_repair("DoH", "⚠️ DNS over HTTPS changed");
    log_incident("DoH", "Alert", "DNS over HTTPS setting changed");
}

pub fn alert_laps_changed() {
    log_repair("LAPS", "⚠️ LAPS status changed");
    log_incident("LAPS", "Alert", "LAPS status changed");
}

pub fn alert_dhcp_spoofing() {
    log_repair("DHCP", "⚠️ DHCP server changed - possible spoofing");
    log_incident("DHCP", "Alert", "DHCP server changed - possible DHCP spoofing attack");
}

pub fn alert_bitlocker_off() {
    log_repair("BitLocker", "⚠️ BitLocker is disabled");
    log_incident("BitLocker", "Alert", "BitLocker is disabled - data at risk");
}

pub fn alert_credential_guard_off() {
    log_repair("CredGuard", "⚠️ Credential Guard is disabled");
    log_incident("CredGuard", "Alert", "Credential Guard is disabled - credential theft risk");
}

// ============================================
// GHOST MODE
// ============================================

pub fn ghost_mode_on() {
    let mut cmd1 = Command::new("powershell");
    cmd1.args(["-NoProfile", "-Command",
        "Get-NetFirewallRule -DisplayName 'TS-VPN-Only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayName 'TS-Block-ICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"]);
    run_command(&mut cmd1, "GhostMode", "Cleaned existing rules");

    let mut cmd2 = Command::new("powershell");
    cmd2.args(["-NoProfile", "-Command",
        "Set-NetFirewallProfile -All -DefaultInboundAction Block;",
        "Set-NetFirewallProfile -All -DefaultOutboundAction Block;",
        "New-NetFirewallRule -DisplayName 'TS-VPN-Only' -Direction Outbound -RemotePort 443,1194,51820 -Protocol TCP,UDP -Action Allow;",
        "New-NetFirewallRule -DisplayName 'TS-Block-ICMP' -Direction Inbound -Protocol ICMPv4 -Action Block;",
        "New-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -Direction Inbound -LocalPort 4444,5555,6667,8080,8888,31337,3389,5900,5800,5938,21,23,25,110,143,993,995,3306,5432,1433,1521,27017,6379,11211,5000,4500,5060 -Action Block;",
        "Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Disable-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Disable-NetFirewallRule;",
        "Stop-Service -Name 'FDResPub','SSDPSRV','upnphost','bthserv' -Force;",
        "Set-Service -Name 'FDResPub','SSDPSRV','upnphost','bthserv' -StartupType Disabled;"]);
    run_command(&mut cmd2, "GhostMode", "Enabled - Full lockdown active");
}

pub fn ghost_mode_off() {
    let mut cmd1 = Command::new("powershell");
    cmd1.args(["-NoProfile", "-Command",
        "Get-NetFirewallRule -DisplayName 'TS-VPN-Only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayName 'TS-Block-ICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"]);
    run_command(&mut cmd1, "GhostMode", "Removed existing rules");

    let mut cmd2 = Command::new("powershell");
    cmd2.args(["-NoProfile", "-Command",
        "Set-NetFirewallProfile -All -DefaultInboundAction Allow;",
        "Set-NetFirewallProfile -All -DefaultOutboundAction Allow;",
        "Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Enable-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Enable-NetFirewallRule;",
        "Set-Service -Name 'FDResPub','SSDPSRV','upnphost','bthserv' -StartupType Manual;"]);
    run_command(&mut cmd2, "GhostMode", "Disabled - Normal operation restored");
}

pub fn is_ghost_active() -> bool {
    let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
    Path::new(&ghost_flag).exists()
}