// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Auto-Repair Module — Silent with Safety Levels
//! - Automatic: Proxy, Defender, UAC, Windows Update, System Restore, SmartScreen,
//!   IPv6, RDP, Fake Extensions, Brute Force
//! - Alert Only: VPN, DoH, LAPS, Event Log
//! - Confirm Required: DNS, Firewall, HID, BT, Adapter, Startup, New Network Devices
//!
//! FIX: DNS and Firewall were "automatic" but a plain baseline != current check
//! can't tell real tampering from a legitimate network change (new Wi-Fi, VPN,
//! DHCP-assigned DNS) - gate them like the other confirm-required categories so
//! the daemon stops silently re-fighting the OS's live network config.
//!
//! FIX (2026-08-20): RDP, Fake Extensions, and Brute Force moved from
//! Confirm to Automatic - all three already had real repair actions sitting
//! behind a one-tap approval; the risk of a legitimate false positive is low
//! and the cost of the extra tap is real (an attacker with RDP access, or an
//! active brute-force attempt, doesn't wait for the approval). New Network
//! Devices moved from Alert to Confirm, since Alert had no action at all.

use std::process::Command;
use std::os::windows::process::CommandExt;
use std::fs;
use std::path::Path;
use chrono::Local;

const CREATE_NO_WINDOW: u32 = 0x08000000;

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
// FIX #9: Create hosts backup
// ============================================

pub fn create_hosts_backup() -> bool {
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let backup = format!("{}\\hosts.backup", DATA_DIR);
    if Path::new(&backup).exists() {
        return true;
    }
    match fs::copy(hosts, &backup) {
        Ok(_) => {
            log_repair("HostsBackup", "✅ Hosts backup created");
            true
        }
        Err(e) => {
            log_repair("HostsBackup", &format!("❌ Failed to create backup: {}", e));
            false
        }
    }
}

// ============================================
// AUTOMATIC REPAIRS (No user input) - ALL RETURN bool
// ============================================

pub fn force_reset_dns() -> bool {
    // FIX: Don't hardcode "Wi-Fi" - target whatever adapter is actually up
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }"]);
    run_command(&mut cmd, "DNS", "Reset to DHCP (active adapter)")
}

pub fn restore_hosts() -> bool {
    // FIX #9: First create backup if missing
    create_hosts_backup();
    
    let hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let backup = format!("{}\\hosts.backup", DATA_DIR);
    if Path::new(&backup).exists() {
        match fs::copy(&backup, hosts) {
            Ok(_) => {
                log_repair("Hosts", "✅ Restored from backup");
                log_incident("Hosts", "Success", "Hosts file restored from backup");
                true
            }
            Err(e) => {
                log_repair("Hosts", &format!("❌ Failed: {}", e));
                log_incident("Hosts", "Failed", &format!("Hosts restore failed: {}", e));
                false
            }
        }
    } else {
        log_repair("Hosts", "⚠️ No backup found");
        false
    }
}

pub fn force_enable_firewall() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command", "Set-NetFirewallProfile -All -Enabled True"]);
    run_command(&mut cmd, "Firewall", "Re-enabled all profiles")
}

pub fn remove_proxy() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue; Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0"]);
    run_command(&mut cmd, "Proxy", "Removed proxy settings")
}

pub fn enable_defender() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"]);
    run_command(&mut cmd, "Defender", "Re-enabled realtime protection")
}

pub fn enable_uac() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1"]);
    run_command(&mut cmd, "UAC", "Re-enabled")
}

pub fn enable_windows_update() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Set-Service -Name wuauserv -StartupType Automatic -Status Running"]);
    run_command(&mut cmd, "WindowsUpdate", "Re-enabled")
}

pub fn enable_system_restore() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Enable-ComputerRestore -Drive 'C:\\'"]);
    let result1 = run_command(&mut cmd, "SystemRestore", "Re-enabled");
    
    let mut cmd2 = Command::new("powershell");
    cmd2.creation_flags(CREATE_NO_WINDOW);
    cmd2.args(["-NoProfile", "-Command",
        "Set-Service -Name srservice -StartupType Automatic -Status Running"]);
    let result2 = run_command(&mut cmd2, "SystemRestore", "Service started");
    
    result1 && result2
}

pub fn enable_smart_screen() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -Value 'RequireAdmin'"]);
    let result1 = run_command(&mut cmd, "SmartScreen", "Re-enabled");
    
    let mut cmd2 = Command::new("powershell");
    cmd2.creation_flags(CREATE_NO_WINDOW);
    cmd2.args(["-NoProfile", "-Command",
        "Set-MpPreference -EnableSmartScreen $true"]);
    let result2 = run_command(&mut cmd2, "SmartScreen", "MP preference updated");
    
    result1 && result2
}

pub fn enable_ipv6() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6"]);
    run_command(&mut cmd, "IPv6", "Re-enabled")
}

pub fn set_wifi_private() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Set-NetConnectionProfile -NetworkCategory Private"]);
    run_command(&mut cmd, "WiFiProfile", "Set to Private")
}

pub fn block_bruteforce_ips() -> bool {
    // FIX #14: Check actual output, not just exit code
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object { $_.Properties[19].Value } | Where-Object {$_ -match '\\d+\\.\\d+\\.\\d+\\.\\d+'} | Group-Object | Where-Object {$_.Count -gt 5} | Select-Object -ExpandProperty Name | ForEach-Object { New-NetFirewallRule -DisplayName 'TS-Block-Brute-' + $_ -Direction Inbound -RemoteAddress $_ -Action Block }"]);
    
    match cmd.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            // Check if any rules were actually created
            let created = stdout.contains("New-NetFirewallRule") || stdout.contains("displayName");
            let has_error = stderr.contains("Error") || stderr.contains("Failed") || output.status.code() != Some(0);
            
            if created && !has_error {
                log_repair("BruteForce", "✅ Blocked brute force IPs");
                log_incident("BruteForce", "Success", "Brute force IPs blocked");
                true
            } else {
                log_repair("BruteForce", &format!("❌ Failed: No rules created or error occurred - {}", stderr));
                log_incident("BruteForce", "Failed", &format!("Brute force blocking failed: {}", stderr));
                false
            }
        }
        Err(e) => {
            log_repair("BruteForce", &format!("❌ Error: {}", e));
            log_incident("BruteForce", "Error", &format!("Brute force blocking error: {}", e));
            false
        }
    }
}

// ============================================
// CONFIRM REQUIRED / QUARANTINE REPAIRS - RETURN bool
// ============================================

pub fn quarantine_startup() -> bool {
    let startup = format!("{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        std::env::var("APPDATA").unwrap_or_default());
    let mut success = true;
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
                        success = false;
                    }
                }
            }
        }
    }
    success
}

pub fn delete_fake_files() -> bool {
    let dirs = ["Desktop", "Downloads"];
    let mut success = true;
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
                            success = false;
                        }
                    }
                }
            }
        }
    }
    success
}

// ============================================
// FIX #20: Confirm Required with auto-revert timer
// ============================================

/// Disables unknown Bluetooth devices with confirmation gate
pub fn disable_bt_devices() -> bool {
    // FIX #20: Add confirmation gate - only runs if explicitly confirmed
    // In automatic mode, this is a no-op; manual trigger via API required
    log_repair("Bluetooth", "⚠️ Manual confirmation required - use /confirm endpoint");
    log_incident("Bluetooth", "ConfirmationRequired", "Unknown BT devices detected - manual approval needed");
    false
}

/// Disables unknown HID devices with confirmation gate
pub fn disable_hid_devices() -> bool {
    log_repair("HID", "⚠️ Manual confirmation required - use /confirm endpoint");
    log_incident("HID", "ConfirmationRequired", "Unknown HID devices detected - manual approval needed");
    false
}

/// FIX: dns is documented as "Confirm Required" but was being auto-reset - gate it
pub fn flag_dns_changed() -> bool {
    log_repair("DNS", "⚠️ Manual confirmation required - use /confirm endpoint");
    log_incident("DNS", "ConfirmationRequired", "DNS servers changed - manual approval needed");
    false
}

/// FIX: firewall is documented as "Confirm Required" but was being auto-enabled - gate it
pub fn flag_firewall_changed() -> bool {
    log_repair("Firewall", "⚠️ Manual confirmation required - use /confirm endpoint");
    log_incident("Firewall", "ConfirmationRequired", "Firewall profile state changed - manual approval needed");
    false
}

/// Disables unknown network adapters with confirmation gate
pub fn disable_unknown_adapters() -> bool {
    log_repair("Adapter", "⚠️ Manual confirmation required - use /confirm endpoint");
    log_incident("Adapter", "ConfirmationRequired", "Unknown network adapters detected - manual approval needed");
    false
}

/// FIX: fakeext is documented as "Never Auto" but was being auto-quarantined - gate it
pub fn flag_fake_extensions() -> bool {
    log_repair("FakeExtensions", "⚠️ Manual confirmation required - use /confirm endpoint");
    log_incident("FakeExtensions", "ConfirmationRequired", "Fake file extensions detected - manual approval needed");
    false
}

/// FIX: startup is documented as "Confirm Required" but was being auto-quarantined - gate it
pub fn flag_startup_changed() -> bool {
    log_repair("Startup", "⚠️ Manual confirmation required - use /confirm endpoint");
    log_incident("Startup", "ConfirmationRequired", "Startup entries changed - manual approval needed");
    false
}

/// FIX: bruteforce is documented as "Confirm Required" but was being auto-blocked - gate it
pub fn flag_bruteforce_detected() -> bool {
    log_repair("BruteForce", "⚠️ Manual confirmation required - use /confirm endpoint");
    log_incident("BruteForce", "ConfirmationRequired", "Possible brute force detected - manual approval needed");
    false
}

/// Force versions (for API confirmation)
pub fn force_disable_bt_devices() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Get-PnpDevice -Class Bluetooth | Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName -notmatch 'Intel|Qualcomm|Realtek|Broadcom|MediaTek|Microsoft'} | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"]);
    run_command(&mut cmd, "Bluetooth", "Disabled unknown BT devices")
}

pub fn force_disable_hid_devices() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Get-PnpDevice -Class Keyboard,Mouse | Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName -notmatch 'Microsoft|Logitech|Razer|Dell|HP|Lenovo|Synaptics|Intel'} | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"]);
    run_command(&mut cmd, "HID", "Disabled unknown HID devices")
}

pub fn force_disable_unknown_adapters() -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Get-NetAdapter | Where-Object {$_.Name -notmatch 'Wi-Fi|Ethernet|Bluetooth|vEthernet|Loopback'} | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue"]);
    run_command(&mut cmd, "Adapter", "Disabled unknown adapters")
}

/// Blocks (inbound firewall rule, same mechanism as block_bruteforce_ips) only the
/// LAN device IPs that are new since the baseline - not a blanket block of every
/// device on the network, which would also cut off the user's own router/phone/
/// printer. Diffs the current ARP-detected devices against the saved baseline.
pub fn block_new_network_devices() -> bool {
    let baseline_devices = match crate::baseline::load_baseline_state() {
        Ok(state) => state.network_devices,
        Err(_) => return false,
    };
    let current_devices = crate::detect::get_network_devices();
    let new_devices: Vec<&String> = current_devices.iter()
        .filter(|ip| !ip.starts_with("ERROR_") && !baseline_devices.contains(ip))
        .collect();

    if new_devices.is_empty() {
        return true;
    }

    let mut all_ok = true;
    for ip in new_devices {
        let mut cmd = Command::new("powershell");
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.args(["-NoProfile", "-Command",
            &format!("New-NetFirewallRule -DisplayName 'TS-Block-Device-{}' -Direction Inbound -RemoteAddress {} -Action Block -ErrorAction SilentlyContinue", ip, ip)]);
        if !run_command(&mut cmd, "NetworkDevice", &format!("Blocked new device {}", ip)) {
            all_ok = false;
        }
    }
    all_ok
}

pub fn clean_unicode_bidi() -> bool {
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
                true
            }
            Err(e) => {
                log_repair("Bidi", &format!("❌ Failed: {}", e));
                false
            }
        }
    } else {
        false
    }
}

// ============================================
// NEW: RDP AUTO-REPAIR - RETURN bool
// ============================================

/// Disables RDP by stopping the Remote Desktop Service and blocking port 3389
pub fn disable_rdp() -> bool {
    // Stop and disable Remote Desktop Service
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "Set-Service -Name TermService -StartupType Disabled -Status Stopped"]);
    let result1 = run_command(&mut cmd, "RDP", "Disabled Remote Desktop Service");

    // Block port 3389 in Windows Firewall
    let mut cmd2 = Command::new("netsh");
    cmd2.creation_flags(CREATE_NO_WINDOW);
    cmd2.args(["advfirewall", "firewall", "add", "rule",
               "name=TS-Block-RDP", "dir=in", "action=block",
               "protocol=TCP", "localport=3389"]);
    let result2 = run_command(&mut cmd2, "RDP", "Blocked RDP port 3389");

    if result1 && result2 {
        log_repair("RDP", "✅ RDP disabled successfully");
        log_incident("RDP", "Disabled", "RDP was disabled (port 3389 blocked, service stopped)");
        true
    } else {
        log_repair("RDP", "⚠️ RDP disable partially failed");
        log_incident("RDP", "Partial", "RDP disable partially failed - manual review recommended");
        false
    }
}

// ============================================
// ALERT ONLY REPAIRS - RETURN bool (always true)
// ============================================

pub fn alert_bloatware() -> bool {
    log_repair("Bloatware", "⚠️ Bloatware/PUP detected");
    log_incident("Bloatware", "Detected", "Bloatware/PUP detected");
    true
}

pub fn alert_suspicious_process() -> bool {
    log_repair("SuspiciousProcess", "⚠️ Suspicious process detected from Temp/Downloads");
    log_incident("SuspiciousProcess", "Detected", "Suspicious process detected");
    true
}

pub fn alert_new_device() -> bool {
    log_repair("NewDevice", "⚠️ New network device detected");
    log_incident("NewDevice", "Detected", "New network device detected");
    true
}

pub fn alert_secure_boot() -> bool {
    log_repair("SecureBoot", "⚠️ Secure Boot is OFF");
    log_incident("SecureBoot", "Alert", "Secure Boot is OFF");
    true
}

pub fn alert_service_change() -> bool {
    log_repair("ServiceChange", "⚠️ Windows Service changed");
    log_incident("ServiceChange", "Alert", "Windows Service changed");
    true
}

pub fn alert_event_log_cleared() -> bool {
    log_repair("EventLog", "⚠️ Event log was cleared");
    log_incident("EventLog", "Alert", "Event log was cleared - investigation recommended");
    true
}

pub fn alert_vpn_disconnected() -> bool {
    log_repair("VPN", "⚠️ VPN disconnected");
    log_incident("VPN", "Alert", "VPN disconnected - check your connection");
    true
}

pub fn alert_doh_changed() -> bool {
    log_repair("DoH", "⚠️ DNS over HTTPS changed");
    log_incident("DoH", "Alert", "DNS over HTTPS setting changed");
    true
}

pub fn alert_laps_changed() -> bool {
    log_repair("LAPS", "⚠️ LAPS status changed");
    log_incident("LAPS", "Alert", "LAPS status changed");
    true
}

pub fn alert_dhcp_spoofing() -> bool {
    log_repair("DHCP", "⚠️ DHCP server changed - possible spoofing");
    log_incident("DHCP", "Alert", "DHCP server changed - possible DHCP spoofing attack");
    true
}

pub fn alert_bitlocker_off() -> bool {
    log_repair("BitLocker", "⚠️ BitLocker is disabled");
    log_incident("BitLocker", "Alert", "BitLocker is disabled - data at risk");
    true
}

pub fn alert_credential_guard_off() -> bool {
    log_repair("CredGuard", "⚠️ Credential Guard is disabled");
    log_incident("CredGuard", "Alert", "Credential Guard is disabled - credential theft risk");
    true
}

// ============================================
// NEW: EXECUTE CONFIRMED REPAIR (for /approve endpoint)
// ============================================

/// Executes a repair that was previously flagged as "confirm-required"
/// This is called from the /approve API endpoint after user approval
pub fn execute_confirmed_repair(category: &str) -> String {
    match category {
        "rdp" => {
            if disable_rdp() {
                "RDP disabled successfully".to_string()
            } else {
                "RDP disable failed - check logs".to_string()
            }
        }
        "dns" => {
            if force_reset_dns() {
                "DNS reset to DHCP successfully".to_string()
            } else {
                "DNS reset failed - check logs".to_string()
            }
        }
        "firewall" => {
            if force_enable_firewall() {
                "Firewall re-enabled successfully".to_string()
            } else {
                "Firewall re-enable failed - check logs".to_string()
            }
        }
        "bt" => {
            if force_disable_bt_devices() {
                "Bluetooth devices disabled successfully".to_string()
            } else {
                "Bluetooth disable failed - check logs".to_string()
            }
        }
        "hid" => {
            if force_disable_hid_devices() {
                "HID devices disabled successfully".to_string()
            } else {
                "HID disable failed - check logs".to_string()
            }
        }
        "startup" => {
            if quarantine_startup() {
                "Startup entries quarantined successfully".to_string()
            } else {
                "Startup quarantine failed - check logs".to_string()
            }
        }
        "bruteforce" => {
            if block_bruteforce_ips() {
                "Brute force IPs blocked successfully".to_string()
            } else {
                "Brute force blocking failed - check logs".to_string()
            }
        }
        "adapter" => {
            if force_disable_unknown_adapters() {
                "Unknown adapters disabled successfully".to_string()
            } else {
                "Adapter disable failed - check logs".to_string()
            }
        }
        "fakeext" => {
            if delete_fake_files() {
                "Fake extensions quarantined successfully".to_string()
            } else {
                "Fake extension quarantine failed - check logs".to_string()
            }
        }
        "devices" => {
            if block_new_network_devices() {
                "New network device(s) blocked successfully".to_string()
            } else {
                "Network device block failed - check logs".to_string()
            }
        }
        _ => format!("Unknown category: {}", category),
    }
}

// ============================================
// GHOST MODE - RETURN bool
// ============================================

/// FIX: Ghost Mode used to set DefaultOutboundAction=Block with only a narrow
/// 443/1194/51820 allow-list - that blocks DNS (port 53) and DHCP outright, so
/// it broke internet connectivity by design, not just when reverting badly.
/// Ghost Mode is now INBOUND-ONLY hardening (block risky inbound ports, block
/// inbound ICMP, hide from network discovery/file sharing, stop discovery
/// services) - it never touches outbound traffic, so it can't break DNS/browsing.
pub fn ghost_mode_on() -> bool {
    let mut cmd1 = Command::new("powershell");
    cmd1.creation_flags(CREATE_NO_WINDOW);
    cmd1.args(["-NoProfile", "-Command",
        "Get-NetFirewallRule -DisplayName 'TS-VPN-Only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayName 'TS-Block-ICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"]);
    let result1 = run_command(&mut cmd1, "GhostMode", "Cleaned existing rules");

    let mut cmd2 = Command::new("powershell");
    cmd2.creation_flags(CREATE_NO_WINDOW);
    cmd2.args(["-NoProfile", "-Command",
        "New-NetFirewallRule -DisplayName 'TS-Block-ICMP' -Direction Inbound -Protocol ICMPv4 -Action Block;",
        "New-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -Direction Inbound -LocalPort 4444,5555,6667,8080,8888,31337,3389,5900,5800,5938,21,23,25,110,143,993,995,3306,5432,1433,1521,27017,6379,11211,5000,4500,5060 -Action Block;",
        "Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Disable-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Disable-NetFirewallRule;",
        "Stop-Service -Name 'FDResPub','SSDPSRV','upnphost','bthserv' -Force;",
        "Set-Service -Name 'FDResPub','SSDPSRV','upnphost','bthserv' -StartupType Disabled;"]);
    let result2 = run_command(&mut cmd2, "GhostMode", "Enabled - Inbound hardening active (outbound unaffected)");

    // FIX: Verify the state we actually care about instead of trusting a
    // multi-statement PowerShell exit code, which can report success even
    // when an individual statement in the chain silently failed.
    let verified = verify_ghost_rule_present(true);
    result1 && result2 && verified
}

pub fn ghost_mode_off() -> bool {
    let mut cmd1 = Command::new("powershell");
    cmd1.creation_flags(CREATE_NO_WINDOW);
    cmd1.args(["-NoProfile", "-Command",
        "Get-NetFirewallRule -DisplayName 'TS-VPN-Only' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayName 'TS-Block-ICMP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayName 'TS-Block-Mal-Ports' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"]);
    let result1 = run_command(&mut cmd1, "GhostMode", "Removed existing rules");

    // FIX: Always force outbound/inbound defaults back to Windows' standard
    // Allow/Block regardless of what they currently are - this is a safety
    // net that cleans up any pre-existing bad state (e.g. from the old
    // full-lockdown implementation) even though ghost_mode_on() no longer
    // sets DefaultOutboundAction itself.
    let mut cmd2 = Command::new("powershell");
    cmd2.creation_flags(CREATE_NO_WINDOW);
    cmd2.args(["-NoProfile", "-Command",
        "Set-NetFirewallProfile -All -DefaultInboundAction Block;",
        "Set-NetFirewallProfile -All -DefaultOutboundAction Allow;",
        "Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Enable-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Enable-NetFirewallRule;",
        "Set-Service -Name 'FDResPub','SSDPSRV','upnphost','bthserv' -StartupType Manual;"]);
    let result2 = run_command(&mut cmd2, "GhostMode", "Disabled - Normal operation restored");

    let verified = verify_ghost_rule_present(false);
    result1 && result2 && verified
}

/// Re-queries live firewall state to confirm a ghost_mode_on/off call actually
/// took effect, rather than trusting the PowerShell process exit code alone.
fn verify_ghost_rule_present(expect_active: bool) -> bool {
    let mut cmd = Command::new("powershell");
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.args(["-NoProfile", "-Command",
        "(Get-NetFirewallProfile -Name Public).DefaultOutboundAction.ToString();",
        "(Get-NetFirewallRule -DisplayName 'TS-Block-ICMP' -ErrorAction SilentlyContinue | Measure-Object).Count"]);
    match cmd.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
            let outbound_allowed = lines.first().map(|l| *l == "Allow").unwrap_or(false);
            let icmp_rule_count: i32 = lines.get(1).and_then(|l| l.parse().ok()).unwrap_or(-1);

            // Outbound must always stay Allow - that invariant holds whether
            // Ghost Mode is on or off in this inbound-only design.
            let outbound_ok = outbound_allowed;
            let icmp_ok = if expect_active { icmp_rule_count >= 1 } else { icmp_rule_count == 0 };

            if !outbound_ok || !icmp_ok {
                log_repair("GhostMode", &format!("❌ Verification failed: outbound_allowed={} icmp_rule_count={}", outbound_allowed, icmp_rule_count));
                log_incident("GhostMode", "VerificationFailed", "Ghost Mode state did not match expected firewall state after apply");
            }
            outbound_ok && icmp_ok
        }
        Err(e) => {
            log_repair("GhostMode", &format!("❌ Verification error: {}", e));
            false
        }
    }
}

pub fn is_ghost_active() -> bool {
    let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
    Path::new(&ghost_flag).exists()
}