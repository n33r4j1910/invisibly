// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Behavior-Based Detection
//!
//! Detects ANY change between baseline and current state.
//! This catches ALL configuration drift, not just pre-defined threats.
//!
//! Returns: (category, details, action_type)
//! - action_type: "automatic" (safe to auto-repair)
//! - action_type: "confirm" (requires user confirmation)
//! - action_type: "alert" (just alert, no repair)
//! - action_type: "manual" (requires manual intervention)

use crate::detect::SystemState;
use std::collections::HashMap;

/// Detects ALL changes between baseline and current state
pub fn detect_all_changes(baseline: &SystemState, current: &SystemState) -> Vec<(String, String, String)> {
    let mut changes = Vec::new();

    // ============================================
    // NETWORK CHANGES
    // ============================================

    // FIX: DNS - Only treat as security signal when network identity is unchanged
    // Added additional signals for better detection
    let network_identity_changed = baseline.wifi_ssid != current.wifi_ssid
        || baseline.dhcp_server != current.dhcp_server
        || baseline.vpn_status != current.vpn_status
        || baseline.network_adapters != current.network_adapters;

    let mut baseline_dns = baseline.dns_servers.clone();
    let mut current_dns = current.dns_servers.clone();
    baseline_dns.sort();
    current_dns.sort();

    if baseline_dns != current_dns && !network_identity_changed {
        changes.push((
            "dns".to_string(),
            format!("DNS changed from {:?} to {:?} while network unchanged (SSID '{}')", baseline_dns, current_dns, current.wifi_ssid),
            "confirm".to_string()
        ));
    }

    if baseline.hosts_hash != current.hosts_hash {
        changes.push((
            "hosts".to_string(),
            "Hosts file modified".to_string(),
            "automatic".to_string()
        ));
    }

    if baseline.proxy_settings != current.proxy_settings {
        changes.push((
            "proxy".to_string(),
            format!("Proxy changed from {:?} to {:?}", baseline.proxy_settings, current.proxy_settings),
            "automatic".to_string()
        ));
    }

    // FIX: arp/devices only mean something as a spoofing signal when they
    // change on a network you were already trusting. Switching WiFi networks
    // makes the ARP table and every device on the new LAN look "new" purely
    // because it's a different network - that's normal daily activity, not
    // an attack, and was previously nagging a normal user every time they
    // reconnected somewhere new. Gate both on network_identity_changed
    // (already computed above for DNS) the same way.
    if baseline.arp_table != current.arp_table && !network_identity_changed {
        changes.push((
            "arp".to_string(),
            format!("ARP table changed: {:?}", current.arp_table),
            "alert".to_string()
        ));
    }

    if baseline.wifi_ssid != current.wifi_ssid {
        changes.push((
            "wifi".to_string(),
            format!("WiFi changed from '{}' to '{}'", baseline.wifi_ssid, current.wifi_ssid),
            // FIX: was "alert" (nagged on every network switch). Switching
            // WiFi networks isn't a security event by itself, so treat it
            // like tasks/services - silently accept the new network identity
            // (wifi/dhcp/arp/devices) as the new normal instead of flagging it.
            "automatic".to_string()
        ));
    }

    if baseline.network_devices != current.network_devices && !network_identity_changed {
        changes.push((
            "devices".to_string(),
            format!("New network devices: {:?}", current.network_devices),
            "confirm".to_string()  // FIX 2026-08-20: was alert (no action possible) - now confirm, blocks the new IP(s) on approval
        ));
    }

    if baseline.network_adapters != current.network_adapters {
        changes.push((
            "adapter".to_string(),
            format!("Network adapters changed: {:?}", current.network_adapters),
            "confirm".to_string()
        ));
    }

    // ============================================
    // FIREWALL CHANGES - FIX: Robust handling with error detection
    // ============================================

    // FIX: Check if current firewall detection has an error
    let has_firewall_error = current.firewall_profiles.iter()
        .any(|p| p.starts_with("ERROR_"));

    if has_firewall_error {
        // Skip firewall comparison on detection error to avoid false positives
        // Don't push any changes
    } else {
        let parse_fw_profiles = |profiles: &[String]| -> HashMap<String, bool> {
            profiles.iter().filter_map(|p| {
                let mut parts = p.splitn(2, ':');
                let name = parts.next()?.trim().to_string();
                let state = parts.next()?.trim().to_lowercase();
                // Handle multiple variants of "ON"
                let enabled = state == "on" || state == "true" || state == "enabled" || state == "1";
                Some((name, enabled))
            }).collect()
        };

        let baseline_fw = parse_fw_profiles(&baseline.firewall_profiles);
        let current_fw = parse_fw_profiles(&current.firewall_profiles);

        // FIX: Only flag profiles that were ON in baseline but are OFF in current
        let weakened_profiles: Vec<String> = baseline_fw.iter()
            .filter(|(name, &was_on)| {
                was_on && current_fw.get(*name) == Some(&false)
            })
            .map(|(name, _)| name.clone())
            .collect();

        if !weakened_profiles.is_empty() {
            changes.push((
                "firewall".to_string(),
                format!("Firewall profile(s) disabled: {:?} (current: {:?})", 
                        weakened_profiles, current.firewall_profiles),
                "confirm".to_string()
            ));
        }
    }

    if baseline.defender_status != current.defender_status {
        changes.push((
            "defender".to_string(),
            current.defender_status.clone(), // Pass raw value
            "automatic".to_string()
        ));
    }

    if baseline.uac_status != current.uac_status {
        changes.push((
            "uac".to_string(),
            current.uac_status.clone(), // Pass raw value
            "automatic".to_string()
        ));
    }

    if baseline.windows_update_status != current.windows_update_status {
        changes.push((
            "wu".to_string(),
            current.windows_update_status.clone(), // Pass raw value
            "automatic".to_string()
        ));
    }

    if baseline.system_restore_status != current.system_restore_status {
        changes.push((
            "sr".to_string(),
            current.system_restore_status.clone(), // Pass raw value
            "automatic".to_string()
        ));
    }

    if baseline.smart_screen_status != current.smart_screen_status {
        changes.push((
            "smartscreen".to_string(),
            current.smart_screen_status.clone(), // Pass raw value
            "automatic".to_string()
        ));
    }

    if baseline.secure_boot != current.secure_boot {
        changes.push((
            "secureboot".to_string(),
            current.secure_boot.clone(), // Pass raw value
            "manual".to_string()
        ));
    }

    // ============================================
    // PERSISTENCE CHANGES
    // ============================================

    if baseline.startup_entries != current.startup_entries {
        changes.push((
            "startup".to_string(),
            format!("Startup entries changed: {:?}", current.startup_entries),
            "confirm".to_string()
        ));
    }

    // FIX: Changed "tasks" from "alert" to "automatic" for auto-repair
    if baseline.scheduled_tasks != current.scheduled_tasks {
        changes.push((
            "tasks".to_string(),
            format!("Scheduled tasks changed: {:?}", current.scheduled_tasks),
            "automatic".to_string()  // CHANGED: alert → automatic
        ));
    }

    // FIX: Changed "services" from "alert" to "automatic" for auto-repair
    if baseline.services_list != current.services_list {
        changes.push((
            "services".to_string(),
            format!("Services changed: {:?}", current.services_list),
            "automatic".to_string()  // CHANGED: alert → automatic
        ));
    }

    // ============================================
    // HARDWARE CHANGES
    // ============================================

    if baseline.bt_devices != current.bt_devices {
        changes.push((
            "bt".to_string(),
            format!("New Bluetooth devices: {:?}", current.bt_devices),
            "confirm".to_string()
        ));
    }

    if baseline.hid_devices != current.hid_devices {
        changes.push((
            "hid".to_string(),
            format!("New HID devices: {:?}", current.hid_devices),
            "confirm".to_string()
        ));
    }

    // ============================================
    // FILE CHANGES
    // ============================================

    if baseline.fake_extensions != current.fake_extensions {
        changes.push((
            "fakeext".to_string(),
            format!("Fake extensions: {:?}", current.fake_extensions),
            "automatic".to_string()  // FIX 2026-08-20: was confirm - near-zero false-positive rate, quarantine is reversible
        ));
    }

    if baseline.unicode_bidi_files != current.unicode_bidi_files {
        changes.push((
            "trojan_source".to_string(),
            format!("Unicode bidi files: {:?}", current.unicode_bidi_files),
            "automatic".to_string()
        ));
    }

    // ============================================
    // SOCIAL ENGINEERING CHANGES
    // ============================================

    if baseline.homoglyph_domains != current.homoglyph_domains {
        changes.push((
            "homoglyph".to_string(),
            format!("Homoglyph domains: {:?}", current.homoglyph_domains),
            "alert".to_string()
        ));
    }

    // ============================================
    // PROCESS CHANGES
    // ============================================

    if baseline.suspicious_processes != current.suspicious_processes {
        changes.push((
            "susp_proc".to_string(),
            format!("Suspicious processes: {:?}", current.suspicious_processes),
            "alert".to_string()
        ));
    }

    // ============================================
    // SOFTWARE CHANGES
    // ============================================

    if baseline.installed_software != current.installed_software {
        changes.push((
            "bloatware".to_string(),
            format!("New software detected: {:?}", current.installed_software),
            "alert".to_string()
        ));
    }

    // ============================================
    // AUTHENTICATION CHANGES
    // ============================================

    if baseline.login_failures != current.login_failures {
        changes.push((
            "bruteforce".to_string(),
            current.login_failures.clone(), // Pass raw value
            "automatic".to_string()  // FIX 2026-08-20: was confirm - blocking an IP hammering failed logons is standard, low-risk behavior
        ));
    }

    // ============================================
    // NETWORK CONFIGURATION CHANGES
    // ============================================

    if baseline.vpn_status != current.vpn_status {
        changes.push((
            "vpn".to_string(),
            current.vpn_status.clone(), // Pass raw value
            "alert".to_string()
        ));
    }

    if baseline.ipv6_status != current.ipv6_status {
        changes.push((
            "ipv6".to_string(),
            current.ipv6_status.clone(), // Pass raw value
            "automatic".to_string()
        ));
    }

    if baseline.wifi_profile_status != current.wifi_profile_status {
        changes.push((
            "wifi_profile".to_string(),
            current.wifi_profile_status.clone(), // Pass raw value
            "automatic".to_string()
        ));
    }

    if baseline.doh_status != current.doh_status {
        changes.push((
            "doh".to_string(),
            current.doh_status.clone(), // Pass raw value
            "alert".to_string()
        ));
    }

    if baseline.laps_status != current.laps_status {
        changes.push((
            "laps".to_string(),
            current.laps_status.clone(), // Pass raw value
            "alert".to_string()
        ));
    }

    // ============================================
    // NEW: DHCP SPOOFING
    // ============================================
    // FIX: same as arp/devices above - a DHCP server change is only a
    // spoofing signal on a network whose identity didn't otherwise change.
    if baseline.dhcp_server != current.dhcp_server && !network_identity_changed {
        changes.push((
            "dhcp".to_string(),
            current.dhcp_server.clone(), // Pass raw value
            "alert".to_string()
        ));
    }

    // ============================================
    // NEW: BITLOCKER
    // ============================================
    if baseline.bitlocker_status != current.bitlocker_status {
        changes.push((
            "bitlocker".to_string(),
            current.bitlocker_status.clone(), // Pass raw value
            "alert".to_string()
        ));
    }

    // ============================================
    // NEW: CREDENTIAL GUARD
    // ============================================
    if baseline.credential_guard_status != current.credential_guard_status {
        changes.push((
            "credguard".to_string(),
            current.credential_guard_status.clone(), // Pass raw value
            "alert".to_string()
        ));
    }

    // ============================================
    // NEW: RDP
    // ============================================
    if baseline.rdp_status != current.rdp_status {
        changes.push((
            "rdp".to_string(),
            current.rdp_status.clone(), // Pass raw value
            "automatic".to_string()  // FIX 2026-08-20: back to automatic - unexpected RDP enablement is a strong compromise signal, low downside to auto-disabling
        ));
    }

    // ============================================
    // NEW: EVENT LOG
    // ============================================
    if baseline.event_log_status != current.event_log_status {
        changes.push((
            "eventlog".to_string(),
            current.event_log_status.clone(), // Pass raw value
            "alert".to_string()
        ));
    }

    changes
}