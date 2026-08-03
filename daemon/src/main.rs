// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.`n// This software is proprietary and confidential.`nuse std::time::Duration;
use std::fs;

mod modules;
use modules::detect;
use modules::repair;
use modules::server;
use modules::config;
use modules::crypto;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";

fn main() {
    // Ensure data directory exists
    if let Err(e) = fs::create_dir_all(DATA_DIR) {
        eprintln!("Failed to create data dir: {}", e);
        std::process::exit(1);
    }
    let _ = fs::create_dir_all(format!("{}\\canary", DATA_DIR));
    let _ = fs::create_dir_all(format!("{}\\quarantine", DATA_DIR));

    println!("🛡️ Invisibly - Autonomous Endpoint Security");
    println!("📡 Detects 38 signals - Auto-repairs - Silent mode");
    println!("");

    // Check self-integrity
    if !check_self_integrity() {
        println!("⚠️ WARNING: Self-integrity check failed!");
    }

    // Load baseline
    let baseline = load_or_create_baseline();
    let home_ssid = config::load_home_ssid().unwrap_or_else(|| "Unknown".into());

    // Start API server
    std::thread::spawn(|| {
        if let Err(e) = server::run() {
            eprintln!("API server error: {}", e);
        }
    });

    std::thread::sleep(Duration::from_secs(2));

    println!("✅ Invisibly running - Press Ctrl+C to stop");
    println!("");

    // Main monitoring loop
    loop {
        std::thread::sleep(Duration::from_secs(300)); // 5 minutes

        let current = detect::collect_state();

        // Check ransomware
        if detect::check_ransomware() {
            println!("🔴 RANSOMWARE CANARY TRIGGERED!");
            repair::network_kill();
        }

        // Check USB
        let usb = detect::check_usb();
        if !usb.is_empty() {
            println!("🔴 USB device detected: {}", usb);
            repair::eject_usb(&usb);
        }

        // Check port scan
        let scanner = detect::detect_port_scan(10);
        if !scanner.is_empty() {
            println!("🔴 Port scan from {}", scanner);
            repair::block_ip(&scanner);
        }

        // Diff against baseline
        let issues = detect::diff(&baseline, &current);

        if !issues.is_empty() {
            println!("⚠️ Found {} changes!", issues.len());

            // Set trust state
            let state = if issues.iter().any(|(_, msg)| msg.contains("compromised") || msg.contains("OFF") || msg.contains("DISABLED") || msg.contains("EMPTY")) {
                "Compromised"
            } else if issues.len() > 0 {
                "Warning"
            } else {
                "Trusted"
            };
            server::set_trust_state(state);

            // Log alerts and apply auto-repair
            for (category, msg) in &issues {
                println!("   - {}: {}", category, msg);

                // Auto-repair based on category
                match category.as_str() {
                    // === EXISTING ===
                    "dns" => repair::reset_dns(),
                    "hosts" => repair::restore_hosts(),
                    "firewall" => repair::enable_firewall(),
                    "proxy" => repair::remove_proxy(),
                    "defender" => repair::enable_defender(),
                    "startup" => repair::quarantine_startup(),
                    "bt" => repair::disable_bt_devices(),
                    "hid" => repair::disable_hid_devices(),
                    "adapter" => repair::disable_unknown_adapters(),
                    "fakeext" => repair::delete_fake_files(),
                    "trojan_source" => repair::clean_unicode_bidi(),
                    "bruteforce" => repair::block_bruteforce_ips(),
                    "bloatware" => repair::alert_bloatware(),
                    "susp_proc" => repair::alert_suspicious_process(),
                    "devices" => repair::alert_new_device(),
                    "secureboot" => repair::alert_secure_boot(),
                    "services" => repair::alert_service_change(),

                    // === NEW: 10 MISSING GAPS ===
                    "uac" => {
                        if msg.contains("OFF") {
                            repair::enable_uac();
                        }
                    }
                    "wu" => {
                        if msg.contains("OFF") {
                            repair::enable_windows_update();
                        }
                    }
                    "sr" => {
                        if msg.contains("OFF") {
                            repair::enable_system_restore();
                        }
                    }
                    "eventlog" => {
                        if msg.contains("EMPTY") {
                            repair::alert_event_log_cleared();
                        }
                    }
                    "smartscreen" => {
                        if msg.contains("OFF") {
                            repair::enable_smart_screen();
                        }
                    }
                    "vpn" => {
                        if msg.contains("DISCONNECTED") {
                            repair::alert_vpn_disconnected();
                        }
                    }
                    "ipv6" => {
                        if msg.contains("OFF") {
                            repair::enable_ipv6();
                        }
                    }
                    "wifi_profile" => {
                        if msg.contains("PUBLIC") {
                            repair::set_wifi_private();
                        }
                    }
                    "doh" => {
                        if msg.contains("OFF") {
                            repair::alert_doh_changed();
                        }
                    }
                    "laps" => {
                        if msg.contains("DISABLED") {
                            repair::alert_laps_changed();
                        }
                    }
                    _ => {}
                }
            }
        }

        // WiFi monitoring
        let wifi = detect::get_wifi();
        if wifi != "Unknown" && wifi != home_ssid {
            println!("🔵 WiFi changed: {} (home: {})", wifi, home_ssid);
            server::set_trust_state("Warning");
        }
    }
}

fn check_self_integrity() -> bool {
    let exe_path = std::env::current_exe().unwrap();
    let current_hash = hash_file(&exe_path);
    let stored_path = format!("{}\\agent.hash", DATA_DIR);

    if let Ok(stored_hash) = fs::read_to_string(&stored_path) {
        stored_hash.trim() == current_hash
    } else {
        fs::write(&stored_path, &current_hash).ok();
        true
    }
}

fn hash_file(path: &std::path::Path) -> String {
    let data = fs::read(path).unwrap_or_default();
    hex::encode(ring::digest::digest(&ring::digest::SHA256, &data))
}

fn load_or_create_baseline() -> detect::SystemState {
    let baseline_path = format!("{}\\baseline.json", DATA_DIR);

    if let Ok(data) = fs::read(&baseline_path) {
        if let Ok(json) = crypto::decrypt_baseline(&data.to_vec()) {
            if let Ok(state) = serde_json::from_str(&json) {
                return state;
            }
        }
    }

    let state = detect::collect_state();
    let json = serde_json::to_string(&state).unwrap();
    let encrypted = crypto::encrypt_baseline(&json);
    fs::write(&baseline_path, encrypted).ok();
    state
}
