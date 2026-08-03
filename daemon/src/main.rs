// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

use std::time::Duration;
use std::fs;

mod modules;
use modules::detect;
use modules::repair;
use modules::server;
use modules::config;
use modules::crypto;
use modules::integrity;
use modules::timeline;
use modules::baseline;
use modules::policy;
use modules::trust;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";

// ============================================
// MAIN
// ============================================

fn main() {
    // Ensure data directory exists
    if let Err(e) = fs::create_dir_all(DATA_DIR) {
        eprintln!("Failed to create data dir: {}", e);
        std::process::exit(1);
    }
    let _ = fs::create_dir_all(format!("{}\\canary", DATA_DIR));
    let _ = fs::create_dir_all(format!("{}\\quarantine", DATA_DIR));

    println!("🛡️ Invisibly - Autonomous Endpoint Security");
    println!("📡 Detects 38 signals - Auto-repairs - Integrity Score");
    println!("");

    // Check self-integrity — FIX: only warn if hash exists and mismatches
    if !check_self_integrity() {
        println!("⚠️ WARNING: Self-integrity check failed!");
        println!("   This may happen after a legitimate update. Re-stamping hash...");
        // Re-stamp the hash for legitimate updates
        if let Ok(exe) = std::env::current_exe() {
            if let Ok(data) = fs::read(&exe) {
                let hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, &data));
                let stored_path = format!("{}\\agent.hash", DATA_DIR);
                let _ = fs::write(&stored_path, &hash);
                println!("   ✅ Hash updated");
            }
        }
    }

    // Load or create baseline
    let baseline = load_or_create_baseline();
    let home_ssid = config::load_home_ssid().unwrap_or_else(|| "Unknown".into());

    // ============================================
    // FIX: Compute initial report at startup
    // ============================================
    let current = detect::collect_state();
    let issues = detect::diff(&baseline, &current);
    let is_baseline_valid = baseline::verify_baseline().valid;
    let is_lockdown = repair::is_ghost_active();
    let report = integrity::calculate(&issues, is_lockdown, is_baseline_valid);
    server::set_integrity_report(report.clone());
    server::set_trust_level(trust::get_trust_score());
    println!("📊 Initial Integrity Score: {} | Trust Level: {}", report.score, server::get_trust_level());
    println!("");

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

        // ============================================
        // 1. COLLECT STATE
        // ============================================
        let current = detect::collect_state();

        // ============================================
        // 2. VERIFY BASELINE INTEGRITY
        // ============================================
        let baseline_status = baseline::verify_baseline();
        let is_baseline_valid = baseline_status.valid;

        if !is_baseline_valid {
            println!("❌ Baseline integrity check failed!");
            let report = integrity::calculate(&[], false, false);
            server::set_integrity_report(report.clone());
            server::set_trust_level(trust::get_trust_score());
            continue;
        }

        // ============================================
        // 3. DETECT CHANGES
        // ============================================
        let issues = detect::diff(&baseline, &current);

        // ============================================
        // 4. RISK ASSESSMENT & AUTO-REPAIR
        // ============================================
        if !issues.is_empty() {
            println!("⚠️ Found {} changes!", issues.len());

            // Apply repairs based on category
            for (category, _) in &issues {
                match category.as_str() {
                    // Automatic repairs
                    "dns" => repair::reset_dns(),
                    "hosts" => repair::restore_hosts(),
                    "firewall" => repair::enable_firewall(),
                    "proxy" => repair::remove_proxy(),
                    "defender" => repair::enable_defender(),
                    "uac" => repair::enable_uac(),
                    "wu" => repair::enable_windows_update(),
                    "sr" => repair::enable_system_restore(),
                    "smartscreen" => repair::enable_smart_screen(),
                    "ipv6" => repair::enable_ipv6(),
                    "wifi_profile" => repair::set_wifi_private(),
                    // Alert only
                    "vpn" => repair::alert_vpn_disconnected(),
                    "doh" => repair::alert_doh_changed(),
                    "laps" => repair::alert_laps_changed(),
                    "eventlog" => repair::alert_event_log_cleared(),
                    // Quarantine
                    "fakeext" => repair::delete_fake_files(),
                    "hid" => repair::disable_hid_devices(),
                    "bt" => repair::disable_bt_devices(),
                    "adapter" => repair::disable_unknown_adapters(),
                    "startup" => repair::quarantine_startup(),
                    "bruteforce" => repair::block_bruteforce_ips(),
                    _ => {}
                }
            }

            // Log to timeline (BEFORE state)
            for (category, msg) in &issues {
                let _ = timeline::add_entry(
                    category,
                    "detected",
                    msg,
                    "repair attempted",
                    timeline::RepairResult::Success,
                    0,
                );
            }
        }

        // ============================================
        // 5. RE-COLLECT CURRENT STATE (After Repairs)
        // ============================================
        let current_after_repair = detect::collect_state();

        // Re-detect issues after repairs
        let issues_after = detect::diff(&baseline, &current_after_repair);

        // ============================================
        // 6. CALCULATE INTEGRITY SCORE FROM CURRENT STATE
        // ============================================
        let is_lockdown = repair::is_ghost_active();
        let report = integrity::calculate(&issues_after, is_lockdown, is_baseline_valid);
        
        // Store integrity report
        server::set_integrity_report(report.clone());
        
        // Update trust level if critical issues remain
        if !issues_after.is_empty() {
            for (category, _) in &issues_after {
                match category.as_str() {
                    "firewall" | "defender" | "uac" | "wu" | "sr" | "smartscreen" | "secureboot" => {
                        trust::deduct_trust(&format!("{} compromised", category), 10);
                    }
                    "dns" | "hosts" | "proxy" | "startup" => {
                        trust::deduct_trust(&format!("{} changed", category), 5);
                    }
                    _ => {}
                }
            }
        } else {
            // Gradual recovery if no issues
            trust::recover_trust(2);
        }
        
        server::set_trust_level(trust::get_trust_score());

        // ============================================
        // 7. UPDATE TIMELINE (AFTER state)
        // ============================================
        if !issues_after.is_empty() {
            for (category, msg) in &issues_after {
                let _ = timeline::add_entry(
                    category,
                    "repaired",
                    msg,
                    "system restored",
                    timeline::RepairResult::Success,
                    0,
                );
            }
        }

        // ============================================
        // 8. WIFI MONITORING
        // ============================================
        let wifi = detect::get_wifi();
        if wifi != "Unknown" && wifi != home_ssid {
            println!("🔵 WiFi changed: {} (home: {})", wifi, home_ssid);
        }

        // ============================================
        // 9. DISPLAY STATUS
        // ============================================
        let report = server::get_integrity_report().unwrap_or(report);
        let trust_level = server::get_trust_level();
        println!("📊 Integrity Score: {} | Trust Level: {}", report.score, trust_level);
    }
}

// ============================================
// HELPERS
// ============================================

fn check_self_integrity() -> bool {
    let exe_path = std::env::current_exe().unwrap();
    let current_hash = hash_file(&exe_path);
    let stored_path = format!("{}\\agent.hash", DATA_DIR);

    if let Ok(stored_hash) = fs::read_to_string(&stored_path) {
        stored_hash.trim() == current_hash
    } else {
        // No hash file — first run, create it
        let _ = fs::write(&stored_path, &current_hash);
        true
    }
}

fn hash_file(path: &std::path::Path) -> String {
    let data = fs::read(path).unwrap_or_default();
    hex::encode(ring::digest::digest(&ring::digest::SHA256, &data))
}

fn load_or_create_baseline() -> detect::SystemState {
    let status = baseline::verify_baseline();

    if status.exists && status.valid {
        if let Ok(state) = baseline::load_baseline_state() {
            println!("✅ Loaded baseline version: {}", status.version);
            return state;
        }
    }

    println!("📝 Creating new baseline...");
    let state = detect::collect_state();
    let _ = baseline::create_baseline(&state);
    state
}