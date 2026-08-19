use std::time::Duration;
use std::fs;
use std::ffi::OsString;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::Path;
use std::os::windows::process::CommandExt;

mod modules;
use modules::detect;
use modules::repair;
use modules::server;
use modules::config;
use modules::crypto;
use modules::integrity;
use modules::timeline;
use modules::baseline;
use modules::trust;
use modules::behavior;

use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";
const SERVICE_NAME: &str = "InvisiblyDaemon";

// ============================================
// GLOBAL BASELINE (Shared across threads)
// ============================================

pub static BASELINE: once_cell::sync::Lazy<Mutex<Option<detect::SystemState>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

fn reload_baseline() -> Option<detect::SystemState> {
    let status = baseline::verify_baseline();
    if status.exists && status.valid {
        if let Ok(state) = baseline::load_baseline_state() {
            let mut guard = BASELINE.lock().unwrap();
            *guard = Some(state.clone());
            println!("✅ Baseline reloaded (version: {})", status.version);
            return Some(state);
        }
    }
    None
}

fn get_baseline() -> detect::SystemState {
    let mut guard = BASELINE.lock().unwrap();
    if let Some(state) = guard.as_ref() {
        return state.clone();
    }
    drop(guard);
    
    let status = baseline::verify_baseline();
    if status.exists && status.valid {
        if let Ok(state) = baseline::load_baseline_state() {
            let mut guard = BASELINE.lock().unwrap();
            *guard = Some(state.clone());
            println!("✅ Loaded baseline version: {}", status.version);
            return state;
        }
    }

    println!("📝 Creating new baseline...");
    let state = detect::collect_state();
    let _ = baseline::create_baseline(&state);
    let mut guard = BASELINE.lock().unwrap();
    *guard = Some(state.clone());
    state
}

// ============================================
// WINDOWS SERVICE ENTRY POINT
// ============================================

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    let status_handle = service_control_handler::register(
        SERVICE_NAME,
        |control_event| {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    std::process::exit(0);
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        },
    ).expect("Failed to register service control handler");

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        process_id: None,
        checkpoint: 0,
        wait_hint: Duration::default(),
    }).expect("Failed to set service status");

    run_daemon();
}

// ============================================
// MAIN - Entry point
// ============================================

fn main() {
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::GetConsoleWindow;
        let console_window = unsafe { GetConsoleWindow() };
        let has_console = !console_window.0.is_null();
        
        if !has_console {
            service_dispatcher::start(SERVICE_NAME, ffi_service_main)
                .expect("Failed to start service dispatcher");
            return;
        }
    }

    run_daemon();
}

// ============================================
// START TRAY AUTOMATICALLY
// ============================================

fn start_tray_if_not_running() {
    // Check if tray is already running
    let output = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq invisibly-tray.exe"])
        .output();

    if let Ok(output) = output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("invisibly-tray.exe") {
            println!("✅ Tray is already running");
            return;
        }
    }

    // Find tray executable
    let tray_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|parent| parent.join("invisibly-tray.exe")))
        .and_then(|p| if p.exists() { Some(p) } else { None });

    if let Some(tray_path) = tray_path {
        match std::process::Command::new(tray_path)
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn() {
            Ok(_) => println!("✅ Tray started automatically"),
            Err(e) => println!("⚠️ Failed to start tray: {}", e),
        }
    } else {
        println!("⚠️ Tray executable not found");
    }
}

// ============================================
// DAEMON CORE LOGIC
// ============================================

fn run_daemon() {
    // START: Auto-start tray
    start_tray_if_not_running();

    if !is_elevated() {
        println!("⚠️ WARNING: Running unelevated. Auto-repair may fail!");
        println!("   Please run as Administrator for full protection.");
    }

    if let Err(e) = config::ensure_data_dir() {
        eprintln!("Failed to create data dir: {}", e);
        std::process::exit(1);
    }

    println!("🛡️ Invisibly - Autonomous Endpoint Security");
    println!("📡 Detects 38 signals - Auto-repairs - Integrity Score");
    println!("");

    let chain_valid = timeline::verify_chain_on_startup();
    if !chain_valid {
        println!("🔴 CRITICAL: Timeline chain verification FAILED!");
        println!("   Timeline may have been tampered with.");
        trust::deduct_trust("Timeline chain verification failed", 30);
    }

    if !check_self_integrity() {
        println!("🔴 CRITICAL: Self-integrity check failed!");
        println!("   The daemon executable has been modified since last run.");
        println!("   This may indicate tampering or an unauthorized update.");
        println!("   ⛔ Auto-repair disabled. Manual verification required.");
        log_self_integrity_failure();
        trust::deduct_trust("Self-integrity check failed - executable modified", 40);
    }

    let baseline = get_baseline();
    let home_ssid = config::load_home_ssid().unwrap_or_else(|| "Unknown".into());

    println!("🔌 Starting API server on port 12790...");
    
    let api_handle = std::thread::spawn(|| {
        if let Err(e) = server::run() {
            eprintln!("❌ API server error: {}", e);
            std::process::exit(1);
        }
    });

    let _supervisor_handle = std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(10));
            if api_handle.is_finished() {
                eprintln!("❌ API server thread died unexpectedly!");
                eprintln!("   Attempting to restart...");
                std::process::exit(1);
            }
        }
    });

    std::thread::spawn(|| {
        loop {
            std::thread::sleep(Duration::from_secs(30));
            let self_ok = check_self_integrity();
            let baseline_ok = baseline::verify_baseline().valid;
            if !self_ok || !baseline_ok {
                println!("🚨 30s heartbeat: integrity check FAILED (self: {}, baseline: {})", self_ok, baseline_ok);
                if !self_ok {
                    log_self_integrity_failure();
                }
                if !baseline_ok {
                    trust::deduct_trust("Heartbeat: baseline tampered", 25);
                }
                let is_lockdown = repair::is_ghost_active();
                let report = integrity::calculate(&[], is_lockdown, false);
                server::set_integrity_report(report);
            }

            let ghost_auto_flag = format!("{}\\ghost_auto.flag", DATA_DIR);
            let ghost_toggle_time = format!("{}\\ghost_last_toggle.txt", DATA_DIR);
            let is_public = detect::get_wifi_profile_status() == "PUBLIC";
            let ghost_active = repair::is_ghost_active();
            let ghost_was_auto = std::path::Path::new(&ghost_auto_flag).exists();

            let mut can_toggle = true;
            if let Ok(last_toggle_str) = fs::read_to_string(&ghost_toggle_time) {
                if let Ok(last_toggle) = last_toggle_str.trim().parse::<u64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs();
                    if now - last_toggle < 60 {
                        can_toggle = false;
                    }
                }
            }

            if can_toggle {
                if is_public && !ghost_active {
                    println!("🔵 Public WiFi detected - auto-enabling Ghost Mode (inbound hardening)");
                    if repair::ghost_mode_on() {
                        let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
                        let _ = fs::write(&ghost_flag, "1");
                        let _ = fs::write(&ghost_auto_flag, "1");
                        let _ = fs::write(&ghost_toggle_time, 
                            &std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or(Duration::from_secs(0))
                                .as_secs()
                                .to_string()
                        );
                        server::set_ghost_active(true);
                        server::set_trust_state("Ghost");
                    }
                } else if !is_public && ghost_active && ghost_was_auto {
                    println!("🔵 Back on a trusted network - auto-disabling Ghost Mode");
                    if repair::ghost_mode_off() {
                        let ghost_flag = format!("{}\\ghost.flag", DATA_DIR);
                        let _ = fs::remove_file(&ghost_flag);
                        let _ = fs::remove_file(&ghost_auto_flag);
                        let _ = fs::write(&ghost_toggle_time, 
                            &std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or(Duration::from_secs(0))
                                .as_secs()
                                .to_string()
                        );
                        server::set_ghost_active(false);
                        server::set_trust_state("Trusted");
                    }
                }
            }
        }
    });

    std::thread::sleep(Duration::from_secs(2));

    println!("✅ API server started - Dashboard: http://127.0.0.1:12790");
    println!("");

    println!("🔍 [1/6] Collecting state...");
    let current = detect::collect_state();
    println!("✅ [1/6] State collected");

    println!("🔍 [2/6] Detecting changes...");
    let issues = behavior::detect_all_changes(&baseline, &current);
    println!("✅ [2/6] Changes detected: {}", issues.len());

    println!("🔍 [3/6] Verifying baseline...");
    let is_baseline_valid = baseline::verify_baseline().valid;
    println!("✅ [3/6] Baseline valid: {}", is_baseline_valid);

    println!("🔍 [4/6] Checking lockdown...");
    let is_lockdown = repair::is_ghost_active();
    println!("✅ [4/6] Lockdown: {}", is_lockdown);

    println!("🔍 [5/6] Calculating integrity...");
    let issues_for_score: Vec<(String, String)> = issues.iter()
        .map(|(cat, details, _)| (cat.clone(), details.clone()))
        .collect();
    let report = integrity::calculate(&issues_for_score, is_lockdown, is_baseline_valid);
    server::set_integrity_report(report.clone());
    server::set_trust_level(trust::get_trust_score());
    println!("📊 [5/6] Initial Integrity Score: {} | Trust Level: {}", report.score, server::get_trust_level());
    println!("");

    println!("✅ Invisibly running - Press Ctrl+C to stop");
    println!("");

    // ============================================
    // MAIN MONITORING LOOP — WITH AUTO-REPAIR
    // ============================================
    loop {
        while !server::is_ts2_enabled() {
            std::thread::sleep(Duration::from_millis(100));
        }

        let mut slept = 0;
        let total_sleep = Duration::from_secs(300);
        while slept < total_sleep.as_secs() {
            if !server::is_ts2_enabled() {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
            slept += 1;
        }

        if !server::is_ts2_enabled() {
            continue;
        }

        let baseline = get_baseline();
        let current = detect::collect_state();

        let baseline_status = baseline::verify_baseline();
        let is_baseline_valid = baseline_status.valid;

        if !is_baseline_valid {
            println!("❌ Baseline integrity check failed!");
            trust::deduct_trust("Baseline integrity check failed", 25);
            let report = integrity::calculate(&[], false, false);
            server::set_integrity_report(report.clone());
            server::set_trust_level(trust::get_trust_score());
            continue;
        }

        let issues = behavior::detect_all_changes(&baseline, &current);

        // ============================================
        // AUTO-REPAIR: Process ALL changes
        // ============================================
        if !issues.is_empty() {
            println!("⚠️ Found {} changes!", issues.len());

            for (category, details, action_type) in &issues {
                match action_type.as_str() {
                    "automatic" => {
                        let success = match category.as_str() {
                            "hosts" => repair::restore_hosts(),
                            "proxy" => repair::remove_proxy(),
                            "defender" => repair::enable_defender(),
                            "uac" => repair::enable_uac(),
                            "wu" => repair::enable_windows_update(),
                            "sr" => repair::enable_system_restore(),
                            "smartscreen" => repair::enable_smart_screen(),
                            "ipv6" => repair::enable_ipv6(),
                            "wifi_profile" => repair::set_wifi_private(),
                            "trojan_source" => repair::clean_unicode_bidi(),
                            // NEW: Auto-repair quarantine categories
                            "startup" => { repair::quarantine_startup(); true }
                            "fakeext" => { repair::delete_fake_files(); true }
                            "bt" => { repair::force_disable_bt_devices(); true }
                            "hid" => { repair::force_disable_hid_devices(); true }
                            "bruteforce" => { repair::block_bruteforce_ips(); true }
                            "adapter" => { repair::force_disable_unknown_adapters(); true }
                            _ => true,
                        };
                        if !success {
                            println!("❌ Auto-repair failed for: {}", category);
                        }
                    }
                    "confirm" => {
                        println!("⏳ Confirm required for: {} - {}", category, details);
                        let _ = timeline::add_entry(
                            category,
                            "pending_approval",
                            details,
                            "awaiting user confirmation",
                            timeline::RepairResult::AwaitingApproval
                        );
                    }
                    "alert" => {
                        println!("🔔 Alert: {} - {}", category, details);
                    }
                    "manual" => {
                        println!("⚠️ Manual intervention required for: {} - {}", category, details);
                    }
                    _ => {
                        println!("⚠️ Unknown action_type '{}' for category: {}", action_type, category);
                    }
                }
            }

            // ============================================
            // AUTO-RESET BASELINE AFTER REPAIRS
            // ============================================
            let current_after_repair = detect::collect_state();
            let issues_after = behavior::detect_all_changes(&baseline, &current_after_repair);

            if issues_after.is_empty() {
                println!("✅ Auto-repair successful, resetting baseline to reflect clean state...");
                let state = detect::collect_state();
                let _ = baseline::create_baseline(&state);
                let mut guard = BASELINE.lock().unwrap();
                *guard = Some(state);
            } else {
                println!("⚠️ Issues remain after auto-repair: {}", issues_after.len());
                for (cat, _, _) in &issues_after {
                    println!("   - {}", cat);
                }
            }
        }

        // ============================================
        // RECALCULATE SCORE
        // ============================================
        let current_after_full = detect::collect_state();
        let issues_final = behavior::detect_all_changes(&baseline, &current_after_full);
        let is_lockdown = repair::is_ghost_active();
        let issues_for_score_final: Vec<(String, String)> = issues_final.iter()
            .map(|(cat, details, _)| (cat.clone(), details.clone()))
            .collect();
        let report = integrity::calculate(&issues_for_score_final, is_lockdown, is_baseline_valid);
        server::set_integrity_report(report.clone());

        if !issues_final.is_empty() {
            for (category, _, _) in &issues_final {
                match category.as_str() {
                    "firewall" | "defender" | "uac" | "wu" | "sr" | "smartscreen" | "secureboot" | "bitlocker" | "credguard" => {
                        trust::deduct_trust(&format!("{} compromised", category), 10);
                    }
                    "dns" | "hosts" | "proxy" | "startup" | "dhcp" | "rdp" => {
                        trust::deduct_trust(&format!("{} changed", category), 5);
                    }
                    _ => {}
                }
            }
        } else {
            trust::recover_trust(2);
        }

        server::set_trust_level(trust::get_trust_score());

        for (category, details, action_type) in &issues {
            if action_type == "confirm" || action_type == "alert" || action_type == "manual" {
                let _ = timeline::add_entry(
                    category,
                    action_type,
                    details,
                    "detected",
                    timeline::RepairResult::AwaitingApproval
                );
            }
        }

        let wifi = detect::get_wifi();
        if wifi != "Unknown" && wifi != home_ssid {
            println!("🔵 WiFi changed: {} (home: {})", wifi, home_ssid);
        }

        let report = server::get_integrity_report().unwrap_or(report);
        let trust_level = server::get_trust_level();
        println!("📊 Integrity Score: {} | Trust Level: {}", report.score, trust_level);
    }
}

// ============================================
// HELPERS
// ============================================

fn is_elevated() -> bool {
    let output = Command::new("whoami")
        .args(["/priv"])
        .output();

    if let Ok(output) = output {
        if let Ok(text) = String::from_utf8(output.stdout) {
            return text.contains("SeIncreaseQuotaPrivilege") ||
                   text.contains("SeSecurityPrivilege") ||
                   text.contains("SeTakeOwnershipPrivilege");
        }
    }
    false
}

fn check_self_integrity() -> bool {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return true,
    };
    let data = fs::read(&exe_path).unwrap_or_default();
    let current_hash = crypto::hmac_sign(&data);
    let stored_path = format!("{}\\agent.hash", DATA_DIR);

    if let Ok(stored_hash) = fs::read_to_string(&stored_path) {
        let result = stored_hash.trim() == current_hash;
        if !result {
            log_self_integrity_failure();
        }
        result
    } else {
        let _ = fs::write(&stored_path, &current_hash);
        true
    }
}

fn log_self_integrity_failure() {
    let log_path = format!("{}\\self_integrity.log", DATA_DIR);
    let entry = format!(
        "{}|SELF_INTEGRITY_FAILED|Daemon executable modified\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
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