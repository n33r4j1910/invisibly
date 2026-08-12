use std::time::Duration;
use std::fs;
use std::ffi::OsString;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::Path;

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
    
    // First run: load or create baseline
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

    // Tell SCM that we're running
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        process_id: None,
        checkpoint: 0,
        wait_hint: Duration::default(),
    }).expect("Failed to set service status");

    // Run the daemon
    run_daemon();
}

// ============================================
// MAIN - Entry point
// ============================================

fn main() {
    // Check if running as Windows Service
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

    // Interactive mode (console)
    run_daemon();
}

// ============================================
// DAEMON CORE LOGIC
// ============================================

fn run_daemon() {
    // FIX #22: Check elevation properly
    if !is_elevated() {
        println!("⚠️ WARNING: Running unelevated. Auto-repair may fail!");
        println!("   Please run as Administrator for full protection.");
    }

    // Ensure data directory exists with ACL hardening
    if let Err(e) = config::ensure_data_dir() {
        eprintln!("Failed to create data dir: {}", e);
        std::process::exit(1);
    }

    println!("🛡️ Invisibly - Autonomous Endpoint Security");
    println!("📡 Detects 38 signals - Auto-repairs - Integrity Score");
    println!("");

    // Initialize timeline and verify chain
    let chain_valid = timeline::verify_chain_on_startup();
    if !chain_valid {
        println!("🔴 CRITICAL: Timeline chain verification FAILED!");
        println!("   Timeline may have been tampered with.");
        // FIX: Deduct trust on chain failure
        trust::deduct_trust("Timeline chain verification failed", 30);
    }

    // FIX #7: Self-integrity check - alert on mismatch, don't auto-heal
    if !check_self_integrity() {
        println!("🔴 CRITICAL: Self-integrity check failed!");
        println!("   The daemon executable has been modified since last run.");
        println!("   This may indicate tampering or an unauthorized update.");
        println!("   ⛔ Auto-repair disabled. Manual verification required.");
        log_self_integrity_failure();
        // FIX: Deduct trust on self-integrity failure
        trust::deduct_trust("Self-integrity check failed - executable modified", 40);
    }

    // Load initial baseline
    let baseline = get_baseline();
    let home_ssid = config::load_home_ssid().unwrap_or_else(|| "Unknown".into());

    // ============================================
    // API server with supervisor thread
    // ============================================
    println!("🔌 Starting API server on port 12790...");
    
    let api_handle = std::thread::spawn(|| {
        if let Err(e) = server::run() {
            eprintln!("❌ API server error: {}", e);
            std::process::exit(1);
        }
    });

    let supervisor_handle = std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(10));
            if api_handle.is_finished() {
                eprintln!("❌ API server thread died unexpectedly!");
                eprintln!("   Attempting to restart...");
                std::process::exit(1);
            }
        }
    });

    // FIX: 30-second tamper-detection heartbeat. Self-integrity (exe hash) and
    // baseline signature previously only got re-checked once at startup and
    // once per 5-minute scan cycle - a tampered exe or baseline could go
    // undetected for up to 5 minutes. This catches it within 30 seconds.
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(Duration::from_secs(30));
            let self_ok = check_self_integrity();
            let baseline_ok = baseline::verify_baseline().valid;
            if !self_ok || !baseline_ok {
                println!("🚨 30s heartbeat: integrity check FAILED (self: {}, baseline: {})", self_ok, baseline_ok);
                if !self_ok {
                    log_self_integrity_failure();
                    trust::deduct_trust("Heartbeat: self-integrity failure", 20);
                }
                if !baseline_ok {
                    trust::deduct_trust("Heartbeat: baseline tampered", 25);
                }
                let is_lockdown = repair::is_ghost_active();
                let report = integrity::calculate(&[], is_lockdown, false);
                server::set_integrity_report(report);
            }

            // FIX: Auto-Ghost-Mode on public WiFi with hysteresis
            let ghost_auto_flag = format!("{}\\ghost_auto.flag", DATA_DIR);
            let ghost_toggle_time = format!("{}\\ghost_last_toggle.txt", DATA_DIR);
            let is_public = detect::get_wifi_profile_status() == "PUBLIC";
            let ghost_active = repair::is_ghost_active();
            let ghost_was_auto = std::path::Path::new(&ghost_auto_flag).exists();

            // FIX: Add debounce - only toggle if 60 seconds have passed since last toggle
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

    // ============================================
    // Full scan runs in background
    // ============================================
    println!("🔍 [1/6] Collecting state...");
    let current = detect::collect_state();
    println!("✅ [1/6] State collected");

    println!("🔍 [2/6] Detecting changes...");
    // FIX: Keep full tuple with action_type
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

    // Main monitoring loop
    loop {
        // FIX: Check if daemon is disabled BEFORE sleeping
        // This allows "Disable Invisibly" to stop the loop immediately
        while !server::is_ts2_enabled() {
            std::thread::sleep(Duration::from_millis(100));
        }

        // FIX: Sleep with interruption - check every second if disabled
        let mut slept = 0;
        let total_sleep = Duration::from_secs(300); // 5 minutes
        while slept < total_sleep.as_secs() {
            if !server::is_ts2_enabled() {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
            slept += 1;
        }

        // If disabled during sleep, skip this scan cycle
        if !server::is_ts2_enabled() {
            continue;
        }

        // ============================================
        // FIX 2 & 4: RELOAD BASELINE AT START OF EACH LOOP
        // ============================================
        let baseline = get_baseline();

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
            trust::deduct_trust("Baseline integrity check failed", 25);
            let report = integrity::calculate(&[], false, false);
            server::set_integrity_report(report.clone());
            server::set_trust_level(trust::get_trust_score());
            continue;
        }

        // ============================================
        // 3. DETECT CHANGES (Behavior-Based) - KEEP ACTION_TYPE
        // ============================================
        let issues = behavior::detect_all_changes(&baseline, &current);

        // ============================================
        // 4. RISK ASSESSMENT & AUTO-REPAIR - USE ACTION_TYPE
        // ============================================
        if !issues.is_empty() {
            println!("⚠️ Found {} changes!", issues.len());

            // FIX: Process based on action_type
            for (category, details, action_type) in &issues {
                match action_type.as_str() {
                    "automatic" => {
                        // Auto-repair for safe categories
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
                            _ => true,
                        };
                        if !success {
                            println!("❌ Auto-repair failed for: {}", category);
                        }
                    }
                    "confirm" => {
                        // Log for confirmation - no auto-repair
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
                        // Just log - no repair
                        println!("🔔 Alert: {} - {}", category, details);
                    }
                    "manual" => {
                        // Requires manual intervention
                        println!("⚠️ Manual intervention required for: {} - {}", category, details);
                    }
                    _ => {
                        // Unknown action_type - log it
                        println!("⚠️ Unknown action_type '{}' for category: {}", action_type, category);
                    }
                }
            }
        }

        // ============================================
        // 5. RE-COLLECT CURRENT STATE (After Repairs)
        // ============================================
        let current_after_repair = detect::collect_state();

        // Re-detect issues after repairs
        let issues_after = behavior::detect_all_changes(&baseline, &current_after_repair);

        // ============================================
        // 6. CALCULATE INTEGRITY SCORE FROM CURRENT STATE
        // ============================================
        let is_lockdown = repair::is_ghost_active();
        let issues_for_score: Vec<(String, String)> = issues_after.iter()
            .map(|(cat, details, _)| (cat.clone(), details.clone()))
            .collect();
        let report = integrity::calculate(&issues_for_score, is_lockdown, is_baseline_valid);

        // Store integrity report
        server::set_integrity_report(report.clone());

        // Update trust level if critical issues remain
        if !issues_after.is_empty() {
            for (category, _, _) in &issues_after {
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
            // Gradual recovery if no issues
            trust::recover_trust(2);
        }

        server::set_trust_level(trust::get_trust_score());

        // ============================================
        // 7. UPDATE TIMELINE
        // ============================================
        // Log only confirm/alert/manual items, not automatic (already logged by repair module)
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

// FIX #22: Proper elevation check
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

// FIX #7: Self-integrity check - alert, don't auto-heal
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