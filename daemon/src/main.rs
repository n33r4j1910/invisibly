#![windows_subsystem = "windows"]

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
use modules::watcher;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";
const SCHEDULED_TASK_NAME: &str = "InvisiblyDaemon";
const CREATE_NO_WINDOW: u32 = 0x08000000;

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
// SCHEDULED TASK MANAGEMENT
// ============================================

fn ensure_scheduled_task() -> bool {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let exe_str = exe_path.to_string_lossy();

    // Check if task already exists with correct path
    let check_output = Command::new("schtasks")
        .args(["/query", "/tn", SCHEDULED_TASK_NAME, "/fo", "csv", "/v"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let task_exists = if let Ok(output) = &check_output {
        String::from_utf8_lossy(&output.stdout).contains(SCHEDULED_TASK_NAME)
    } else {
        false
    };

    let task_path_matches = if task_exists {
        if let Ok(output) = Command::new("schtasks")
            .args(["/query", "/tn", SCHEDULED_TASK_NAME, "/fo", "csv", "/v"])
            .creation_flags(CREATE_NO_WINDOW)
            .output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains(exe_str.as_ref()) || stdout.contains("invisibly-daemon.exe")
        } else {
            false
        }
    } else {
        false
    };

    if task_exists && task_path_matches {
        println!("✅ Scheduled Task already exists with correct path");
        return true;
    }

    println!("🔄 Creating/updating Scheduled Task with current path: {}", exe_str);

    if task_exists {
        let _ = Command::new("schtasks")
            .args(["/delete", "/tn", SCHEDULED_TASK_NAME, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    let create_cmd = format!(
        "schtasks /create /tn \"{}\" /tr \"{}\" /sc onlogon /rl highest /f",
        SCHEDULED_TASK_NAME, exe_str
    );

    let output = Command::new("cmd")
        .args(["/c", &create_cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    match output {
        Ok(o) if o.status.success() => {
            println!("✅ Scheduled Task created successfully");
            true
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            println!("❌ Failed to create Scheduled Task: {}", stderr);
            false
        }
        Err(e) => {
            println!("❌ Failed to create Scheduled Task: {}", e);
            false
        }
    }
}

// ============================================
// MAIN - Entry point (No service dispatcher)
// ============================================

fn main() {
    run_daemon();
}

// ============================================
// AUTO-FIX STARTUP ISSUES
// ============================================

fn auto_fix_startup_issues() {
    let data_dir = Path::new(DATA_DIR);
    
    // 1. Fix self-integrity hash
    let hash_path = data_dir.join("agent.hash");
    if hash_path.exists() {
        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return,
        };
        let data = fs::read(&exe_path).unwrap_or_default();
        let current_hash = crypto::hmac_sign(&data);
        if let Ok(stored_hash) = fs::read_to_string(&hash_path) {
            if stored_hash.trim() != current_hash {
                println!("🔄 Auto-fix: Updating self-integrity hash...");
                let _ = fs::write(&hash_path, &current_hash);
            }
        }
    }
    
    // 2. Fix timeline chain
    let timeline_path = data_dir.join("timeline.jsonl");
    if timeline_path.exists() {
        if !timeline::verify_chain() {
            println!("🔄 Auto-fix: Resetting corrupted timeline...");
            let _ = fs::remove_file(&timeline_path);
        }
    }

    // 3. Prune timeline to prevent unbounded growth
    timeline::prune_old_entries();
}

// ============================================
// START TRAY AUTOMATICALLY
// ============================================

fn start_tray_if_not_running() {
    let output = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq invisibly-tray.exe"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(output) = output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("invisibly-tray.exe") {
            println!("✅ Tray is already running");
            return;
        }
    }

    let tray_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|parent| parent.join("invisibly-tray.exe")))
        .and_then(|p| if p.exists() { Some(p) } else { None });

    if let Some(tray_path) = tray_path {
        match std::process::Command::new(tray_path)
            .creation_flags(0x08000000)
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
    start_tray_if_not_running();
    auto_fix_startup_issues();

    let is_elevated_now = is_elevated();
    server::set_elevated(is_elevated_now);
    if !is_elevated_now {
        println!("⚠️ Running unelevated. Attempting to create Scheduled Task for elevation...");
        if ensure_scheduled_task() {
            println!("✅ Scheduled Task created. Daemon will run elevated on next login.");
            println!("💡 For now, running in monitor-only mode.");
            println!("   Auto-repair will work after next login or restart.");
        } else {
            println!("⚠️ Could not create Scheduled Task. Running in monitor-only mode.");
        }
    } else {
        println!("✅ Running with elevated privileges.");
        ensure_scheduled_task();
    }

    if let Err(e) = config::ensure_data_dir() {
        eprintln!("Failed to create data dir: {}", e);
        std::process::exit(1);
    }

    watcher::start_watching(config::load_watched_folders());

    println!("🛡️ Invisibly - Autonomous Endpoint Security");
    println!("📡 Detects 35 signals - Auto-repairs - Integrity Score - Real-time ransomware watch");
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
        server::set_tamper_detected(true);
    } else {
        server::set_tamper_detected(false);
    }

    // FIX: Start the API server BEFORE the (potentially slow, first-run)
    // baseline collection below - collect_state() shells out to 30+ PowerShell
    // calls and can take longer than the tray's failure threshold, so binding
    // the port first stops the tray from thinking the daemon is dead and
    // launching a duplicate instance while the real one is still starting.
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

            // AUTO-RECOVERY: re-create the Scheduled Task if it was deleted or
            // disabled mid-session, not just at startup. ensure_scheduled_task()
            // already no-ops quickly when the task is present and correct.
            ensure_scheduled_task();

            let self_ok = check_self_integrity();
            server::set_tamper_detected(!self_ok);
            let baseline_status_hb = baseline::verify_baseline();
            let mut baseline_ok = baseline_status_hb.valid;

            // AUTO-RECOVERY: same criteria as the main loop - don't drain trust
            // for something that's about to self-heal anyway. Without this, this
            // independent 30s timer can catch the same transient invalid window
            // the main loop is already fixing and deduct trust for nothing.
            if !baseline_ok && baseline_status_hb.exists && self_ok && crypto::key_read_healthy() {
                println!("🔧 30s heartbeat: baseline invalid but key healthy and executable untampered - regenerating instead of deducting trust");
                let state = detect::collect_state();
                if baseline::create_baseline(&state).is_ok() {
                    let mut guard = BASELINE.lock().unwrap();
                    *guard = Some(state);
                    baseline_ok = true;
                }
            }

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

    // NIGHTLY CACHE PRUNE: timeline pruning previously only ran once at daemon
    // startup, so a long-running session (days between restarts) let the
    // timeline log grow unbounded until the next restart. Poll the clock and
    // fire once when it crosses 23:59 local time each day.
    std::thread::spawn(|| {
        use chrono::Timelike;
        let mut last_pruned_date = chrono::Local::now().date_naive();
        loop {
            std::thread::sleep(Duration::from_secs(60));
            let now = chrono::Local::now();
            let today = now.date_naive();
            if today != last_pruned_date && now.hour() == 23 && now.minute() >= 59 {
                println!("🔄 Nightly cache prune (23:59) triggered");
                timeline::prune_old_entries();
                last_pruned_date = today;
            }
        }
    });

    std::thread::sleep(Duration::from_secs(2));

    println!("✅ API server started - Dashboard: http://127.0.0.1:12790");
    println!("");

    let baseline = get_baseline();
    let home_ssid = config::load_home_ssid().unwrap_or_else(|| "Unknown".into());

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
    // MAIN MONITORING LOOP
    // ============================================
    loop {
        while !server::is_ts2_enabled() {
            std::thread::sleep(Duration::from_millis(100));
        }

        let mut slept = 0;
        let total_sleep = Duration::from_secs(30);
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

        let mut baseline = get_baseline();
        let current = detect::collect_state();

        let baseline_status = baseline::verify_baseline();
        let is_baseline_valid = baseline_status.valid;

        if !is_baseline_valid {
            // AUTO-RECOVERY: an invalid baseline usually means real tampering,
            // but if the master key is genuinely readable AND the executable
            // itself is untampered, this is far more likely an infrastructure
            // hiccup (e.g. a stale signature from a temporary key/ACL issue)
            // than an attack - regenerate instead of draining trust forever.
            if baseline_status.exists && crypto::key_read_healthy() && check_self_integrity() {
                println!("🔧 Auto-recovery: baseline invalid but key is healthy and executable is untampered - regenerating baseline");
                let state = detect::collect_state();
                if baseline::create_baseline(&state).is_ok() {
                    let mut guard = BASELINE.lock().unwrap();
                    *guard = Some(state);
                    drop(guard);
                    // Refresh the served report immediately instead of leaving the
                    // stale "Invalid" report up for another full ~30s cycle.
                    let is_lockdown = repair::is_ghost_active();
                    let report = integrity::calculate(&[], is_lockdown, true);
                    server::set_integrity_report(report);
                    continue;
                }
            }
            println!("❌ Baseline integrity check failed!");
            trust::deduct_trust("Baseline integrity check failed", 25);
            let report = integrity::calculate(&[], false, false);
            server::set_integrity_report(report.clone());
            server::set_trust_level(trust::get_trust_score());
            continue;
        }

        let issues = behavior::detect_all_changes(&baseline, &current);

        if !issues.is_empty() {
            println!("⚠️ Found {} changes!", issues.len());
            let mut baseline_synced = false;

            for (category, details, action_type) in &issues {
                match action_type.as_str() {
                    "automatic" => {
                        let success = if !is_elevated_now {
                            println!("⚠️ Skipping {} repair - not elevated", category);
                            true
                        } else {
                            match category.as_str() {
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
                                "rdp" => repair::disable_rdp(),
                                "startup" => { repair::quarantine_startup(); true }
                                "fakeext" => { repair::delete_fake_files(); true }
                                "bt" => { repair::force_disable_bt_devices(); true }
                                "hid" => { repair::force_disable_hid_devices(); true }
                                "bruteforce" => { repair::block_bruteforce_ips(); true }
                                "adapter" => { repair::force_disable_unknown_adapters(); true }
                                // No revert capability for tasks/services yet - accept
                                // current state as the new baseline instead of lying
                                // about a repair that never happened.
                                "tasks" => {
                                    baseline.scheduled_tasks = current.scheduled_tasks.clone();
                                    baseline_synced = true;
                                    true
                                }
                                "services" => {
                                    baseline.services_list = current.services_list.clone();
                                    baseline_synced = true;
                                    true
                                }
                                _ => true,
                            }
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

            if baseline_synced {
                let _ = baseline::create_baseline(&baseline);
                let mut guard = BASELINE.lock().unwrap();
                *guard = Some(baseline.clone());
            }

            let current_after_repair = detect::collect_state();
            let issues_after = behavior::detect_all_changes(&baseline, &current_after_repair);

            if issues_after.is_empty() {
                println!("✅ Auto-repair successful, resetting baseline to reflect clean state...");
                let state = detect::collect_state();
                let _ = baseline::create_baseline(&state);
                let mut guard = BASELINE.lock().unwrap();
                *guard = Some(state);
                // FIX: Use tiered recovery, not manual_verify
                trust::recover_trust(5);
                server::set_trust_level(trust::get_trust_score());
            } else {
                println!("⚠️ Issues remain after auto-repair: {}", issues_after.len());
                for (cat, _, _) in &issues_after {
                    println!("   - {}", cat);
                }
            }
        }

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

// FIX: Reliable elevation check using Windows API
fn is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::Security::TokenElevation;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let process = unsafe { GetCurrentProcess() };
    let mut token_handle = HANDLE::default();

    let token_result = unsafe {
        OpenProcessToken(
            process,
            TOKEN_QUERY,
            &mut token_handle,
        )
    };

    if token_result.is_err() || token_handle.is_invalid() {
        return false;
    }

    let mut elevation: windows::Win32::Security::TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut return_length = 0;

    let info_result = unsafe {
        windows::Win32::Security::GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<windows::Win32::Security::TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )
    };

    let is_elevated = info_result.is_ok() && elevation.TokenIsElevated != 0;

    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(token_handle);
    }

    is_elevated
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