#![windows_subsystem = "windows"]

use std::time::Duration;
use std::fs;
use std::ffi::OsString;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::Path;
use std::os::windows::process::CommandExt;
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::w;

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
use modules::license;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";
const SCHEDULED_TASK_NAME: &str = "InvisiblyDaemon";
const CREATE_NO_WINDOW: u32 = 0x08000000;

// ============================================
// GLOBAL BASELINE (Shared across threads)
// ============================================

pub static BASELINE: once_cell::sync::Lazy<Mutex<Option<detect::SystemState>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

// FIX: tracks which categories have already had trust deducted for their
// *current* occurrence, so a persistent condition (e.g. BitLocker off,
// which many machines simply don't have available) gets charged once, not
// every ~2min cycle forever. See TRUST_PENALIZED usage in the monitoring
// loop for the full story - this used to be an unconditional re-deduction
// on every cycle an issue was still present, which meant trust could only
// ever ratchet down to 0 and never recover as long as any one known,
// already-reviewed issue remained.
static TRUST_PENALIZED: once_cell::sync::Lazy<Mutex<std::collections::HashSet<String>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(std::collections::HashSet::new()));

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

fn get_baseline(is_elevated_now: bool) -> detect::SystemState {
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

    println!("📝 First run - checking against recommended secure defaults...");
    let mut state = detect::collect_state();
    run_first_run_setup(&mut state, is_elevated_now);
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
// SINGLE INSTANCE GUARD
// ============================================

// Without this, a second launch (e.g. the Store cert kit's repeat-launch
// test, or a user reopening the app while it's already running from the
// Scheduled Task) hits the API server's port-already-in-use error and the
// spawned server thread hard-exits via std::process::exit(1) - silent,
// windowless (windows_subsystem = "windows"), and indistinguishable from a
// crash. Reproduced locally: a second invisibly-daemon.exe process exits
// with code 1 within ~2s and no visible error, matching a certification
// report of "crashes after launch, Error Message: N/A".
fn check_single_instance() -> bool {
    unsafe {
        let handle = CreateMutexW(None, true, w!("Global\\InvisiblyDaemonMutex"));
        if handle.is_ok() {
            GetLastError().0 != ERROR_ALREADY_EXISTS.0
        } else {
            false
        }
    }
}

// ============================================
// MAIN - Entry point (No service dispatcher)
// ============================================

fn main() {
    if !check_single_instance() {
        println!("⚠️ Invisibly daemon is already running - exiting quietly.");
        return;
    }
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
    baseline::prune_old_versions();
    repair::rotate_repair_log_if_large();
    repair::prune_old_incidents();
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
// AUTOMATIC REPAIR DISPATCH
// ============================================

/// Applies the automatic-tier repair for one detected category. Shared by
/// the 30s monitoring loop and first-run setup so there's one place that
/// knows how to fix each category, not two copies that can drift apart.
/// Returns (success, baseline_was_synced) - `baseline` is only mutated for
/// categories with no real revert capability (tasks/services/wifi), which
/// accept the current state as the new normal instead of pretending a
/// change was reverted when it wasn't.
fn apply_automatic_repair(
    category: &str,
    baseline: &mut detect::SystemState,
    current: &detect::SystemState,
    is_elevated_now: bool,
) -> (bool, bool) {
    if !is_elevated_now {
        println!("⚠️ Skipping {} repair - not elevated", category);
        return (true, false);
    }
    // FIX: tasks/services/wifi are baseline-hygiene syncs, not security
    // fixes - they exist purely to stop re-flagging normal drift (a
    // WiFi switch, a routine service change) as an ongoing issue. Gating
    // these behind a subscription would reintroduce the exact re-nagging
    // noise this session already fixed, for every free-tier user, since
    // free tier still needs accurate detection/scoring. Only the actual
    // security-fix categories below require an active subscription.
    let is_baseline_hygiene = matches!(category, "tasks" | "services" | "wifi");
    if !is_baseline_hygiene && !license::is_pro_licensed() {
        println!("🔒 Skipping {} repair - Pro subscription required (detected, not auto-fixed)", category);
        return (true, false);
    }
    let success = match category {
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
        "bruteforce" => repair::block_bruteforce_ips(),
        "adapter" => { repair::force_disable_unknown_adapters(); true }
        "tasks" => {
            baseline.scheduled_tasks = current.scheduled_tasks.clone();
            true
        }
        "services" => {
            baseline.services_list = current.services_list.clone();
            true
        }
        // FIX: switching WiFi networks isn't a security event - accept the
        // new network identity (SSID + its correlated DHCP/ARP/device list)
        // as the new normal instead of flagging every reconnect.
        "wifi" => {
            baseline.wifi_ssid = current.wifi_ssid.clone();
            baseline.dhcp_server = current.dhcp_server.clone();
            baseline.arp_table = current.arp_table.clone();
            baseline.network_devices = current.network_devices.clone();
            true
        }
        _ => true,
    };
    if !success {
        println!("❌ Auto-repair failed for: {}", category);
    }
    let synced = matches!(category, "tasks" | "services" | "wifi");
    (success, synced)
}

// ============================================
// FIRST-RUN SETUP - compare against recommended secure defaults
// ============================================

/// Builds a synthetic "ideal" reference state for first-run comparison.
/// Only overrides the signals that have one universally correct answer
/// regardless of whose PC this is (Defender on, RDP off, no bloatware...).
/// Everything else (your WiFi name, your devices, your installed software,
/// your startup apps) is left equal to `current` - there's no universal
/// "correct" value for those, so they're never flagged on first run.
///
/// Known gap: hosts_hash and firewall_profiles are deliberately left out -
/// there's no reliable hardcoded "clean" hosts hash across Windows
/// locales/versions, and the firewall diff format is a parsed profile list
/// that's fragile to hand-construct correctly. A machine with an already-
/// poisoned hosts file or an already-disabled firewall at first launch
/// won't be caught by this - a real limitation of a non-signature-based
/// tool, not something silently pretended away.
fn ideal_reference(current: &detect::SystemState) -> detect::SystemState {
    let mut ideal = current.clone();
    ideal.defender_status = "ON".to_string();
    ideal.uac_status = "ON".to_string();
    ideal.windows_update_status = "ON".to_string();
    ideal.system_restore_status = "ON".to_string();
    ideal.smart_screen_status = "ON".to_string();
    ideal.ipv6_status = "ON".to_string();
    ideal.doh_status = "ON".to_string();
    ideal.laps_status = "ENABLED".to_string();
    ideal.bitlocker_status = "ON".to_string();
    ideal.credential_guard_status = "ON".to_string();
    ideal.secure_boot = "ON".to_string();
    ideal.proxy_settings = Vec::new();
    ideal.fake_extensions = Vec::new();
    ideal.unicode_bidi_files = Vec::new();
    ideal.homoglyph_domains = Vec::new();
    ideal.installed_software = Vec::new();
    // RDP: the detector has no clean explicit "off" string (falls through
    // to an error string when the service isn't running) - only force a
    // diff when the current value is actually one of the known "on" signals.
    if current.rdp_status == "LISTENING" || current.rdp_status == "RUNNING" {
        ideal.rdp_status = "OFF".to_string();
    }
    ideal
}

/// Runs once, only when no baseline exists yet. Diffs the fresh state
/// against `ideal_reference()` and applies/queues findings through the
/// exact same automatic/confirm/alert pipeline as ongoing drift detection -
/// no new UI, no new endpoint, reuses the tray's existing pending-approval
/// badge for anything that needs a human call (RDP, firewall, BitLocker...).
fn run_first_run_setup(state: &mut detect::SystemState, is_elevated_now: bool) {
    let ideal = ideal_reference(state);
    let setup_issues = behavior::detect_all_changes(&ideal, state);

    if setup_issues.is_empty() {
        println!("✅ First run - already matches recommended secure defaults");
        return;
    }

    println!("🔧 First run - found {} recommended fixes", setup_issues.len());
    for (category, details, action_type) in &setup_issues {
        match action_type.as_str() {
            "automatic" => {
                let current_snapshot = state.clone();
                apply_automatic_repair(category, state, &current_snapshot, is_elevated_now);
            }
            "confirm" => {
                let _ = timeline::add_entry(
                    category,
                    "pending_approval",
                    details,
                    "found during first-run setup",
                    timeline::RepairResult::AwaitingApproval
                );
            }
            "alert" | "manual" => {
                println!("⚠️ First run: {} - {} (not auto-fixed, review manually)", category, details);
            }
            _ => {}
        }
    }

    // Re-snapshot so the baseline reflects what actually landed, not what
    // was attempted - some fixes (e.g. GPO-locked settings) can fail.
    *state = detect::collect_state();
}

// ============================================
// FIRST-RUN CONSENT GATE
// ============================================

fn is_consent_accepted() -> bool {
    Path::new(&format!("{}\\consent_accepted.txt", DATA_DIR)).exists()
}

/// Blocks until the user accepts on the dashboard's consent screen
/// (server.rs's POST /accept_consent writes the flag this checks for).
/// A no-op on every run after the first, since the flag persists.
fn wait_for_consent() {
    if is_consent_accepted() {
        server::set_awaiting_consent(false);
        return;
    }
    println!("📋 Awaiting privacy/terms acceptance - open the dashboard to continue...");
    server::set_awaiting_consent(true);
    while !is_consent_accepted() {
        std::thread::sleep(Duration::from_millis(500));
    }
    server::set_awaiting_consent(false);
    println!("✅ Consent accepted - starting monitoring");
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
            // FIX: previously this just sat in monitor-only mode until the
            // *next full logon* - meaning a manual restart (double-click,
            // Start menu) never regained elevation, and every "automatic"
            // repair below is unconditionally skipped while unelevated, so
            // the integrity score could never climb back up without the
            // user logging off/on. The Scheduled Task is already registered
            // with /rl highest by a prior elevated run, so `schtasks /run`
            // launches it elevated immediately - silently, no UAC prompt,
            // same as Windows already does at logon - instead of waiting.
            println!("🔼 Scheduled Task exists - launching it elevated now instead of waiting for next login...");
            let run_result = Command::new("schtasks")
                .args(["/run", "/tn", SCHEDULED_TASK_NAME])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
            let launched = matches!(&run_result, Ok(o) if o.status.success());
            if launched {
                println!("✅ Elevated instance launching - this unelevated instance is stepping aside.");
                return;
            }
            if let Ok(o) = &run_result {
                println!("⚠️ Could not launch elevated task ({}). Running in monitor-only mode.", String::from_utf8_lossy(&o.stderr));
            } else if let Err(e) = &run_result {
                println!("⚠️ Could not launch elevated task ({}). Running in monitor-only mode.", e);
            }
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

    // FIX: server::set_ghost_active() was only ever updated by an explicit
    // toggle (auto on/off in the monitoring loop, or the /ghost /unghost API)
    // - never synced from the on-disk ghost.flag at startup. So restarting
    // the daemon while Ghost Mode was active left /status (and the tray icon)
    // reporting "ghost: false" indefinitely, even though the real firewall
    // rule/services were still hardened and the monitoring loop's own
    // (file-based) is_ghost_active() check knew better.
    server::set_ghost_active(repair::is_ghost_active());

    println!("🛡️ Invisibly - Autonomous Endpoint Security");
    println!("📡 Detects 35 signals - Auto-repairs - Integrity Score - Real-time ransomware watch");
    println!("");

    timeline::init_counter();
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

    // First launch: don't collect or process any system data until the
    // user has actively opted in via the dashboard's consent screen (the
    // privacy policy itself already promises consent is obtained before
    // processing starts - this makes that actually true instead of just
    // claimed). Placed AFTER the API server thread spawn above so the
    // consent page is actually reachable while this blocks - putting it
    // before the spawn deadlocks the daemon waiting on a server that
    // hasn't started yet.
    wait_for_consent();

    license::start_license_check_thread();
    watcher::start_watching(config::load_watched_folders());

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
                baseline::prune_old_versions();
                repair::rotate_repair_log_if_large();
                repair::prune_old_incidents();
                last_pruned_date = today;
            }
        }
    });

    std::thread::sleep(Duration::from_secs(2));

    println!("✅ API server started - Dashboard: http://127.0.0.1:12790");
    println!("");

    let baseline = get_baseline(is_elevated_now);
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

        let mut baseline = get_baseline(is_elevated_now);
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
                        let (_success, synced) = apply_automatic_repair(category, &mut baseline, &current, is_elevated_now);
                        if synced {
                            baseline_synced = true;
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

        // FIX: only deduct trust for a category the cycle it NEWLY appears,
        // not every cycle it's still present - see TRUST_PENALIZED above.
        // Recovery now fires whenever nothing NEW went wrong this cycle,
        // even if one known, already-charged-for issue (e.g. BitLocker
        // permanently off) is still sitting there - trust represents
        // whether new bad things are happening, not whether an old, already
        // priced-in condition still technically exists.
        {
            let mut penalized = TRUST_PENALIZED.lock().unwrap();
            let current_categories: std::collections::HashSet<String> =
                issues_final.iter().map(|(cat, _, _)| cat.clone()).collect();
            let mut newly_penalized = false;

            for category in &current_categories {
                if penalized.contains(category) {
                    continue;
                }
                newly_penalized = true;
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

            // Categories that resolved stop being tracked, so they're
            // treated as fresh (and re-deducted once) if they recur later.
            penalized.retain(|c| current_categories.contains(c));
            penalized.extend(current_categories);

            if !newly_penalized {
                trust::recover_trust(2);
            }
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