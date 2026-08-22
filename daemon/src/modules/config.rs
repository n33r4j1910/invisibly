// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Configuration Module - Monitor-Only
use std::fs;
use chrono::Local;

const DATA_DIR: &str = "C:\\ProgramData\\Invisibly";

pub fn load_home_ssid() -> Option<String> {
    let path = format!("{}\\home.ssid", DATA_DIR);
    if let Ok(ssid) = fs::read_to_string(&path) {
        let trimmed = ssid.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

pub fn save_home_ssid(ssid: &str) {
    let path = format!("{}\\home.ssid", DATA_DIR);
    let _ = fs::write(&path, ssid);
}

// ============================================
// WATCHED FOLDERS (real-time ransomware detection)
// ============================================

/// Default folders picked by where ransomware actually targets, not an
/// exhaustive list - Documents/Desktop/Pictures/Downloads. Deliberately
/// short: watching more folders (or a whole drive) means more background
/// Windows/app noise and a higher chance of the OS dropping change
/// notifications under load, which is worse than not watching at all.
fn default_watched_folders() -> Vec<String> {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    if home.is_empty() {
        return Vec::new();
    }
    ["Documents", "Desktop", "Pictures", "Downloads"]
        .iter()
        .map(|d| format!("{}\\{}", home, d))
        .filter(|p| std::path::Path::new(p).exists())
        .collect()
}

pub fn load_watched_folders() -> Vec<String> {
    let path = format!("{}\\watched_folders.txt", DATA_DIR);
    if let Ok(data) = fs::read_to_string(&path) {
        let folders: Vec<String> = data.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        if !folders.is_empty() {
            return folders;
        }
    }
    // First run: seed with the defaults and persist them, so the list shown
    // in the dashboard matches what's actually being watched.
    let defaults = default_watched_folders();
    save_watched_folders(&defaults);
    defaults
}

fn save_watched_folders(folders: &[String]) {
    let path = format!("{}\\watched_folders.txt", DATA_DIR);
    let _ = fs::write(&path, folders.join("\n"));
}

// FIX #13: Log icacls failures, don't silently ignore
pub fn ensure_data_dir() -> std::io::Result<()> {
    fs::create_dir_all(DATA_DIR)?;
    fs::create_dir_all(format!("{}\\quarantine", DATA_DIR))?;
    fs::create_dir_all(format!("{}\\canary", DATA_DIR))?;
    fs::create_dir_all(format!("{}\\backups", DATA_DIR))?;
    
    // === ACL HARDENING: Restrict access to SYSTEM, Administrators, and the
    // current user. The app runs unelevated as a normal, expected state
    // (monitor-only mode before the Scheduled Task takes over) - without an
    // explicit grant for the current user, that user's own unelevated runs
    // can no longer read files (like the master key) that a prior elevated
    // run wrote, silently breaking self-integrity/baseline verification. ===
    #[cfg(windows)]
    {
        let username = std::env::var("USERNAME").unwrap_or_default();
        // /T recurses into existing files/subfolders - without it, only the
        // directory's own ACL changes and files created by an earlier icacls
        // run (which have their own explicit, non-inherited ACL) are untouched.
        let mut args: Vec<String> = vec![
            DATA_DIR.to_string(), "/T".to_string(), "/inheritance:r".to_string(),
            "/grant".to_string(), "SYSTEM:F".to_string(),
            "/grant".to_string(), "Administrators:F".to_string(),
        ];
        if !username.is_empty() {
            args.push("/grant".to_string());
            args.push(format!("{}:F", username));
        }
        args.push("/remove".to_string());
        args.push("Users".to_string());
        args.push("/remove".to_string());
        args.push("Everyone".to_string());

        let result = std::process::Command::new("icacls")
            .args(&args)
            .status();
        
        match result {
            Ok(status) => {
                if status.success() {
                    println!("✅ Data directory ACL hardening applied successfully");
                } else {
                    let msg = format!("⚠️ Data directory ACL hardening failed with exit code: {}", status.code().unwrap_or(-1));
                    println!("{}", msg);
                    // Log the failure to file
                    log_acl_failure(&msg);
                }
            }
            Err(e) => {
                let msg = format!("⚠️ Failed to run icacls: {}", e);
                println!("{}", msg);
                log_acl_failure(&msg);
            }
        }
    }
    
    Ok(())
}

// FIX #13: Log ACL failures to file
pub fn log_acl_failure(msg: &str) {
    let log_path = format!("{}\\acl_hardening.log", DATA_DIR);
    let entry = format!(
        "{}|ACL_FAILURE|{}\n",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        msg
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

