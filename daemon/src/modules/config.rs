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

// FIX #13: Log icacls failures, don't silently ignore
pub fn ensure_data_dir() -> std::io::Result<()> {
    fs::create_dir_all(DATA_DIR)?;
    fs::create_dir_all(format!("{}\\quarantine", DATA_DIR))?;
    fs::create_dir_all(format!("{}\\canary", DATA_DIR))?;
    fs::create_dir_all(format!("{}\\backups", DATA_DIR))?;
    
    // === ACL HARDENING: Restrict access to SYSTEM and Administrators ===
    #[cfg(windows)]
    {
        let result = std::process::Command::new("icacls")
            .args([DATA_DIR, "/inheritance:r", "/grant", "SYSTEM:F", "/grant", "Administrators:F", "/remove", "Users", "/remove", "Everyone"])
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
fn log_acl_failure(msg: &str) {
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

