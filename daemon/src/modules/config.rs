// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.`n// This software is proprietary and confidential.`n//! Configuration Module - Monitor-Only
use std::fs;
use std::path::Path;

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

pub fn get_data_dir() -> String {
    DATA_DIR.to_string()
}

pub fn ensure_data_dir() -> std::io::Result<()> {
    fs::create_dir_all(DATA_DIR)?;
    fs::create_dir_all(format!("{}\\quarantine", DATA_DIR))?;
    fs::create_dir_all(format!("{}\\canary", DATA_DIR))?;
    fs::create_dir_all(format!("{}\\backups", DATA_DIR))?;
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsentRecord {
    pub action: String,
    pub timestamp: String,
    pub user: String,
    pub status: String,
    pub details: String,
}

pub fn log_consent(record: &ConsentRecord) {
    let path = format!("{}\\consent.log", DATA_DIR);
    let entry = serde_json::to_string(record).unwrap_or_default();
    let _ = fs::write(&path, entry + "\n");
}

pub fn get_consent_history() -> Vec<ConsentRecord> {
    let path = format!("{}\\consent.log", DATA_DIR);
    let mut records = Vec::new();
    if let Ok(content) = fs::read_to_string(&path) {
        for line in content.lines() {
            if let Ok(record) = serde_json::from_str(line) {
                records.push(record);
            }
        }
    }
    records
}

pub fn require_user_consent(action: &str, details: &str) -> bool {
    let record = ConsentRecord {
        action: action.to_string(),
        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        user: "SYSTEM".to_string(),
        status: "monitor-only".to_string(),
        details: details.to_string(),
    };
    log_consent(&record);
    true
}

pub fn save_baseline(state: &crate::detect::SystemState) {
    let path = format!("{}\\baseline.json", DATA_DIR);
    let json = serde_json::to_string(state).unwrap();
    let encrypted = crate::crypto::encrypt_baseline(&json);
    let _ = fs::write(&path, encrypted);
}

pub fn load_baseline() -> Option<crate::detect::SystemState> {
    let path = format!("{}\\baseline.json", DATA_DIR);
    if let Ok(encrypted) = fs::read(&path) {
        if let Ok(json) = crate::crypto::decrypt_baseline(&encrypted) {
            if let Ok(state) = serde_json::from_str(&json) {
                return Some(state);
            }
        }
    }
    None
}

pub fn backup_file(path: &str) -> bool {
    let backup_dir = format!("{}\\backups", DATA_DIR);
    let _ = fs::create_dir_all(&backup_dir);
    let filename = Path::new(path).file_name().unwrap_or_default();
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let backup_path = format!("{}\\{}_{}.backup", backup_dir, filename.to_string_lossy(), timestamp);
    match fs::copy(path, &backup_path) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn restore_from_backup(path: &str) -> bool {
    let backup_dir = format!("{}\\backups", DATA_DIR);
    if let Ok(entries) = fs::read_dir(&backup_dir) {
        let filename = Path::new(path).file_name().unwrap_or_default();
        let mut backups: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(&*filename.to_string_lossy()))
            .collect();
        backups.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
        if let Some(latest) = backups.last() {
            return fs::copy(latest.path(), path).is_ok();
        }
    }
    false
}

pub fn get_install_dir() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.to_string_lossy().to_string();
        }
    }
    "C:\\Program Files\\Invisibly".to_string()
}

pub fn cleanup_uninstall() -> bool {
    let data_dir = DATA_DIR;
    if Path::new(data_dir).exists() {
        let to_delete = ["temp", "cache", "ghost.flag", "home.ssid"];
        for item in &to_delete {
            let path = format!("{}\\{}", data_dir, item);
            if Path::new(&path).exists() {
                let _ = fs::remove_file(&path);
            }
        }
        true
    } else {
        false
    }
}

