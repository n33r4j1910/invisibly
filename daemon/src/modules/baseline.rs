// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Baseline Integrity — Secure, signed, versioned
//!
//! Baseline is cryptographically signed with HMAC-SHA256.
//! If tampered → system enters Invalid state.
//! Only the latest baseline version is considered valid (rollback protection).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const BASELINE_FILE: &str = "C:\\ProgramData\\Invisibly\\baseline.signed";
const BASELINE_HASH_FILE: &str = "C:\\ProgramData\\Invisibly\\baseline.hash";
const VERSIONS_DIR: &str = "C:\\ProgramData\\Invisibly\\baselines\\";
const CURRENT_VERSION_FILE: &str = "C:\\ProgramData\\Invisibly\\current_version.txt";

// ============================================
// TYPES
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBaseline {
    pub version: u64,
    pub timestamp: String,
    pub state: String, // JSON of SystemState
    pub signature: String, // HMAC-SHA256
    pub previous_hash: String, // Chain to previous baseline
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineVersion {
    pub version: u64,
    pub timestamp: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStatus {
    pub exists: bool,
    pub valid: bool,
    pub version: u64,
    pub timestamp: String,
    pub state: String,
}

// ============================================
// CORE FUNCTIONS
// ============================================

pub fn create_baseline(state: &crate::detect::SystemState) -> Result<SignedBaseline, String> {
    let version = get_next_version();
    let prev_hash = get_previous_hash();
    let timestamp = chrono::Local::now().to_rfc3339();

    let state_json = serde_json::to_string(state).map_err(|e| e.to_string())?;
    let signature = sign_baseline(&state_json, &prev_hash, version);

    let baseline = SignedBaseline {
        version,
        timestamp,
        state: state_json,
        signature,
        previous_hash: prev_hash,
    };

    // Save baseline
    let path = Path::new(BASELINE_FILE);
    let data = serde_json::to_string(&baseline).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())?;

    // Save hash
    let hash = compute_baseline_hash(&baseline);
    fs::write(BASELINE_HASH_FILE, &hash).map_err(|e| e.to_string())?;

    // Save current version
    fs::write(CURRENT_VERSION_FILE, &version.to_string()).map_err(|e| e.to_string())?;

    // Save version history
    save_version(baseline.version, &hash);

    Ok(baseline)
}

pub fn verify_baseline() -> BaselineStatus {
    let baseline = load_baseline();
    if baseline.is_none() {
        return BaselineStatus {
            exists: false,
            valid: false,
            version: 0,
            timestamp: String::new(),
            state: String::new(),
        };
    }

    let baseline = baseline.unwrap();

    // === ROLLBACK PROTECTION: Check this is the latest version ===
    let current_version = get_current_version();
    if baseline.version != current_version {
        return BaselineStatus {
            exists: true,
            valid: false,
            version: baseline.version,
            timestamp: baseline.timestamp,
            state: format!("OUTDATED_VERSION (current: {})", current_version),
        };
    }

    // Verify stored hash matches computed
    let stored_hash = fs::read_to_string(BASELINE_HASH_FILE).unwrap_or_default();
    let computed_hash = compute_baseline_hash(&baseline);
    if computed_hash != stored_hash {
        return BaselineStatus {
            exists: true,
            valid: false,
            version: baseline.version,
            timestamp: baseline.timestamp,
            state: "HASH_MISMATCH".to_string(),
        };
    }

    // Verify signature
    let state_hash = sign_baseline(&baseline.state, &baseline.previous_hash, baseline.version);
    if state_hash != baseline.signature {
        return BaselineStatus {
            exists: true,
            valid: false,
            version: baseline.version,
            timestamp: baseline.timestamp,
            state: "INVALID_SIGNATURE".to_string(),
        };
    }

    BaselineStatus {
        exists: true,
        valid: true,
        version: baseline.version,
        timestamp: baseline.timestamp,
        state: "VALID".to_string(),
    }
}

pub fn load_baseline_state() -> Result<crate::detect::SystemState, String> {
    let baseline = load_baseline().ok_or("Baseline not found")?;
    let state: crate::detect::SystemState =
        serde_json::from_str(&baseline.state).map_err(|e| e.to_string())?;
    Ok(state)
}

pub fn get_versions() -> Vec<BaselineVersion> {
    let dir = Path::new(VERSIONS_DIR);
    if !dir.exists() {
        return Vec::new();
    }

    let mut versions = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name() {
                if let Some(name_str) = name.to_str() {
                    if let Ok(data) = fs::read_to_string(&path) {
                        if let Ok(version) = serde_json::from_str::<BaselineVersion>(&data) {
                            versions.push(version);
                        }
                    }
                }
            }
        }
    }
    versions.sort_by_key(|v| v.version);
    versions
}

// NEW: Prune old baseline versions to prevent unbounded growth of the
// baselines/ folder. A new version is written to disk on every baseline
// sync (auto-repair, drift confirmation, etc.), with nothing ever deleting
// old ones - unlike timeline.jsonl this had no cap at all. restore_version()
// only ever needs a *recent* known-good snapshot in practice, so keeping the
// newest MAX_VERSIONS and dropping the rest preserves that feature while
// bounding disk use. Version numbering/hash-chaining for future baselines
// only ever reads the live baseline.signed + current_version.txt (see
// get_next_version/get_previous_hash), not these archived files, so pruning
// them can't corrupt a future baseline.
const MAX_VERSIONS: usize = 200;

pub fn prune_old_versions() {
    let mut versions = get_versions();
    if versions.len() <= MAX_VERSIONS {
        return;
    }
    versions.sort_by_key(|v| v.version);
    let to_remove = versions.len() - MAX_VERSIONS;
    println!("🔄 Pruning baseline history: removing {} old version(s), keeping last {}", to_remove, MAX_VERSIONS);
    for v in &versions[..to_remove] {
        let _ = fs::remove_file(format!("{}{}.json", VERSIONS_DIR, v.version));
        let _ = fs::remove_file(format!("{}{}.signed", VERSIONS_DIR, v.version));
    }
}

pub fn restore_version(version: u64) -> Result<(), String> {
    let versions = get_versions();
    let target = versions.iter().find(|v| v.version == version);
    if target.is_none() {
        return Err(format!("Version {} not found", version));
    }

    // Load the signed baseline for that version
    let path = format!("{}{}.signed", VERSIONS_DIR, version);
    let data = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let baseline: SignedBaseline = serde_json::from_str(&data).map_err(|e| e.to_string())?;

    // Save as current baseline
    fs::write(BASELINE_FILE, data).map_err(|e| e.to_string())?;
    fs::write(BASELINE_HASH_FILE, &target.unwrap().hash).map_err(|e| e.to_string())?;
    fs::write(CURRENT_VERSION_FILE, &version.to_string()).map_err(|e| e.to_string())?;

    Ok(())
}

// ============================================
// HELPERS
// ============================================

fn load_baseline() -> Option<SignedBaseline> {
    let path = Path::new(BASELINE_FILE);
    if !path.exists() {
        return None;
    }
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn get_current_version() -> u64 {
    if let Ok(data) = fs::read_to_string(CURRENT_VERSION_FILE) {
        if let Ok(v) = data.trim().parse::<u64>() {
            return v;
        }
    }
    // If no current version file, try to get from baseline
    if let Some(baseline) = load_baseline() {
        return baseline.version;
    }
    0
}

fn get_next_version() -> u64 {
    get_current_version() + 1
}

fn get_previous_hash() -> String {
    let baseline = load_baseline();
    baseline.map(|b| compute_baseline_hash(&b)).unwrap_or_else(|| "0".to_string())
}

fn sign_baseline(state: &str, prev_hash: &str, version: u64) -> String {
    use ring::hmac;

    // Use the encryption key as HMAC key
    let key_data = crate::crypto::get_hmac_key();
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_data);

    let data = format!("{}{}{}", prev_hash, version, state);
    let tag = hmac::sign(&key, data.as_bytes());
    hex::encode(tag.as_ref())
}

fn compute_baseline_hash(baseline: &SignedBaseline) -> String {
    let data = format!(
        "{}{}{}{}",
        baseline.version,
        baseline.timestamp,
        baseline.state,
        baseline.signature
    );
    hex::encode(ring::digest::digest(&ring::digest::SHA256, data.as_bytes()))
}

fn save_version(version: u64, hash: &str) {
    let dir = Path::new(VERSIONS_DIR);
    let _ = fs::create_dir_all(dir);

    let version_data = BaselineVersion {
        version,
        timestamp: chrono::Local::now().to_rfc3339(),
        hash: hash.to_string(),
    };

    let path = format!("{}{}.json", VERSIONS_DIR, version);
    if let Ok(data) = serde_json::to_string(&version_data) {
        let _ = fs::write(&path, data);
    }

    // Also save the full baseline for restore
    if let Some(baseline) = load_baseline() {
        let signed_path = format!("{}{}.signed", VERSIONS_DIR, version);
        if let Ok(data) = serde_json::to_string(&baseline) {
            let _ = fs::write(&signed_path, data);
        }
    }
}