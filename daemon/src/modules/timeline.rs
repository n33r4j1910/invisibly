// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Security Timeline — Append-only with cryptographic chaining
//!
//! Every event is stored with a hash of the previous event, creating
//! a lightweight blockchain that makes tampering obvious.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use chrono::Local;

const TIMELINE_FILE: &str = "C:\\ProgramData\\Invisibly\\timeline.jsonl";

// ============================================
// IN-MEMORY CACHE — FIX #25
// ============================================

static TIMELINE_CACHE: once_cell::sync::Lazy<Mutex<Option<Vec<TimelineEntry>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

fn invalidate_cache() {
    let mut cache = TIMELINE_CACHE.lock().unwrap();
    *cache = None;
}

fn get_cached_entries() -> Vec<TimelineEntry> {
    let mut cache = TIMELINE_CACHE.lock().unwrap();
    if let Some(entries) = cache.as_ref() {
        return entries.clone();
    }
    let entries = read_entries_from_disk();
    *cache = Some(entries.clone());
    entries
}

// ============================================
// TYPES
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub id: u64,
    pub timestamp: String,
    pub monotonic_counter: u64,  // FIX: Add monotonic counter for clock drift protection
    pub category: String,
    pub action: String,
    pub before: String,
    pub after: String,
    pub result: RepairResult,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RepairResult {
    Success,
    Failed,
    Skipped,
    AwaitingApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub entries: Vec<TimelineEntry>,
    pub last_hash: String,
    pub chain_valid: bool,
    pub entry_count: u64,
}

// ============================================
// CORE FUNCTIONS
// ============================================

pub fn add_entry(
    category: &str,
    action: &str,
    before: &str,
    after: &str,
    result: RepairResult,
) -> Result<(), String> {
    let previous = get_last_hash();
    let id = get_next_id();
    let counter = get_next_counter();  // FIX: Use monotonic counter

    let entry = TimelineEntry {
        id,
        timestamp: Local::now().to_rfc3339(),
        monotonic_counter: counter,
        category: category.to_string(),
        action: action.to_string(),
        before: before.to_string(),
        after: after.to_string(),
        result: result.clone(),
        previous_hash: previous.clone(),
        hash: compute_hash(&previous, id, category, action, before, after, &result, counter),
    };

    append_entry(&entry)?;
    invalidate_cache();
    Ok(())
}

pub fn get_full_timeline() -> Timeline {
    let entries = get_cached_entries();
    let last_hash = get_last_hash();
    let chain_valid = verify_chain();
    let entry_count = entries.len() as u64;
    Timeline {
        entries,
        last_hash,
        chain_valid,
        entry_count,
    }
}

pub fn export_timeline(format: &str) -> String {
    let timeline = get_full_timeline();
    match format {
        "json" => serde_json::to_string_pretty(&timeline.entries).unwrap_or_default(),
        "markdown" => format_timeline_markdown(&timeline.entries),
        _ => serde_json::to_string_pretty(&timeline.entries).unwrap_or_default(),
    }
}

// FIX #12: verify_chain() now called and exposed
pub fn verify_chain() -> bool {
    let entries = read_entries_from_disk();
    if entries.is_empty() {
        return true;
    }

    let mut prev_hash = String::from("0");
    let mut prev_counter: u64 = 0;
    for entry in &entries {
        // Check monotonic counter is increasing
        if entry.monotonic_counter <= prev_counter {
            return false;
        }
        prev_counter = entry.monotonic_counter;

        let computed = compute_hash(
            &prev_hash,
            entry.id,
            &entry.category,
            &entry.action,
            &entry.before,
            &entry.after,
            &entry.result,
            entry.monotonic_counter,
        );
        if computed != entry.hash {
            return false;
        }
        prev_hash = entry.hash.clone();
    }
    true
}

// FIX #12: Verify chain on startup with alert
pub fn verify_chain_on_startup() -> bool {
    let result = verify_chain();
    if result {
        println!("✅ Timeline chain verified");
    } else {
        println!("❌ Timeline chain verification FAILED! Possible tampering detected.");
        // FIX: Log the failure
        let log_path = format!("{}\\timeline_failure.log", 
            std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string()));
        let _ = fs::create_dir_all(Path::new(&log_path).parent().unwrap());
        let entry = format!(
            "{}|TIMELINE_CHAIN_FAILURE|Chain verification failed - possible tampering\n",
            Local::now().format("%Y-%m-%d %H:%M:%S")
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
    result
}

// FIX #12: Initialize timeline on daemon startup
pub fn init_timeline() -> bool {
    verify_chain_on_startup()
}

// ============================================
// HELPERS
// ============================================

// FIX: Get next counter value
static NEXT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn get_next_counter() -> u64 {
    NEXT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
}

fn get_last_hash() -> String {
    let entries = get_cached_entries();
    entries.last().map(|e| e.hash.clone()).unwrap_or_else(|| "0".to_string())
}

fn get_next_id() -> u64 {
    let entries = get_cached_entries();
    entries.len() as u64 + 1
}

fn compute_hash(
    previous: &str,
    id: u64,
    category: &str,
    action: &str,
    before: &str,
    after: &str,
    result: &RepairResult,
    counter: u64,
) -> String {
    // FIX: Include counter in hash for clock drift protection
    let data = format!(
        "{}{}{}{}{}{}{:?}{}",
        previous, id, category, action, before, after, result, counter
    );
    hex::encode(ring::digest::digest(&ring::digest::SHA256, data.as_bytes()))
}

fn read_entries_from_disk() -> Vec<TimelineEntry> {
    let path = Path::new(TIMELINE_FILE);
    if !path.exists() {
        return Vec::new();
    }

    let content = fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn append_entry(entry: &TimelineEntry) -> Result<(), String> {
    let path = Path::new(TIMELINE_FILE);
    let json = serde_json::to_string(entry).map_err(|e| e.to_string())?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    use std::io::Write;
    writeln!(file, "{}", json).map_err(|e| e.to_string())?;

    Ok(())
}

fn format_timeline_markdown(entries: &[TimelineEntry]) -> String {
    if entries.is_empty() {
        return "# Security Timeline\n\nNo events recorded.".to_string();
    }

    let mut output = String::from("# Security Timeline\n\n");

    for entry in entries.iter().rev() {
        let result_str = match entry.result {
            RepairResult::Success => "✅ Success",
            RepairResult::Failed => "❌ Failed",
            RepairResult::Skipped => "⏭️ Skipped",
            RepairResult::AwaitingApproval => "⏳ Awaiting Approval",
        };

        output.push_str(&format!(
            "## {} — {}\n\n",
            entry.timestamp, entry.category
        ));

        output.push_str(&format!(
            "- **Action:** {}\n\
             - **Before:** `{}`\n\
             - **After:** `{}`\n\
             - **Result:** {}\n\
             - **Entry ID:** {}\n\
             - **Counter:** {}\n\
             - **Chain Hash:** `{}`\n\n",
            entry.action,
            entry.before,
            entry.after,
            result_str,
            entry.id,
            entry.monotonic_counter,
            &entry.hash[..16]
        ));
    }

    output
}