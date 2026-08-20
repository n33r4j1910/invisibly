// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Real-Time Folder Watcher — Ransomware Pattern Detection
//!
//! Everything else in this daemon works on a 30s poll cycle, which is fine
//! for config drift (DNS, firewall, etc.) but too slow for ransomware, which
//! can finish encrypting a folder in seconds. This watches a small, curated
//! set of high-value folders (Documents/Desktop/Pictures/Downloads by
//! default) in real time using the OS's own change-notification API, and
//! raises an alert if it sees a burst of rapid file changes - the signature
//! of mass encryption, not a normal single-file edit.
//!
//! Deliberately alert-only, not auto-kill: this API tells you WHAT changed,
//! not WHICH PROCESS did it, so there's no reliable way to attribute the
//! activity to a specific process to terminate - same reasoning that kept
//! "suspicious processes" as alert-only elsewhere in this codebase.

use notify::{Watcher, RecursiveMode, RecommendedWatcher, EventKind};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::{Duration, Instant};
use std::collections::VecDeque;

const BURST_THRESHOLD: usize = 20;
const BURST_WINDOW: Duration = Duration::from_secs(10);
const ALERT_COOLDOWN: Duration = Duration::from_secs(60);

pub fn start_watching(folders: Vec<String>) {
    if folders.is_empty() {
        println!("⚠️ No folders configured for real-time watching - skipping");
        return;
    }

    std::thread::spawn(move || {
        let (tx, rx) = channel();
        let mut watcher: RecommendedWatcher = match notify::recommended_watcher(tx) {
            Ok(w) => w,
            Err(e) => {
                println!("⚠️ Failed to create real-time file watcher: {}", e);
                return;
            }
        };

        for folder in &folders {
            match watcher.watch(std::path::Path::new(folder), RecursiveMode::Recursive) {
                Ok(_) => println!("👁️ Watching {} in real time for ransomware-pattern activity", folder),
                Err(e) => println!("⚠️ Failed to watch {}: {}", folder, e),
            }
        }

        let mut recent_events: VecDeque<Instant> = VecDeque::new();
        let mut last_alert: Option<Instant> = None;

        loop {
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(event)) => {
                    if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)) {
                        continue;
                    }
                    let now = Instant::now();
                    recent_events.push_back(now);
                    while let Some(&front) = recent_events.front() {
                        if now.duration_since(front) > BURST_WINDOW {
                            recent_events.pop_front();
                        } else {
                            break;
                        }
                    }

                    if recent_events.len() >= BURST_THRESHOLD {
                        let cooldown_ok = last_alert.map_or(true, |t| now.duration_since(t) > ALERT_COOLDOWN);
                        if cooldown_ok {
                            let count = recent_events.len();
                            println!("🚨 Possible ransomware activity: {} file changes in {}s across watched folders", count, BURST_WINDOW.as_secs());
                            crate::modules::server::set_ransomware_alert(true);
                            let _ = crate::modules::timeline::add_entry(
                                "ransomware_activity",
                                "detected",
                                &format!("{} file changes within {}s", count, BURST_WINDOW.as_secs()),
                                "Real-time alert - review immediately",
                                crate::modules::timeline::RepairResult::AwaitingApproval,
                            );
                            last_alert = Some(now);
                        }
                        recent_events.clear();
                    }
                }
                Ok(Err(e)) => {
                    println!("⚠️ File watcher error: {}", e);
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Quiet period check: auto-clear the alert once activity has
                    // settled, same as tamper_detected reflects current state
                    // rather than sticking forever on a resolved incident.
                    if crate::modules::server::is_ransomware_alert() {
                        if let Some(t) = last_alert {
                            if Instant::now().duration_since(t) > ALERT_COOLDOWN {
                                crate::modules::server::set_ransomware_alert(false);
                            }
                        }
                    }
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    });
}
