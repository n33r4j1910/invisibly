// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

pub mod detect;
pub mod repair;
pub mod server;
pub mod config;
pub mod crypto;

// Integrity modules
pub mod integrity;
pub mod timeline;
pub mod baseline;
pub mod trust;

// Behavior-based detection
pub mod behavior;

// Real-time ransomware-pattern detection (separate from the 30s poll cycle)
pub mod watcher;

// Tests
#[cfg(test)]
mod integrity_tests;
#[cfg(test)]
mod trust_tests;