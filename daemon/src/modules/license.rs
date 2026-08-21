// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

//! Store subscription licensing
//!
//! Free tier: detection/monitoring only (all 35 signals, dashboard, alerts).
//! Paid tier (`invisibly_pro_subscription`): automatic + confirm-tier repair,
//! Ghost Mode, real-time ransomware watch.
//!
//! FAIL-OPEN BY DESIGN: this only blocks a paid feature when it gets a
//! definitive "not subscribed" answer from the Store. Any ambiguous case -
//! the add-on not published yet, no package identity (unpackaged/dev exe),
//! a network error, the Store service unreachable - defaults to GRANTING
//! access, not denying it. Two deliberate reasons:
//! 1. There will be a gap between the app being approved and the
//!    subscription add-on going live. Before the add-on exists in the
//!    Store, every license query for it comes back "product not found" -
//!    which falls into fail-open, so early downloaders get full features
//!    automatically with no separate grandfathering logic needed.
//! 2. The product is marketed as fully offline-capable - a user with no
//!    internet access shouldn't lose paid features they're entitled to
//!    just because the daemon couldn't reach Microsoft's licensing service.

use std::sync::atomic::{AtomicBool, Ordering};

const PRODUCT_ID: &str = "invisibly_pro_subscription";

// Defaults to true (licensed) until the first real check completes, and
// stays true if that check can't produce a definitive answer - see the
// fail-open rationale above. This is deliberately NOT the same posture as
// AWAITING_CONSENT in server.rs (which defaults to "blocked" until proven
// otherwise) - the two flags have opposite failure modes on purpose:
// consent must be proven given, licensing must be proven absent.
static IS_LICENSED: AtomicBool = AtomicBool::new(true);

pub fn is_pro_licensed() -> bool {
    IS_LICENSED.load(Ordering::Acquire)
}

fn set_licensed(licensed: bool) {
    IS_LICENSED.store(licensed, Ordering::Release);
}

/// Queries the Windows Store for an active license on PRODUCT_ID.
/// Requires package identity (only works running from the installed MSIX,
/// not a raw/unpackaged exe) - StoreContext::GetDefault() itself is the
/// first thing that fails in that case, and is handled as fail-open below
/// like every other ambiguous outcome.
fn check_store_license() -> bool {
    use windows::Services::Store::StoreContext;

    let context = match StoreContext::GetDefault() {
        Ok(c) => c,
        Err(e) => {
            println!("⚠️ License check: no Store context available ({}) - defaulting to full access", e);
            return true;
        }
    };

    let async_op = match context.GetAppLicenseAsync() {
        Ok(op) => op,
        Err(e) => {
            println!("⚠️ License check: GetAppLicenseAsync failed ({}) - defaulting to full access", e);
            return true;
        }
    };

    let license = match async_op.get() {
        Ok(l) => l,
        Err(e) => {
            println!("⚠️ License check: could not retrieve app license ({}) - defaulting to full access", e);
            return true;
        }
    };

    let add_ons = match license.AddOnLicenses() {
        Ok(map) => map,
        Err(e) => {
            println!("⚠️ License check: could not read add-on licenses ({}) - defaulting to full access", e);
            return true;
        }
    };

    match add_ons.Lookup(&windows::core::HSTRING::from(PRODUCT_ID)) {
        Ok(store_license) => {
            match store_license.IsActive() {
                Ok(true) => {
                    println!("✅ Pro subscription active");
                    true
                }
                Ok(false) => {
                    println!("ℹ️ Pro subscription not active - free tier (detection only)");
                    false
                }
                Err(e) => {
                    println!("⚠️ License check: could not read IsActive ({}) - defaulting to full access", e);
                    true
                }
            }
        }
        // Product not found in the map: either the add-on isn't published
        // yet (the gap this was designed for) or something else ambiguous.
        // Fail open either way.
        Err(_) => {
            println!("ℹ️ License check: product not found in Store (add-on may not be live yet) - defaulting to full access");
            true
        }
    }
}

/// Runs one check immediately, then re-checks periodically so a lapsed
/// subscription (or a newly-purchased one) is picked up without requiring
/// a restart. Call once from main.rs at startup.
pub fn start_license_check_thread() {
    std::thread::spawn(|| {
        loop {
            let licensed = check_store_license();
            set_licensed(licensed);
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    });
}
