// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.`n// This software is proprietary and confidential.`nuse std::time::Duration;
use std::thread;
use std::process;
use tray_icon::{TrayIconBuilder, Icon};
use serde::Deserialize;
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::w;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct DaemonStatus {
    trust_state: String,
    ghost: bool,
    enabled: bool,
}

const API_URL: &str = "http://127.0.0.1:12790";

fn create_circle_icon(r: u8, g: u8, b: u8) -> Icon {
    let mut pixels = Vec::with_capacity(1024);
    for y in 0..16 {
        for x in 0..16 {
            let dx = x as f32 - 7.5;
            let dy = y as f32 - 7.5;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist <= 6.5 {
                pixels.extend_from_slice(&[r, g, b, 255]);
            } else if dist <= 7.0 {
                let alpha = (255.0 * (1.0 - (dist - 6.5) / 0.5)) as u8;
                pixels.extend_from_slice(&[r, g, b, alpha]);
            } else {
                pixels.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    Icon::from_rgba(pixels, 16, 16).unwrap()
}

fn check_single_instance() -> bool {
    unsafe {
        let handle = CreateMutexW(None, true, w!("Global\\InvisiblyTrayMutex"));
        if handle.is_ok() {
            let err = GetLastError();
            if err.0 == ERROR_ALREADY_EXISTS.0 {
                return false;
            }
            true
        } else {
            false
        }
    }
}

fn main() {
    if !check_single_instance() {
        println!("⚠️ Invisibly tray is already running!");
        process::exit(0);
    }

    println!("🛡️ Invisibly Tray - Silent Mode (Dashboard-only alerts)");

    let icon_green = create_circle_icon(0, 255, 0);
    let icon_yellow = create_circle_icon(255, 255, 0);
    let icon_red = create_circle_icon(255, 0, 0);
    let icon_blue = create_circle_icon(0, 100, 255);
    let icon_gray = create_circle_icon(128, 128, 128);

    let tray = TrayIconBuilder::new()
        .with_icon(icon_gray.clone())
        .with_tooltip("Invisibly - Starting...")
        .build()
        .unwrap();

    let client = reqwest::blocking::Client::new();

    loop {
        match client.get(API_URL).timeout(Duration::from_secs(3)).send() {
            Ok(resp) => {
                if let Ok(status) = resp.json::<DaemonStatus>() {
                    let (icon, tooltip) = match status.trust_state.as_str() {
                        "Trusted" => {
                            if status.enabled {
                                (icon_green.clone(), "🟢 Trusted - Active")
                            } else {
                                (icon_gray.clone(), "⚪ Disabled - Monitor Only")
                            }
                        }
                        "Warning" => (icon_yellow.clone(), "🟡 Warning - Changes Detected"),
                        "Compromised" => (icon_red.clone(), "🔴 COMPROMISED - Check Dashboard"),
                        "Ghost" => (icon_blue.clone(), "🔵 Ghost Mode Active"),
                        _ => (icon_gray.clone(), "⚪ Checking..."),
                    };

                    let _ = tray.set_icon(Some(icon));
                    let _ = tray.set_tooltip(Some(tooltip));
                }
            }
            Err(_) => {
                let _ = tray.set_icon(Some(icon_gray.clone()));
                let _ = tray.set_tooltip(Some("⚪ Daemon offline"));
            }
        }
        thread::sleep(Duration::from_secs(3));
    }
}
