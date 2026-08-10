// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.
// This software is proprietary and confidential.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::env;

fn main() {
    if !cfg!(target_os = "windows") {
        return;
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir).parent().unwrap().parent().unwrap().parent().unwrap();
    let exe_path = target_dir.join("release");
    let msix_dir = target_dir.join("msix");

    // Create MSIX directory
    if let Err(e) = fs::create_dir_all(&msix_dir) {
        panic!("Failed to create msix directory: {}", e);
    }

    // FIX #31: Check return values, fail build on error
    // Copy executables to MSIX layout
    let daemon_src = exe_path.join("invisibly-daemon.exe");
    let daemon_dst = msix_dir.join("invisibly-daemon.exe");
    if daemon_src.exists() {
        if let Err(e) = fs::copy(&daemon_src, &daemon_dst) {
            panic!("Failed to copy invisibly-daemon.exe: {}", e);
        }
        println!("✅ Copied invisibly-daemon.exe to MSIX package");
    } else {
        panic!("invisibly-daemon.exe not found at {:?}", daemon_src);
    }

    let tray_src = exe_path.join("invisibly-tray.exe");
    let tray_dst = msix_dir.join("invisibly-tray.exe");
    if tray_src.exists() {
        if let Err(e) = fs::copy(&tray_src, &tray_dst) {
            panic!("Failed to copy invisibly-tray.exe: {}", e);
        }
        println!("✅ Copied invisibly-tray.exe to MSIX package");
    } else {
        panic!("invisibly-tray.exe not found at {:?}", tray_src);
    }

    // Copy assets from msix_package
    let source_assets = Path::new("msix_package").join("Assets");
    let dest_assets = msix_dir.join("Assets");
    if source_assets.exists() {
        if let Err(e) = fs::create_dir_all(&dest_assets) {
            panic!("Failed to create assets directory: {}", e);
        }
        match fs::read_dir(&source_assets) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) => {
                            let dest = dest_assets.join(entry.file_name());
                            if let Err(e) = fs::copy(entry.path(), dest) {
                                panic!("Failed to copy asset: {}", e);
                            }
                        }
                        Err(e) => panic!("Failed to read asset entry: {}", e),
                    }
                }
                println!("✅ Copied assets to MSIX package");
            }
            Err(e) => panic!("Failed to read assets directory: {}", e),
        }
    } else {
        println!("⚠️ No assets directory found, skipping");
    }

    // Copy the actual AppxManifest from msix_package (not generated)
    let source_manifest = Path::new("msix_package").join("AppxManifest.xml");
    if source_manifest.exists() {
        let dest_manifest = msix_dir.join("AppxManifest.xml");
        if let Err(e) = fs::copy(&source_manifest, &dest_manifest) {
            panic!("Failed to copy AppxManifest.xml: {}", e);
        }
        println!("✅ Copied AppxManifest.xml to MSIX package");
    } else {
        panic!("AppxManifest.xml not found at {:?}", source_manifest);
    }

    // Generate MSIX using MakeAppx
    let msix_path = target_dir.join("Invisibly.msix");
    let status = Command::new("makeappx")
        .args([
            "pack",
            "/d", msix_dir.to_str().unwrap(),
            "/p", msix_path.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(status) => {
            if status.success() {
                println!("✅ MSIX package created successfully at: {}", msix_path.display());
            } else {
                panic!("makeappx failed with exit code: {:?}", status.code());
            }
        }
        Err(e) => {
            panic!("Failed to run makeappx: {}", e);
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=msix_package/AppxManifest.xml");
}