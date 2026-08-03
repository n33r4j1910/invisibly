// Copyright (c) 2026 DeltaIQx LLP. All rights reserved.`n// This software is proprietary and confidential.`nuse std::fs;
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
    let _ = fs::create_dir_all(&msix_dir);

    // Copy executables to MSIX layout
    let _ = fs::copy(exe_path.join("invisibly-daemon.exe"), msix_dir.join("invisibly-daemon.exe"));
    let _ = fs::copy(exe_path.join("invisibly-tray.exe"), msix_dir.join("invisibly-tray.exe"));

    // Create AppxManifest
    let manifest_path = msix_dir.join("AppxManifest.xml");
    let manifest_content = r#"
<Package xmlns="http://schemas.microsoft.com/appx/2010/manifest"
         xmlns:rescap="http://schemas.microsoft.com/appx/2014/11/manifest"
         xmlns:uap5="http://schemas.microsoft.com/appx/2015/12/manifest">
    <Identity Name="Invisibly"
              Publisher="CN=Invisibly"
              Version="1.0.0.0"/>
    <Properties>
        <DisplayName>Invisibly</DisplayName>
        <Description>Lightweight autonomous endpoint security agent</Description>
        <Logo>assets\logo.png</Logo>
        <PublisherDisplayName>Invisibly</PublisherDisplayName>
    </Properties>
    <Resources>
        <Resource Language="en-US"/>
    </Resources>
    <Capabilities>
        <Capability Name="internetClient"/>
        <rescap:Capability Name="runFullTrust"/>
    </Capabilities>
    <Applications>
        <Application Id="Invisibly" Executable="invisibly-daemon.exe" EntryPoint="Windows.FullTrustApplication">
            <Extensions>
                <uap5:Extension Category="windows.appExecutionAlias" EntryPoint="Windows.FullTrustApplication" Executable="invisibly-daemon.exe">
                    <uap5:AppExecutionAlias>
                        <uap5:ExecutionAlias Alias="invisibly.exe"/>
                    </uap5:AppExecutionAlias>
                </uap5:Extension>
            </Extensions>
        </Application>
    </Applications>
</Package>"#;

    fs::write(manifest_path, manifest_content).unwrap();

    // Create placeholder icon if not exists
    let assets_dir = msix_dir.join("assets");
    let _ = fs::create_dir_all(&assets_dir);

    // Generate MSIX using MakeAppx
    let _ = Command::new("makeappx")
        .args([
            "pack",
            "/d", msix_dir.to_str().unwrap(),
            "/p", target_dir.join("Invisibly.msix").to_str().unwrap(),
        ])
        .status();

    println!("cargo:rerun-if-changed=build.rs");
}
