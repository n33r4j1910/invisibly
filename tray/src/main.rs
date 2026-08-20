#![windows_subsystem = "windows"]

use std::time::Duration;
use std::process;
use std::sync::Arc;
use std::os::windows::process::CommandExt;
use tray_icon::{TrayIconBuilder, Icon, TrayIcon};
use tray_icon::menu::{Menu, MenuItem, MenuEvent};
use serde::Deserialize;
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ControlFlow, EventLoop, ActiveEventLoop};
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::w;

// FIX #29: WM_TASKBARCREATED message for explorer restart
const WM_TASKBARCREATED: u32 = 0x0400 + 1;

fn default_true() -> bool { true }

#[derive(Debug, Deserialize)]
struct DaemonStatus {
    #[serde(default)]
    status: Option<String>,
    trust_state: String,
    ghost: bool,
    enabled: bool,
    #[serde(default)]
    integrity_score: Option<u8>,
    #[serde(default)]
    integrity_state: Option<String>,
    #[serde(default)]
    trust_level: Option<u8>,
    // Whether the daemon has admin rights - without it, auto-repair is
    // silently skipped. Defaults to true so an older daemon build that
    // doesn't send this field doesn't wrongly trigger the warning.
    #[serde(default = "default_true")]
    elevated: bool,
    // The daemon's own executable failed its self-integrity check - the one
    // state that must be surfaced to the user, never silently auto-repaired.
    #[serde(default)]
    tamper_detected: bool,
}

#[derive(Debug)]
enum UserEvent {
    MenuEvent(tray_icon::menu::MenuEvent),
    StatusUpdate(Option<DaemonStatus>),
    TaskbarCreated,
}

const API_URL: &str = "http://127.0.0.1:12790";
const CREATE_NO_WINDOW: u32 = 0x08000000;

// ============================================
// DYNAMIC DAEMON PATH
// ============================================

fn daemon_exe_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("invisibly-daemon.exe")))
        .unwrap_or_else(|| "invisibly-daemon.exe".into())
}

// ============================================
// TOKEN STORAGE
// ============================================

static TOKEN: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn get_token() -> Option<String> {
    let mut guard = TOKEN.lock().unwrap();
    if let Some(token) = guard.as_ref() {
        return Some(token.clone());
    }
    
    let client = reqwest::blocking::Client::new();
    if let Ok(resp) = client.get(&format!("{}/token", API_URL)).timeout(Duration::from_secs(2)).send() {
        if let Ok(json) = resp.json::<serde_json::Value>() {
            if let Some(token) = json.get("token").and_then(|t| t.as_str()) {
                let token_str = token.to_string();
                *guard = Some(token_str.clone());
                return Some(token_str);
            }
        }
    }
    None
}

// ============================================
// GET PENDING CATEGORIES FROM TIMELINE
// ============================================

fn get_pending_categories() -> Vec<String> {
    let mut pending = Vec::new();
    let token = match get_token() {
        Some(t) => t,
        None => return pending,
    };
    
    let client = reqwest::blocking::Client::new();
    let url = format!("{}/timeline?format=json", API_URL);
    
    match client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .timeout(Duration::from_secs(5))
        .send()
    {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(entries) = json.as_array() {
                    for entry in entries {
                        if let (Some(category), Some(action), Some(result)) = (
                            entry.get("category").and_then(|v| v.as_str()),
                            entry.get("action").and_then(|v| v.as_str()),
                            entry.get("result").and_then(|v| v.as_str()),
                        ) {
                            if action == "pending_approval" && result == "AwaitingApproval" {
                                if !pending.contains(&category.to_string()) {
                                    pending.push(category.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to get timeline: {}", e);
        }
    }
    pending
}

// ============================================
// CALL APPROVE ENDPOINT (SINGLE CATEGORY)
// ============================================

fn call_approve(category: &str) -> bool {
    let token = match get_token() {
        Some(t) => t,
        None => {
            println!("❌ Failed to get token for approve");
            return false;
        }
    };
    
    let client = reqwest::blocking::Client::new();
    let url = format!("{}/approve?category={}", API_URL, category);
    
    match client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .timeout(Duration::from_secs(5))
        .send() 
    {
        Ok(resp) => {
            if resp.status().is_success() {
                if let Ok(json) = resp.json::<serde_json::Value>() {
                    if let Some(msg) = json.get("message").and_then(|m| m.as_str()) {
                        println!("✅ Approve successful: {}", msg);
                    }
                }
                true
            } else {
                println!("❌ Approve failed: HTTP {}", resp.status());
                false
            }
        }
        Err(e) => {
            println!("❌ Approve error: {}", e);
            false
        }
    }
}

// ============================================
// NOTIFICATIONS - fired only on real state transitions (see StatusUpdate),
// not on every poll, so the tool stays quiet unless something needs attention.
// Uses WinForms balloon tips via PowerShell rather than WinRT toast APIs -
// no new dependency, no AUMID/package-identity setup, same Command::new
// pattern already used throughout this codebase.
// ============================================

fn show_notification(title: &str, message: &str, is_warning: bool) {
    let icon = if is_warning { "Warning" } else { "Info" };
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; \
         $n = New-Object System.Windows.Forms.NotifyIcon; \
         $n.Icon = [System.Drawing.SystemIcons]::Shield; \
         $n.Visible = $true; \
         Start-Sleep -Milliseconds 300; \
         $n.ShowBalloonTip(6000, '{}', '{}', [System.Windows.Forms.ToolTipIcon]::{}); \
         Start-Sleep -Seconds 7; \
         $n.Dispose()",
        title.replace('\'', "''"), message.replace('\'', "''"), icon
    );
    let _ = process::Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

fn is_daemon_running() -> bool {
    let output = process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq invisibly-daemon.exe"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    if let Ok(output) = output {
        String::from_utf8_lossy(&output.stdout).contains("invisibly-daemon.exe")
    } else {
        false
    }
}

fn relaunch_daemon() {
    println!("🔁 Daemon unresponsive - attempting relaunch...");
    let daemon_path = daemon_exe_path();
    match process::Command::new(&daemon_path)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
    {
        Ok(_) => println!("✅ Daemon relaunch triggered from: {}", daemon_path.display()),
        Err(e) => println!("❌ Failed to relaunch daemon: {}", e),
    }
}

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

fn open_dashboard() {
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "http://127.0.0.1:12790/dashboard"])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

struct TrayApp {
    tray: Option<TrayIcon>,
    icons: Arc<(Icon, Icon, Icon, Icon, Icon)>,
    proxy: winit::event_loop::EventLoopProxy<UserEvent>,
    approve_item: Option<MenuItem>,
    last_pending_count: usize,
    last_tamper_state: bool,
}

impl ApplicationHandler<UserEvent> for TrayApp {
    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {
        if self.tray.is_some() {
            return;
        }

        println!("🔄 TrayApp::resumed() - Creating tray icon");

        // Ensure daemon is running immediately on startup (skip if already running)
        if !is_daemon_running() {
            relaunch_daemon();
        }

        let pending = get_pending_categories();
        let pending_count = pending.len();
        let approve_label = if pending_count > 0 {
            format!("Approve Pending Changes ({})", pending_count)
        } else {
            "Approve Pending Changes (0)".to_string()
        };

        let menu = Menu::new();
        let open_item = MenuItem::with_id("open_dashboard", "Open Dashboard", true, None);
        let approve_item = MenuItem::with_id("approve_all", &approve_label, true, None);
        let separator = MenuItem::with_id("sep", "", false, None);
        let quit_item = MenuItem::with_id("quit_app", "Quit", true, None);
        
        menu.append(&open_item).unwrap();
        menu.append(&approve_item).unwrap();
        menu.append(&separator).unwrap();
        menu.append(&quit_item).unwrap();

        let tray = TrayIconBuilder::new()
            .with_icon(self.icons.4.clone())
            .with_tooltip("Invisibly - Right-click for menu")
            .with_menu(Box::new(menu))
            .build()
            .unwrap();

        println!("✅ Tray icon created");
        self.tray = Some(tray);
        self.approve_item = Some(approve_item);
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: winit::window::WindowId,
        _event: WindowEvent,
    ) {
        // FIX #29: Handle WM_TASKBARCREATED
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::MenuEvent(event) => {
                println!("📋 MenuEvent: {:?}", event.id.as_ref());
                match event.id.as_ref() {
                    "open_dashboard" => {
                        open_dashboard();
                    }
                    "approve_all" => {
                        println!("🔓 Checking pending approvals...");
                        let pending = get_pending_categories();
                        
                        if pending.is_empty() {
                            println!("✅ No pending approvals found");
                        } else {
                            println!("📋 Found {} pending category(s): {:?}", pending.len(), pending);
                            let mut success_count = 0;
                            for category in &pending {
                                println!("🔓 Approving: {}", category);
                                if call_approve(category) {
                                    success_count += 1;
                                }
                                std::thread::sleep(Duration::from_millis(500));
                            }
                            println!("✅ Approved {}/{} pending items", success_count, pending.len());
                        }
                    }
                    "quit_app" => {
                        println!("Exiting...");
                        if let Some(tray_instance) = self.tray.take() {
                            let _ = tray_instance.set_visible(false);
                            drop(tray_instance);
                        }
                        event_loop.exit();
                        process::exit(0);
                    }
                    _ => {}
                }
            }
            UserEvent::TaskbarCreated => {
                println!("🔄 Taskbar recreated - re-creating tray icon");
                if let Some(tray) = self.tray.take() {
                    let _ = tray.set_visible(false);
                    drop(tray);
                }
                self.resumed(event_loop);
                let _ = self.proxy.send_event(UserEvent::StatusUpdate(None));
            }
            UserEvent::StatusUpdate(status) => {
                println!("🔄 StatusUpdate event received");

                let pending_count = get_pending_categories().len();
                if let Some(approve_item) = &self.approve_item {
                    approve_item.set_text(format!("Approve Pending Changes ({})", pending_count));
                }
                if pending_count > self.last_pending_count {
                    show_notification("Invisibly", &format!("{} change(s) need your approval - open the tray menu to review.", pending_count), false);
                }
                self.last_pending_count = pending_count;

                if let Some(s) = &status {
                    if s.tamper_detected && !self.last_tamper_state {
                        show_notification("Invisibly - Security Alert", "The app's own executable failed its integrity check. Open the dashboard for details.", true);
                    }
                    self.last_tamper_state = s.tamper_detected;
                }

                if let Some(tray) = &self.tray {
                    let (icon, tooltip) = match status {
                        Some(s) => {
                            println!("📊 Status: score={:?}, state={:?}, ghost={}, enabled={}", 
                                     s.integrity_score, s.integrity_state, s.ghost, s.enabled);
                            
                            // FIX: Check GHOST MODE FIRST
                            if s.tamper_detected {
                                (self.icons.2.clone(), "🔴 SECURITY ALERT - executable may be tampered\nOpen Dashboard for details".to_string())
                            } else if s.ghost {
                                (self.icons.3.clone(), format!("🔵 Ghost Mode Active - {}%\nRight-click for menu",
                                    s.integrity_score.unwrap_or(0)))
                            } else if !s.elevated {
                                (self.icons.4.clone(), "⚠️ Limited Protection - Restart to enable auto-repair\nRight-click for menu".to_string())
                            } else {
                                // Then check integrity score for color
                                match s.integrity_score {
                                    Some(score) if score >= 90 => {
                                        if s.enabled {
                                            (self.icons.0.clone(), format!("🟢 Maintained - {}%\nRight-click for menu", score))
                                        } else {
                                            (self.icons.4.clone(), "⚪ Disabled - Monitor Only".to_string())
                                        }
                                    }
                                    Some(score) if score >= 70 => {
                                        (self.icons.1.clone(), format!("🟡 Drift Detected - {}%\nRight-click for menu", score))
                                    }
                                    Some(score) if score >= 40 => {
                                        (self.icons.2.clone(), format!("🔴 Compromised - {}%\nRight-click for menu", score))
                                    }
                                    Some(score) => {
                                        (self.icons.2.clone(), format!("🔴 CRITICAL - {}%\nRight-click for menu", score))
                                    }
                                    None => {
                                        // Fallback to state string if score missing
                                        match s.integrity_state.as_deref() {
                                            Some("Maintained") => (self.icons.0.clone(), "🟢 Maintained\nRight-click for menu".to_string()),
                                            Some("DriftDetected") => (self.icons.1.clone(), "🟡 Drift Detected\nRight-click for menu".to_string()),
                                            Some("Compromised") => (self.icons.2.clone(), "🔴 Compromised\nRight-click for menu".to_string()),
                                            Some("Lockdown") => (self.icons.3.clone(), "🔵 Lockdown Active\nRight-click for menu".to_string()),
                                            _ => {
                                                match s.trust_state.as_str() {
                                                    "Ghost" => (self.icons.3.clone(), "🔵 Ghost Mode Active\nRight-click for menu".to_string()),
                                                    "Trusted" => {
                                                        if s.enabled {
                                                            (self.icons.0.clone(), "🟢 Trusted - Active\nRight-click for menu".to_string())
                                                        } else {
                                                            (self.icons.4.clone(), "⚪ Disabled - Monitor Only".to_string())
                                                        }
                                                    }
                                                    _ => (self.icons.4.clone(), "⚪ Checking...".to_string()),
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            println!("⚠️ No status received - daemon offline");
                            (self.icons.4.clone(), "⚪ Daemon offline".to_string())
                        }
                    };
                    println!("🎨 Setting icon and tooltip");
                    let _ = tray.set_icon(Some(icon));
                    let _ = tray.set_tooltip(Some(&tooltip));
                } else {
                    println!("⚠️ Tray is None, cannot update icon");
                }
            }
        }
    }

    fn about_to_wait(&mut self, _event_loop: &ActiveEventLoop) {}
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

fn register_taskbar_notification() {
    println!("🔔 Taskbar notification registered");
}

fn main() {
    if !check_single_instance() {
        println!("⚠️ Invisibly tray is already running!");
        return;
    }

    println!("🛡️ Invisibly Tray - Starting...");

    register_taskbar_notification();

    let event_loop = EventLoop::with_user_event().build().unwrap();

    let icon_green = create_circle_icon(0, 255, 0);
    let icon_yellow = create_circle_icon(255, 255, 0);
    let icon_red = create_circle_icon(255, 0, 0);
    let icon_blue = create_circle_icon(0, 100, 255);
    let icon_gray = create_circle_icon(128, 128, 128);

    let icons = Arc::new((icon_green, icon_yellow, icon_red, icon_blue, icon_gray));

    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::MenuEvent(event));
    }));

    let proxy2 = event_loop.create_proxy();
    std::thread::spawn(move || {
        let client = reqwest::blocking::Client::new();
        println!("🔄 Status polling thread started");
        let mut consecutive_failures: u32 = 0;
        let mut last_relaunch: Option<std::time::Instant> = None;
        loop {
            match client.get(API_URL).timeout(Duration::from_secs(2)).send() {
                Ok(resp) => {
                    consecutive_failures = 0;
                    match resp.json::<DaemonStatus>() {
                        Ok(status) => {
                            println!("📊 Daemon status: {}", status.trust_state);
                            let _ = proxy2.send_event(UserEvent::StatusUpdate(Some(status)));
                        }
                        Err(e) => {
                            println!("⚠️ JSON parse error: {}", e);
                            let _ = proxy2.send_event(UserEvent::StatusUpdate(None));
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Daemon offline: {}", e);
                    let _ = proxy2.send_event(UserEvent::StatusUpdate(None));
                    consecutive_failures += 1;
                    if consecutive_failures >= 3 {
                        let cooldown_ok = last_relaunch.map_or(true, |t: std::time::Instant| t.elapsed() > Duration::from_secs(30));
                        if cooldown_ok {
                            relaunch_daemon();
                            last_relaunch = Some(std::time::Instant::now());
                            consecutive_failures = 0;
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    });

    let mut app = TrayApp {
        tray: None,
        icons: icons.clone(),
        proxy: event_loop.create_proxy(),
        approve_item: None,
        last_pending_count: 0,
        last_tamper_state: false,
    };

    println!("🚀 Running event loop...");
    if let Err(e) = event_loop.run_app(&mut app) {
        println!("❌ Event loop error: {}", e);
    }
}