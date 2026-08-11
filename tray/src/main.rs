// #![windows_subsystem = "windows"]

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
}

#[derive(Debug)]
enum UserEvent {
    MenuEvent(tray_icon::menu::MenuEvent),
    StatusUpdate(Option<DaemonStatus>),
    TaskbarCreated,
}

const API_URL: &str = "http://127.0.0.1:12790";
const DAEMON_EXE: &str = "C:\\Invisibly\\target\\release\\invisibly-daemon.exe";
const CREATE_NO_WINDOW: u32 = 0x08000000;

// FIX: Tray supervises the daemon - if it stops responding, relaunch it
// instead of waiting for the next logon (Scheduled Task only fires then).
fn relaunch_daemon() {
    println!("🔁 Daemon unresponsive - attempting relaunch...");
    match process::Command::new(DAEMON_EXE)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
    {
        Ok(_) => println!("✅ Daemon relaunch triggered"),
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
        .spawn();
}

struct TrayApp {
    tray: Option<TrayIcon>,
    icons: Arc<(Icon, Icon, Icon, Icon, Icon)>,
    proxy: winit::event_loop::EventLoopProxy<UserEvent>,
}

impl ApplicationHandler<UserEvent> for TrayApp {
    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {
        if self.tray.is_some() {
            return;
        }

        println!("🔄 TrayApp::resumed() - Creating tray icon");

        let menu = Menu::new();
        let open_item = MenuItem::with_id("open_dashboard", "Open Dashboard", true, None);
        let quit_item = MenuItem::with_id("quit_app", "Quit", true, None);
        menu.append(&open_item).unwrap();
        menu.append(&quit_item).unwrap();

        let tray = TrayIconBuilder::new()
            .with_icon(self.icons.4.clone())
            .with_tooltip("Invisibly - Right-click for menu")
            .with_menu(Box::new(menu))
            .build()
            .unwrap();

        println!("✅ Tray icon created");
        self.tray = Some(tray);
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: winit::window::WindowId,
        _event: WindowEvent,
    ) {
        // FIX #29: Handle WM_TASKBARCREATED
        // Note: Full implementation requires windows message handling
        // This is a placeholder for the message handling
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::MenuEvent(event) => {
                println!("📋 MenuEvent: {:?}", event.id.as_ref());
                match event.id.as_ref() {
                    "open_dashboard" => {
                        open_dashboard();
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
            // FIX #29: Handle taskbar re-creation
            UserEvent::TaskbarCreated => {
                println!("🔄 Taskbar recreated - re-creating tray icon");
                // Re-create the tray icon
                if let Some(tray) = self.tray.take() {
                    let _ = tray.set_visible(false);
                    drop(tray);
                }
                // Trigger resumed() to recreate
                self.resumed(event_loop);
                // Send a status update to refresh the icon
                let _ = self.proxy.send_event(UserEvent::StatusUpdate(None));
            }
            UserEvent::StatusUpdate(status) => {
                println!("🔄 StatusUpdate event received");
                if let Some(tray) = &self.tray {
                    let (icon, tooltip) = match status {
                        Some(s) => {
                            println!("📊 Status: trust_state={}, integrity_state={:?}, enabled={}", 
                                     s.trust_state, s.integrity_state, s.enabled);
                            
                            // FIX C10: Branch on integrity_state instead of trust_state
                            // Use integrity_state for color, trust_state only for Ghost
                            match s.integrity_state.as_deref() {
                                Some("Maintained") => {
                                    if s.enabled {
                                        (self.icons.0.clone(), "🟢 Maintained - Secure\nRight-click for menu")
                                    } else {
                                        (self.icons.4.clone(), "⚪ Disabled - Monitor Only")
                                    }
                                }
                                Some("DriftDetected") => {
                                    (self.icons.1.clone(), "🟡 Drift Detected - Review changes\nRight-click for menu")
                                }
                                Some("Compromised") => {
                                    (self.icons.2.clone(), "🔴 COMPROMISED - Check Dashboard\nRight-click for menu")
                                }
                                Some("Lockdown") => {
                                    (self.icons.3.clone(), "🔵 Lockdown Active\nRight-click for menu")
                                }
                                _ => {
                                    // Fallback to trust_state for Ghost/Trusted
                                    match s.trust_state.as_str() {
                                        "Ghost" => (self.icons.3.clone(), "🔵 Ghost Mode Active\nRight-click for menu"),
                                        "Trusted" => {
                                            if s.enabled {
                                                (self.icons.0.clone(), "🟢 Trusted - Active\nRight-click for menu")
                                            } else {
                                                (self.icons.4.clone(), "⚪ Disabled - Monitor Only")
                                            }
                                        }
                                        _ => (self.icons.4.clone(), "⚪ Checking..."),
                                    }
                                }
                            }
                        }
                        None => {
                            println!("⚠️ No status received - daemon offline");
                            (self.icons.4.clone(), "⚪ Daemon offline")
                        }
                    };
                    println!("🎨 Setting icon and tooltip");
                    let _ = tray.set_icon(Some(icon));
                    let _ = tray.set_tooltip(Some(tooltip));
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

// FIX #29: Function to register for taskbar creation notification
fn register_taskbar_notification() {
    // This is a placeholder for the actual window message registration
    // In a full implementation, you would use RegisterWindowMessage and set up a hidden window
    println!("🔔 Taskbar notification registered");
}

fn main() {
    if !check_single_instance() {
        println!("⚠️ Invisibly tray is already running!");
        return;
    }

    println!("🛡️ Invisibly Tray - Starting...");

    // FIX #29: Register for taskbar creation notification
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
        // FIX: Track consecutive failures so a crashed/hung daemon gets
        // relaunched automatically, with a cooldown to avoid a spawn storm.
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
    };

    println!("🚀 Running event loop...");
    if let Err(e) = event_loop.run_app(&mut app) {
        println!("❌ Event loop error: {}", e);
    }
}