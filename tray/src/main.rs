#![windows_subsystem = "windows"]

use std::time::Duration;
use std::process;
use std::sync::Arc;
use tray_icon::{TrayIconBuilder, Icon, TrayIcon, TrayIconEvent};
use tray_icon::menu::{Menu, MenuItem, MenuEvent};
use serde::Deserialize;
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ControlFlow, EventLoop, ActiveEventLoop};

#[derive(Debug, Deserialize)]
struct DaemonStatus {
    trust_state: String,
    ghost: bool,
    enabled: bool,
}

#[derive(Debug)]
enum UserEvent {
    MenuEvent(tray_icon::menu::MenuEvent),
    StatusUpdate(Option<DaemonStatus>),
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

        self.tray = Some(tray);
    }

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: winit::window::WindowId,
        _event: WindowEvent,
    ) {
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::MenuEvent(event) => {
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
            UserEvent::StatusUpdate(status) => {
                if let Some(tray) = &self.tray {
                    let (icon, tooltip) = match status {
                        Some(s) => {
                            match s.trust_state.as_str() {
                                "Trusted" => {
                                    if s.enabled {
                                        (self.icons.0.clone(), "🟢 Trusted - Active\nRight-click for menu")
                                    } else {
                                        (self.icons.4.clone(), "⚪ Disabled - Monitor Only")
                                    }
                                }
                                "Warning" => (self.icons.1.clone(), "🟡 Warning - Changes Detected\nRight-click for menu"),
                                "Compromised" => (self.icons.2.clone(), "🔴 COMPROMISED - Check Dashboard\nRight-click for menu"),
                                "Ghost" => (self.icons.3.clone(), "🔵 Ghost Mode Active\nRight-click for menu"),
                                _ => (self.icons.4.clone(), "⚪ Checking..."),
                            }
                        }
                        None => (self.icons.4.clone(), "⚪ Daemon offline"),
                    };
                    let _ = tray.set_icon(Some(icon));
                    let _ = tray.set_tooltip(Some(tooltip));
                }
            }
        }
    }

    fn about_to_wait(&mut self, _event_loop: &ActiveEventLoop) {}
}

fn main() {
    println!("🛡️ Invisibly Tray - Right-click for menu");

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
        loop {
            match client.get(API_URL).timeout(Duration::from_secs(1)).send() {
                Ok(resp) => {
                    if let Ok(status) = resp.json::<DaemonStatus>() {
                        let _ = proxy2.send_event(UserEvent::StatusUpdate(Some(status)));
                    }
                }
                Err(_) => {
                    let _ = proxy2.send_event(UserEvent::StatusUpdate(None));
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

    let _ = event_loop.run_app(&mut app);
}