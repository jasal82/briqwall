//! Briqwall user interface (Tauri 2 + Svelte/TypeScript in ui/).
//!
//! Runs unprivileged in the user's session. Loosening changes are applied via
//! a short-lived elevated copy of this executable (`--apply <hex>`), never by
//! keeping the whole UI elevated.

#![windows_subsystem = "windows"]

mod backend;
mod hello;
mod i18n;
mod icon;
mod picker;
mod platform;

use backend::{ActionResult, AddResult, Shared, Snapshot, EV_NAVIGATE};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use briqwall_common::{util::unhex, Mode, Request, Response, Status};

const TRAY_ID: &str = "main";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Elevated helper mode: apply exactly one request and exit (no window).
    if let Some(i) = args.iter().position(|a| a == "--apply") {
        std::process::exit(apply_helper(args.get(i + 1)));
    }
    let start_in_inbox = args.iter().any(|a| a == "--show");
    let minimized = args.iter().any(|a| a == "--minimized");

    let show_event = match platform::acquire_instance() {
        platform::Instance::Secondary => return,
        platform::Instance::Primary { show_event } => show_event,
    };
    platform::migrate_legacy_user_settings();
    platform::register_shell_integration();
    if platform::ui_pref("FirstRunDone").is_none() {
        let _ = platform::set_autostart(true);
        platform::set_ui_pref("FirstRunDone", 1);
    }

    i18n::set(&language_pref());
    let shared = Shared::new(platform::ui_pref("Notifications").unwrap_or(1) == 1);

    tauri::Builder::default()
        .manage(shared.clone())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            send_request,
            send_requests,
            add_program,
            hello_supported,
            hello_enroll,
            hello_remove,
            ui_prefs,
            set_notifications,
            set_autostart,
            set_language,
            install_service
        ])
        .on_window_event(|window, event| {
            // Closing only hides the window; protection and tray stay.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                static HINT_SHOWN: AtomicBool = AtomicBool::new(false);
                if !HINT_SHOWN.swap(true, Ordering::SeqCst) {
                    let _ = platform::toast(
                        i18n::t("Briqwall schützt weiter im Hintergrund", "Briqwall keeps protecting you in the background"),
                        i18n::t(
                            "Das Symbol im Infobereich zeigt den Status. Rechtsklick für mehr.",
                            "The icon in the notification area shows the status. Right-click for more.",
                        ),
                        None,
                    );
                }
            }
        })
        .setup(move |app| {
            let handle = app.handle().clone();
            build_tray(&handle)?;

            let h = handle.clone();
            backend::spawn_poller(handle.clone(), shared.clone(), Box::new(move |_app, status, connected| update_tray(&h, status, connected)));

            {
                let h = handle.clone();
                let shared = shared.clone();
                platform::spawn_show_listener(show_event, move || {
                    show_main(&h);
                    if shared.pending() > 0 {
                        let _ = h.emit(EV_NAVIGATE, "inbox");
                    }
                });
            }

            if !minimized {
                show_main(&handle);
            }
            if start_in_inbox {
                let h = handle.clone();
                // Give the frontend a moment to register its listener.
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(800));
                    let _ = h.emit(EV_NAVIGATE, "inbox");
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Briqwall UI failed to start");
}

fn apply_helper(hex: Option<&String>) -> i32 {
    let Some(bytes) = hex.and_then(|h| unhex(h)) else { return 2 };
    let Ok(req) = serde_json::from_slice::<Request>(&bytes) else { return 2 };
    match briqwall_common::ipc::call(&req) {
        Ok(Response::Ok) => 0,
        Ok(Response::Denied) => 3,
        _ => 2,
    }
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

// ---------------------------------------------------------------------------
// Tray
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Look {
    Ok,
    Attention,
    Danger,
    Offline,
}

fn tray_image(look: Look) -> Image<'static> {
    let color = match look {
        Look::Ok => [0x1f, 0xa8, 0x62],
        Look::Attention => [0xe0, 0x9a, 0x1f],
        Look::Danger => [0xd6, 0x3b, 0x3b],
        Look::Offline => [0x8a, 0x92, 0xa0],
    };
    Image::new_owned(icon::shield_rgba(32, color, look != Look::Danger), 32, 32)
}

/// Tray menu entries, kept to relabel them when the language changes.
struct TrayItems {
    open: MenuItem<tauri::Wry>,
    inbox: MenuItem<tauri::Wry>,
    lockdown: MenuItem<tauri::Wry>,
    quit: MenuItem<tauri::Wry>,
    /// Last known state, to rebuild the tooltip in the new language.
    last: std::sync::Mutex<(Option<Status>, bool)>,
}

impl TrayItems {
    fn relabel(&self) {
        let _ = self.open.set_text(i18n::t("Briqwall öffnen", "Open Briqwall"));
        let _ = self.inbox.set_text(i18n::t("Anfragen ansehen", "View requests"));
        let _ = self.lockdown.set_text(i18n::t("Notfall-Sperre aktivieren", "Activate lockdown"));
        let _ = self.quit.set_text(i18n::t("Oberfläche beenden (Schutz bleibt aktiv)", "Quit interface (protection stays on)"));
    }
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "", true, None::<&str>)?;
    let inbox = MenuItem::with_id(app, "inbox", "", true, None::<&str>)?;
    let lockdown = MenuItem::with_id(app, "lockdown", "", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "", true, None::<&str>)?;
    let items = TrayItems {
        open: open.clone(),
        inbox: inbox.clone(),
        lockdown: lockdown.clone(),
        quit: quit.clone(),
        last: std::sync::Mutex::new((None, false)),
    };
    items.relabel();
    app.manage(items);
    let menu = Menu::with_items(
        app,
        &[&open, &inbox, &PredefinedMenuItem::separator(app)?, &lockdown, &PredefinedMenuItem::separator(app)?, &quit],
    )?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(tray_image(Look::Offline))
        .tooltip("Briqwall")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "inbox" => {
                show_main(app);
                let _ = app.emit(EV_NAVIGATE, "inbox");
            }
            "lockdown" => {
                let shared = app.state::<Arc<Shared>>().inner().clone();
                std::thread::spawn(move || {
                    backend::send(&shared, &Request::SetMode(Mode::Lockdown));
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn update_tray(app: &AppHandle, status: Option<&Status>, connected: bool) {
    use i18n::t;
    if let Some(items) = app.try_state::<TrayItems>() {
        *items.last.lock().unwrap() = (status.cloned(), connected);
    }
    let (look, tip) = match (status, connected) {
        (Some(s), true) => match s.mode {
            Mode::Off => (Look::Danger, format!("Briqwall – {}", t("ausgeschaltet", "turned off"))),
            Mode::Lockdown => (Look::Danger, format!("Briqwall – {}", t("Notfall-Sperre aktiv", "lockdown active"))),
            _ if s.pending > 0 => {
                (Look::Attention, format!("Briqwall – {} {}", s.pending, t("Anfrage(n) offen", "pending request(s)")))
            }
            m => (Look::Ok, format!("Briqwall – {} ({})", t("geschützt", "protected"), i18n::mode_name(m))),
        },
        _ => (Look::Offline, format!("Briqwall – {}", t("Dienst nicht erreichbar", "service not reachable"))),
    };
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(Some(tray_image(look)));
        let _ = tray.set_tooltip(Some(&tip));
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn snapshot(shared: State<'_, Arc<Shared>>) -> Snapshot {
    shared.snap.lock().unwrap().clone()
}

#[tauri::command]
async fn send_request(req: Request, shared: State<'_, Arc<Shared>>) -> Result<ActionResult, String> {
    let shared = shared.inner().clone();
    tauri::async_runtime::spawn_blocking(move || backend::send(&shared, &req)).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_requests(reqs: Vec<Request>, shared: State<'_, Arc<Shared>>) -> Result<ActionResult, String> {
    let shared = shared.inner().clone();
    tauri::async_runtime::spawn_blocking(move || backend::send_many(&shared, reqs)).await.map_err(|e| e.to_string())
}

/// Pick a program and take it into the list, so a rule can be set for it
/// before it ever asks for the network.
#[tauri::command]
async fn add_program(app: AppHandle, window: tauri::Window, shared: State<'_, Arc<Shared>>) -> Result<AddResult, String> {
    let shared = shared.inner().clone();
    let parent = window.hwnd().map(|h| h.0 as isize).unwrap_or(0);
    // The dialog is modal to the main window, so it has to run on its thread.
    let (tx, rx) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let _ = tx.send(picker::pick_executable(parent));
    })
    .map_err(|e| e.to_string())?;
    let picked = tauri::async_runtime::spawn_blocking(move || rx.recv().ok().flatten()).await.map_err(|e| e.to_string())?;
    let Some(path) = picked else { return Ok(AddResult::Cancelled) };
    tauri::async_runtime::spawn_blocking(move || backend::add_app(&shared, &path)).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn hello_supported() -> bool {
    tauri::async_runtime::spawn_blocking(hello::supported).await.unwrap_or(false)
}

#[tauri::command]
async fn hello_enroll(shared: State<'_, Arc<Shared>>) -> Result<ActionResult, String> {
    let shared = shared.inner().clone();
    tauri::async_runtime::spawn_blocking(move || backend::enroll_hello(&shared)).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn hello_remove(shared: State<'_, Arc<Shared>>) -> Result<ActionResult, String> {
    let shared = shared.inner().clone();
    tauri::async_runtime::spawn_blocking(move || backend::remove_hello(&shared)).await.map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct UiPrefs {
    notifications: bool,
    autostart: bool,
    service_exe_available: bool,
    /// "system", "de" or "en"
    language: String,
    /// Language "system" resolves to.
    system_language: &'static str,
    /// Windows account this UI runs as (SID identifies its Hello key).
    user_sid: String,
    user_name: String,
}

fn language_pref() -> String {
    platform::ui_pref_str("Language").filter(|l| ["system", "de", "en"].contains(&l.as_str())).unwrap_or_else(|| "system".into())
}

#[tauri::command]
fn set_language(lang: String, app: AppHandle) {
    let lang = if ["system", "de", "en"].contains(&lang.as_str()) { lang } else { "system".into() };
    platform::set_ui_pref_str("Language", &lang);
    i18n::set(&lang);
    if let Some(items) = app.try_state::<TrayItems>() {
        items.relabel();
        let (status, connected) = items.last.lock().unwrap().clone();
        update_tray(&app, status.as_ref(), connected);
    }
}

#[tauri::command]
fn ui_prefs(shared: State<'_, Arc<Shared>>) -> UiPrefs {
    let user = platform::current_user();
    UiPrefs {
        notifications: shared.notifications.load(Ordering::Relaxed),
        autostart: platform::autostart_enabled(),
        service_exe_available: service_exe().is_some(),
        language: language_pref(),
        system_language: i18n::system_language(),
        user_sid: user.0,
        user_name: user.1,
    }
}

#[tauri::command]
fn set_notifications(on: bool, shared: State<'_, Arc<Shared>>) {
    shared.notifications.store(on, Ordering::Relaxed);
    platform::set_ui_pref("Notifications", on as u32);
}

#[tauri::command]
fn set_autostart(on: bool) -> Result<(), String> {
    platform::set_autostart(on).map_err(|e| e.to_string())
}

fn service_exe() -> Option<std::path::PathBuf> {
    let p = std::env::current_exe().ok()?.parent()?.join("briqwall-service.exe");
    p.exists().then_some(p)
}

#[tauri::command]
async fn install_service(shared: State<'_, Arc<Shared>>) -> Result<ActionResult, String> {
    let Some(exe) = service_exe() else {
        return Ok(ActionResult::Failed {
            message: i18n::t("briqwall-service.exe nicht gefunden", "briqwall-service.exe not found").into(),
        });
    };
    let shared = shared.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let r = match platform::run_elevated(&exe.to_string_lossy(), "install") {
            platform::ElevationResult::Applied => ActionResult::Done,
            platform::ElevationResult::Cancelled => ActionResult::Cancelled,
            platform::ElevationResult::Failed(m) => ActionResult::Failed { message: m },
        };
        shared.poke.store(true, Ordering::SeqCst);
        r
    })
    .await
    .map_err(|e| e.to_string())
}
