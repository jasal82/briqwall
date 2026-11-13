//! Briqwall firewall service.
//!
//! Usage:
//!   briqwall-service install        register + start the Windows service (admin)
//!   briqwall-service uninstall      stop, unregister, remove all WFP objects (admin)
//!   briqwall-service reset          emergency: remove all Briqwall filters (admin)
//!   briqwall-service console        run in the foreground (debugging)
//!   briqwall-service check <exe>    show how Briqwall would classify a file

mod compiler;
mod cli_text;
mod core;
mod dns;
mod hello;
mod ipc_server;
mod policy;
mod procinfo;
mod store;
mod trust;
mod watchers;
mod wfp;

use crate::core::{Core, Msg};
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceDependency,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};
use briqwall_common::util::is_elevated;
use cli_text::t;
use briqwall_common::{SERVICE_DISPLAY_NAME, SERVICE_NAME};

fn main() {
    // Umlauts and dashes in CLI output: switch the console to UTF-8.
    unsafe {
        let _ = windows::Win32::System::Console::SetConsoleOutputCP(65001);
    }
    let args: Vec<String> = std::env::args().collect();
    let res = match args.get(1).map(String::as_str) {
        Some("service") => service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("service dispatcher"),
        Some("console") => run_console(),

        Some("install") => install(),
        Some("uninstall") => uninstall(args.iter().any(|a| a == "--purge")),
        Some("reset") => reset(),
        Some("check") if args.len() > 2 => check(&args[2]),
        _ => {
            eprintln!("{}", cli_text::usage(briqwall_common::VERSION));
            Ok(())
        }
    };
    if let Err(e) = res {
        eprintln!("{} {e:#}", t("Fehler:", "Error:"));
        log::error!("{e:#}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

fn open_engine() -> Result<wfp::Engine> {
    let e = wfp::Engine::open()?;
    e.ensure_objects()?;
    Ok(e)
}

/// Bring up all components; returns the core thread handle.
fn start(tx: Sender<Msg>, rx: Receiver<Msg>, echo: bool) -> Result<std::thread::JoinHandle<()>> {
    let elevated = is_elevated();
    let dir = store::data_dir(elevated);
    let dir_notes = store::prepare_dir(&dir, elevated)?;
    store::init_logging(&dir, echo);
    for note in dir_notes {
        log::warn!("{note}");
    }
    store::migrate_legacy(&dir, elevated);
    log::info!("Briqwall {} startet (Daten: {}, erhöht: {elevated})", briqwall_common::VERSION, dir.display());

    let mut audit_enabled = Vec::new();
    let engine = match open_engine() {
        Ok(e) => {
            audit_enabled = watchers::ensure_audit_policy();
            if let Err(err) = e.enable_net_events() {
                log::warn!("{err:#}");
            }
            // Leaked: the context must outlive the subscription (= the process).
            let ctx: &'static watchers::NetEventCtx = Box::leak(Box::new(watchers::NetEventCtx { tx: tx.clone() }));
            match e.subscribe(Some(watchers::net_event_callback), ctx as *const _ as *const _) {
                Ok(_) => log::info!("WFP-Ereignisse abonniert"),
                Err(err) => log::warn!("Keine Verbindungs-Ereignisse: {err:#}"),
            }
            match watchers::subscribe_drop_audit(tx.clone()) {
                Ok(()) => log::info!("Audit-Ereignis 5157 abonniert (Prozess-Herkunft)"),
                Err(err) => log::warn!("Keine Prozess-Herkunft: {err:#}"),
            }
            match dns::start() {
                Ok(()) => log::info!("DNS-Client-Ereignisse abonniert (Hostnamen)"),
                Err(err) => log::warn!("Keine Hostnamen: {err:#}"),
            }
            Ok(e)
        }
        Err(e) => {
            log::error!("WFP nicht verfügbar – nur Anzeige-Modus: {e:#}");
            Err(format!("{e:#}"))
        }
    };

    let handle = std::thread::Builder::new().name("core".into()).spawn(move || {
        let mut core = Core::new(dir, engine);
        core.note_audit_enabled(audit_enabled);
        core.run(rx);
    })?;
    watchers::spawn_process_watcher(tx.clone());
    ipc_server::spawn(tx);
    Ok(handle)
}

fn run_console() -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let handle = start(tx, rx, true)?;
    eprintln!("{}", t("Briqwall läuft im Vordergrund. Beenden mit Strg+C (Filter bleiben aktiv).", "Briqwall is running in the foreground. Stop with Ctrl+C (filters stay active)."));
    let _ = handle.join();
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows service
// ---------------------------------------------------------------------------

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        log::error!("Dienst-Fehler: {e:#}");
    }
}

fn run_service() -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let ctl_tx = tx.clone();
    let status = service_control_handler::register(SERVICE_NAME, move |ctrl| match ctrl {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = ctl_tx.send(Msg::Shutdown);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let set = |state: ServiceState, accept: ServiceControlAccept, wait: u64| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(wait),
            process_id: None,
        });
    };
    set(ServiceState::StartPending, ServiceControlAccept::empty(), 30);
    let handle = start(tx, rx, false)?;
    set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0);
    let _ = handle.join();
    set(ServiceState::Stopped, ServiceControlAccept::empty(), 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Management commands
// ---------------------------------------------------------------------------

fn require_admin() -> Result<()> {
    if !is_elevated() {
        anyhow::bail!("{}", t("Dieser Befehl benötigt Administratorrechte (Eingabeaufforderung „Als Administrator ausführen“).", "This command requires administrator rights (\"Run as administrator\")."));
    }
    Ok(())
}

/// Exit code of `install` when the executable lies where non-administrators
/// can replace it (the interface shows a matching message).
const EXIT_UNPROTECTED: i32 = 5;

fn install() -> Result<()> {
    require_admin()?;
    let exe = std::env::current_exe()?;
    // The service runs as SYSTEM from exactly this file. Registered from a
    // folder a normal user can write to, that user – or any program running
    // as them – could swap the file and own the machine.
    if !trust::is_protected(&exe.to_string_lossy()) {
        eprintln!(
            "{} {}",
            t("Fehler:", "Error:"),
            t(
                "Der Dienst wird nur aus einem Ordner eingerichtet, in den ausschließlich Administratoren schreiben dürfen (z. B. C:\\Program Files\\Briqwall). Bitte den Installer oder scripts\\install.ps1 verwenden.",
                "The service is only set up from a folder that only administrators can write to (e.g. C:\\Program Files\\Briqwall). Please use the installer or scripts\\install.ps1.",
            )
        );
        eprintln!("  {}", exe.display());
        std::process::exit(EXIT_UNPROTECTED);
    }
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec!["service".into()],
        dependencies: vec![ServiceDependency::Service("BFE".into())],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = match manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START) {
        Ok(s) => s,
        Err(_) => {
            println!("{}", t("Dienst existiert bereits – wird aktualisiert und gestartet.", "Service already exists – updating and starting it."));
            let s = manager.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
            s.change_config(&info)?;
            s
        }
    };
    svc.set_description("Anwendungsbasierte Firewall auf Basis der Windows Filtering Platform.")?;
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(2) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
        ]),
    })?;
    let _ = svc.start::<&str>(&[]);
    println!("{}", t("Briqwall-Dienst installiert und gestartet.", "Briqwall service installed and started."));
    Ok(())
}

fn uninstall(purge: bool) -> Result<()> {
    require_admin()?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    if let Ok(svc) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        let _ = svc.stop();
        for _ in 0..50 {
            match svc.query_status() {
                Ok(s) if s.current_state == ServiceState::Stopped => break,
                Err(_) => break,
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        }
        svc.delete()?;
        println!("{}", t("Dienst entfernt.", "Service removed."));
    }
    let dir = store::data_dir(true);
    let state = store::load(&dir);
    let engine = open_engine()?;
    engine.uninstall()?;
    println!("{}", t("Alle WFP-Filter, Sublayer und Provider von Briqwall entfernt.", "Removed all Briqwall WFP filters, sublayer and provider."));
    let ours = state.audit_to_revert();
    if !ours.is_empty() {
        watchers::revert_audit_policy(&ours);
        println!("{}", t("Audit-Richtlinie zurückgesetzt.", "Audit policy restored."));
    }
    if purge {
        let _ = std::fs::remove_dir_all(&dir);
        println!("{} ({})", t("Daten gelöscht", "Data deleted"), dir.display());
    }
    Ok(())
}

fn reset() -> Result<()> {
    require_admin()?;
    let engine = open_engine()?;
    let n = engine.transaction(|e| e.purge_filters())?;
    println!("{n} {}", t("Briqwall-Filter entfernt. Achtung: ein laufender Dienst setzt sie beim nächsten Neuaufbau wieder.", "Briqwall filters removed. Note: a running service recreates them on its next rebuild."));
    Ok(())
}

fn check(path: &str) -> Result<()> {
    let win = trust::windows_dir();
    let f = trust::gather(path, &win);
    let row = |de: &'static str, en: &'static str| format!("{:<14}", format!("{}:", t(de, en)));
    println!("{}{path}", row("Datei", "File"));
    println!("{}{}", row("Name", "Name"), f.name);
    println!("{}{}", row("Existiert", "Exists"), f.exists);
    println!("{}{:?}", row("Signatur", "Signature"), f.signature);
    println!("{}{} ({})", row("Geschützt", "Protected"), f.protected, t("nur Admins/System können schreiben", "only admins/system can write"));
    println!("{}{:?}", row("Kategorie", "Category"), f.category);
    println!("{}{:?}", row("Ort", "Location"), f.location_hint);
    for mode in [briqwall_common::Mode::Relaxed, briqwall_common::Mode::Balanced, briqwall_common::Mode::Strict] {
        let v = policy::auto_verdict(&policy::Inputs {
            category: f.category,
            signature: &f.signature,
            mode,
            learned: &[],
            lan_discovery: true,
            protected: f.protected,
            location: f.location_hint,
        });
        println!("{:<14}{}={:?} {}={:?} – {:?}", format!("{}:", cli_text::mode_name(mode)), t("aus", "out"), v.out, t("ein", "in"), v.inn, v.reason);
    }
    Ok(())
}
