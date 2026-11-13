//! Keeps a copy of the service state and pushes *changes* to the web UI as
//! events, so the frontend never polls and never re-renders without need.

use crate::hello::{self, HelloError};
use crate::i18n::{self, t};
use crate::platform::{self, ElevationResult};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use briqwall_common::ipc::Client;
use briqwall_common::*;

pub const EV_STATE: &str = "briqwall://state";
pub const EV_APPS: &str = "briqwall://apps";
pub const EV_EVENTS: &str = "briqwall://events";
pub const EV_NAVIGATE: &str = "briqwall://navigate";

#[derive(Clone, Serialize, Default)]
pub struct ConnState {
    pub connected: bool,
    pub error: Option<String>,
    pub status: Option<Status>,
}

#[derive(Clone, Serialize, Default)]
pub struct Snapshot {
    pub connected: bool,
    pub error: Option<String>,
    pub status: Option<Status>,
    pub apps: Vec<AppInfo>,
    pub events: Vec<Event>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ActionResult {
    Done,
    Cancelled,
    Failed { message: String },
}

/// Outcome of adding a program by hand.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AddResult {
    Added { key: String, existed: bool },
    Cancelled,
    Failed { message: String },
}

pub struct Shared {
    pub snap: Mutex<Snapshot>,
    pub poke: AtomicBool,
    pub notifications: AtomicBool,
}

impl Shared {
    pub fn new(notifications: bool) -> Arc<Self> {
        Arc::new(Self {
            snap: Mutex::new(Snapshot::default()),
            poke: AtomicBool::new(false),
            notifications: AtomicBool::new(notifications),
        })
    }

    pub fn pending(&self) -> usize {
        self.snap.lock().unwrap().status.as_ref().map_or(0, |s| s.pending)
    }
}

pub fn send(shared: &Shared, req: &Request) -> ActionResult {
    send_many(shared, vec![req.clone()])
}

/// Send one or more changes. Tightening changes go through directly. If the
/// service says a change loosens protection, the user confirms *once* for
/// all of them: with Windows Hello if set up, otherwise via UAC.
pub fn send_many(shared: &Shared, reqs: Vec<Request>) -> ActionResult {
    if reqs.is_empty() {
        return ActionResult::Done;
    }
    let combined = if reqs.len() == 1 { reqs[0].clone() } else { Request::Batch(reqs.clone()) };
    let r = match briqwall_common::ipc::call(&combined) {
        Ok(Response::Ok) => ActionResult::Done,
        Ok(Response::Denied) => confirm(shared, reqs, &combined),
        Ok(Response::Error(e)) => ActionResult::Failed { message: i18n::error_text(&e) },
        Ok(_) => ActionResult::Failed { message: i18n::unexpected_response() },
        Err(e) => ActionResult::Failed { message: format!("{e:#}") },
    };
    shared.poke.store(true, Ordering::SeqCst);
    r
}

/// Take a program into the list. This changes nothing about what is allowed,
/// so it needs no confirmation; the rule itself is set afterwards as usual.
pub fn add_app(shared: &Shared, path: &str) -> AddResult {
    let r = match briqwall_common::ipc::call(&Request::AddApp { path: path.to_string() }) {
        Ok(Response::Added { key, existed }) => AddResult::Added { key, existed },
        Ok(Response::Error(e)) => AddResult::Failed { message: i18n::error_text(&e) },
        Ok(_) => AddResult::Failed { message: i18n::unexpected_response() },
        Err(e) => AddResult::Failed { message: format!("{e:#}") },
    };
    shared.poke.store(true, Ordering::SeqCst);
    r
}

fn confirm(shared: &Shared, reqs: Vec<Request>, combined: &Request) -> ActionResult {
    let enrolled = shared.snap.lock().unwrap().status.as_ref().is_some_and(|s| s.hello_enrolled);
    if enrolled {
        match approve_with_hello(&reqs) {
            Ok(()) => return ActionResult::Done,
            Err(HelloError::Cancelled) => return ActionResult::Cancelled,
            // Key missing (other Windows account) or Hello unavailable: fall back to UAC.
            Err(HelloError::NotFound) => {}
            Err(HelloError::Failed(m)) => return ActionResult::Failed { message: m },
        }
    }
    uac(combined)
}

pub fn uac(req: &Request) -> ActionResult {
    match platform::apply_elevated(req) {
        ElevationResult::Applied => ActionResult::Done,
        ElevationResult::Cancelled => ActionResult::Cancelled,
        ElevationResult::Failed(m) => ActionResult::Failed { message: m },
    }
}

fn approve_with_hello(reqs: &[Request]) -> Result<(), HelloError> {
    let fail = |m: String| HelloError::Failed(m);
    let payload = serde_json::to_string(reqs).map_err(|e| fail(e.to_string()))?;
    let nonce = match briqwall_common::ipc::call(&Request::Challenge) {
        Ok(Response::Challenge(n)) => n,
        Ok(Response::Error(e)) => return Err(fail(i18n::error_text(&e))),
        Ok(_) => return Err(fail(i18n::unexpected_response())),
        Err(e) => return Err(fail(format!("{e:#}"))),
    };
    let signature = hello::sign(&approval_message(&nonce, &payload))?;
    let req = Request::Approved { nonce, payload, signature: briqwall_common::util::hex(&signature) };
    match briqwall_common::ipc::call(&req) {
        Ok(Response::Ok) => Ok(()),
        Ok(Response::Denied) => Err(fail(t("Die Bestätigung war ungültig.", "The confirmation was invalid.").into())),
        Ok(Response::Error(e)) => Err(fail(i18n::error_text(&e))),
        Ok(_) => Err(fail(i18n::unexpected_response())),
        Err(e) => Err(fail(format!("{e:#}"))),
    }
}

/// Create a Hello key and register it with the service (one UAC prompt).
pub fn enroll_hello(shared: &Shared) -> ActionResult {
    let spki = match hello::create_key() {
        Ok(k) => k,
        Err(HelloError::Cancelled) => return ActionResult::Cancelled,
        Err(HelloError::NotFound) => {
            return ActionResult::Failed {
                message: t("Windows Hello ist auf diesem Konto nicht eingerichtet.", "Windows Hello is not set up for this account.")
                    .into(),
            }
        }
        Err(HelloError::Failed(m)) => return ActionResult::Failed { message: m },
    };
    let r = uac(&Request::EnrollHello { public_key: briqwall_common::util::hex(&spki) });
    if !matches!(r, ActionResult::Done) {
        hello::delete_key();
    }
    shared.poke.store(true, Ordering::SeqCst);
    r
}

pub fn remove_hello(shared: &Shared) -> ActionResult {
    let r = send(shared, &Request::RemoveHello);
    if matches!(r, ActionResult::Done) {
        hello::delete_key();
    }
    r
}

/// Callback when the protection state changes (used for the tray icon).
pub type OnStatus = Box<dyn Fn(&AppHandle, Option<&Status>, bool) + Send>;

pub fn spawn_poller(app: AppHandle, shared: Arc<Shared>, on_status: OnStatus) {
    std::thread::Builder::new()
        .name("poller".into())
        .spawn(move || poll_loop(app, shared, on_status))
        .expect("spawn poller");
}

fn poll_loop(app: AppHandle, shared: Arc<Shared>, on_status: OnStatus) {
    let mut last_seq = 0u64;
    let mut apps_rev = 0u64;
    let mut first = true;
    let mut last_state_json = String::new();

    let mut publish_state = |app: &AppHandle, st: ConnState| {
        let json = serde_json::to_string(&st).unwrap_or_default();
        if json != last_state_json {
            last_state_json = json;
            on_status(app, st.status.as_ref(), st.connected);
            let _ = app.emit(EV_STATE, &st);
        }
    };

    loop {
        let mut client = match Client::connect() {
            Ok(c) => c,
            Err(e) => {
                let err = format!("{e:#}");
                {
                    let mut s = shared.snap.lock().unwrap();
                    s.connected = false;
                    s.error = Some(err.clone());
                }
                publish_state(&app, ConnState { connected: false, error: Some(err), status: None });
                sleep_or_poke(&shared, Duration::from_secs(2));
                continue;
            }
        };
        loop {
            let res: anyhow::Result<()> = (|| {
                let Response::Status(status) = client.call(&Request::Status)? else { anyhow::bail!("Status") };
                let apps = if status.revision != apps_rev {
                    match client.call(&Request::Apps)? {
                        Response::Apps(a) => Some(a),
                        _ => None,
                    }
                } else {
                    None
                };
                let Response::Events(events) = client.call(&Request::Events { after: last_seq })? else {
                    anyhow::bail!("Events")
                };
                apps_rev = status.revision;

                if !first && shared.notifications.load(Ordering::Relaxed) {
                    notify(&events);
                }
                first = false;
                if let Some(e) = events.last() {
                    last_seq = e.seq;
                }

                {
                    let mut s = shared.snap.lock().unwrap();
                    s.connected = true;
                    s.error = None;
                    s.status = Some((*status).clone());
                    if let Some(a) = &apps {
                        s.apps = a.clone();
                    }
                    s.events.extend(events.iter().cloned());
                    let n = s.events.len();
                    if n > 500 {
                        s.events.drain(..n - 500);
                    }
                }
                publish_state(&app, ConnState { connected: true, error: None, status: Some(*status) });
                if let Some(a) = apps {
                    let _ = app.emit(EV_APPS, &a);
                }
                if !events.is_empty() {
                    let _ = app.emit(EV_EVENTS, &events);
                }
                Ok(())
            })();
            if let Err(e) = res {
                let err = format!("{e:#}");
                shared.snap.lock().unwrap().connected = false;
                publish_state(&app, ConnState { connected: false, error: Some(err), status: None });
                break;
            }
            sleep_or_poke(&shared, Duration::from_millis(1000));
        }
        sleep_or_poke(&shared, Duration::from_millis(500));
    }
}

fn notify(events: &[Event]) {
    for e in events {
        match &e.kind {
            EventKind::NewRequest { name, risk, .. } => {
                let body = match risk {
                    Risk::High => t(
                        "Angehalten – hohes Risiko. Öffnen Sie Briqwall, um zu entscheiden.",
                        "Stopped – high risk. Open Briqwall to decide.",
                    ),
                    _ => t(
                        "Briqwall hat die Verbindung angehalten. Klicken Sie, um zu entscheiden.",
                        "Briqwall stopped the connection. Click to decide.",
                    ),
                };
                let title = format!("{} {}", quoted(name), t("möchte ins Netz", "wants to go online"));
                let _ = platform::toast(&title, body, Some(t("Entscheiden", "Decide")));
            }
            EventKind::Tampered { name, .. } => {
                let _ = platform::toast(
                    &format!("{} {}", quoted(name), t("wurde verändert", "was modified")),
                    t("Die Freigabe wurde vorsorglich ausgesetzt.", "Its permission was suspended as a precaution."),
                    Some(t("Ansehen", "View")),
                );
            }
            _ => {}
        }
    }
}

fn sleep_or_poke(shared: &Shared, d: Duration) {
    let until = Instant::now() + d;
    while Instant::now() < until {
        if shared.poke.swap(false, Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Typographic quotes matching the UI language.
fn quoted(name: &str) -> String {
    format!("{}{name}{}", t("„", "“"), t("“", "”"))
}
