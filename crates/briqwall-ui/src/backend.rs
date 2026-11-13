//! Keeps a copy of the service state and pushes *changes* to the web UI as
//! events, so the frontend never polls and never re-renders without need.

use crate::hello::{self, HelloError};
use crate::i18n::{self, t};
use crate::platform::{self, ElevationResult};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};
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
    /// Set by [`Shared::poke`]; the poller sleeps on it.
    poked: Mutex<bool>,
    wake: Condvar,
    pub notifications: AtomicBool,
}

impl Shared {
    pub fn new(notifications: bool) -> Arc<Self> {
        Arc::new(Self {
            snap: Mutex::new(Snapshot::default()),
            poked: Mutex::new(false),
            wake: Condvar::new(),
            notifications: AtomicBool::new(notifications),
        })
    }

    /// Something changed, or someone is looking: fetch from the service now
    /// instead of at the next regular interval.
    pub fn poke(&self) {
        *self.poked.lock().unwrap() = true;
        self.wake.notify_all();
    }

    /// Sleep for `d`, or until poked. Costs nothing while waiting.
    fn wait(&self, d: Duration) {
        let guard = self.poked.lock().unwrap();
        let (mut poked, _) = self.wake.wait_timeout_while(guard, d, |poked| !*poked).unwrap();
        *poked = false;
    }

    pub fn pending(&self) -> usize {
        self.snap.lock().unwrap().status.as_ref().map_or(0, |s| s.pending)
    }
}

/// Is *this* Windows account set up for Hello approvals? A key from before
/// per-account enrollment (no SID) counts, it was this device's single key.
pub fn hello_enrolled_here(shared: &Shared) -> bool {
    let sid = platform::current_user().0;
    shared.snap.lock().unwrap().status.as_ref().is_some_and(|s| {
        s.hello_users.iter().any(|u| u.sid.is_empty() || u.sid == sid)
    })
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
    shared.poke();
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
    shared.poke();
    r
}

fn confirm(shared: &Shared, reqs: Vec<Request>, combined: &Request) -> ActionResult {
    let enrolled = hello_enrolled_here(shared);
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
    let (sid, name) = platform::current_user();
    let r = uac(&Request::EnrollHello { public_key: briqwall_common::util::hex(&spki), sid, name });
    if !matches!(r, ActionResult::Done) {
        hello::delete_key();
    }
    shared.poke();
    r
}

pub fn remove_hello(shared: &Shared) -> ActionResult {
    let r = send(shared, &Request::RemoveHello { sid: platform::current_user().0 });
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

/// Where the poller stands in the service's numbering of events and app-list
/// revisions. Both start over when the service does (update, crash, reboot
/// of the service only), and its start time tells one instance from the next.
#[derive(Default)]
struct Cursor {
    started: u64,
    last_seq: u64,
    /// Revision and activity count of the app list the frontend has.
    apps_rev: u64,
    apps_activity: u64,
}

/// How long details nobody has to act on (counters, last targets) may lag
/// behind while the window is open.
const ACTIVITY_LAG: Duration = Duration::from_secs(5);
/// Interval while the window is open / hidden in the tray. Hidden, only the
/// tray icon and notifications depend on it.
const POLL_VISIBLE: Duration = Duration::from_millis(1000);
const POLL_HIDDEN: Duration = Duration::from_millis(3000);

/// Fetch the app list now? It is by far the largest answer of the service
/// (hundreds of kilobytes), and every fetch is parsed and rendered again.
///
/// * Nobody looking: no, except for the very first one (the frontend starts
///   from it). What was missed is fetched when the window is shown.
/// * Something to act on changed (apps, rules, requests): right away.
/// * Only counters and the like: at most every [`ACTIVITY_LAG`].
fn apps_wanted(cursor: &Cursor, status: &Status, visible: bool, have_apps: bool, since_fetch: Duration) -> bool {
    if !have_apps {
        return true;
    }
    if !visible {
        return false;
    }
    status.revision != cursor.apps_rev || (status.activity != cursor.apps_activity && since_fetch >= ACTIVITY_LAG)
}

impl Cursor {
    /// Note which service instance answered. `true` if it is a different one
    /// than before: the old positions mean nothing to it and are dropped.
    /// Keeping them would hide every event until the new instance had counted
    /// past the old one's last number – no requests, no notifications.
    fn observe(&mut self, started: u64) -> bool {
        let restarted = self.started != 0 && self.started != started;
        if restarted {
            self.last_seq = 0;
            self.apps_rev = 0;
            self.apps_activity = 0;
        }
        self.started = started;
        restarted
    }
}

fn poll_loop(app: AppHandle, shared: Arc<Shared>, on_status: OnStatus) {
    let mut cursor = Cursor::default();
    let mut first = true;
    let mut request_toasts = RequestToasts::default();
    let mut have_apps = false;
    let mut last_apps_fetch = Instant::now();
    // Hidden in the tray or minimized: nobody sees the app list.
    let window_visible = |app: &AppHandle| {
        app.get_webview_window("main")
            .map(|w| w.is_visible().unwrap_or(true) && !w.is_minimized().unwrap_or(false))
            .unwrap_or(true)
    };
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
                shared.wait(Duration::from_secs(2));
                continue;
            }
        };
        loop {
            let res: anyhow::Result<()> = (|| {
                let Response::Status(status) = client.call(&Request::Status)? else { anyhow::bail!("Status") };
                if cursor.observe(status.started) {
                    // Events of the previous instance carry numbers the new
                    // one hands out again; the frontend drops its copy too
                    // when it sees the numbering start over.
                    shared.snap.lock().unwrap().events.clear();
                }
                let visible = window_visible(&app);
                let apps = if apps_wanted(&cursor, &status, visible, have_apps, last_apps_fetch.elapsed()) {
                    match client.call(&Request::Apps)? {
                        Response::Apps(a) => {
                            cursor.apps_rev = status.revision;
                            cursor.apps_activity = status.activity;
                            have_apps = true;
                            last_apps_fetch = Instant::now();
                            Some(a)
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                let Response::Events(events) = client.call(&Request::Events { after: cursor.last_seq })? else {
                    anyhow::bail!("Events")
                };

                if !first && shared.notifications.load(Ordering::Relaxed) {
                    // The service hands out its log of earlier runs as well;
                    // only what happened in this run is news.
                    let fresh: Vec<&Event> = events.iter().filter(|e| e.time >= status.started).collect();
                    notify(&fresh, &mut request_toasts);
                }
                first = false;
                if let Some((title, body)) = request_toasts.due(Instant::now()) {
                    let _ = platform::toast(&title, &body, Some(t("Entscheiden", "Decide")));
                }
                if let Some(e) = events.last() {
                    cursor.last_seq = e.seq;
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
            shared.wait(if window_visible(&app) { POLL_VISIBLE } else { POLL_HIDDEN });
        }
        shared.wait(Duration::from_millis(500));
    }
}

/// Gathers new requests so that several at once – a program starting its
/// helpers, a stricter level taking effect – become one notification instead
/// of a pile, and so that notifications keep a distance from each other.
#[derive(Default)]
struct RequestToasts {
    /// Name and "high risk" of the requests not yet announced.
    waiting: Vec<(String, bool)>,
    last_shown: Option<Instant>,
}

impl RequestToasts {
    /// Shortest time between two notifications about requests.
    const QUIET: Duration = Duration::from_secs(10);

    fn add(&mut self, name: &str, high_risk: bool) {
        if !self.waiting.iter().any(|(n, _)| n == name) {
            self.waiting.push((name.to_string(), high_risk));
        }
    }

    /// Title and text of the notification to show now, if it is time for one.
    fn due(&mut self, now: Instant) -> Option<(String, String)> {
        if self.waiting.is_empty() || self.last_shown.is_some_and(|at| now.duration_since(at) < Self::QUIET) {
            return None;
        }
        let waiting = std::mem::take(&mut self.waiting);
        self.last_shown = Some(now);
        let high_risk = waiting.iter().any(|(_, high)| *high);
        if let [(name, _)] = waiting.as_slice() {
            let body = if high_risk {
                t("Angehalten – hohes Risiko. Öffnen Sie Briqwall, um zu entscheiden.", "Stopped – high risk. Open Briqwall to decide.")
            } else {
                t(
                    "Briqwall hat die Verbindung angehalten. Klicken Sie, um zu entscheiden.",
                    "Briqwall stopped the connection. Click to decide.",
                )
            };
            return Some((format!("{} {}", quoted(name), t("möchte ins Netz", "wants to go online")), body.to_string()));
        }
        let title = format!("{} {}", waiting.len(), t("Programme möchten ins Netz", "programs want to go online"));
        let mut names: Vec<String> = waiting.iter().take(3).map(|(n, _)| quoted(n)).collect();
        if waiting.len() > 3 {
            names.push("…".into());
        }
        let mut body = names.join(", ");
        if high_risk {
            body.push_str(t(" – darunter mit hohem Risiko", " – some of them high risk"));
        }
        Some((title, body))
    }
}

fn notify(events: &[&Event], requests: &mut RequestToasts) {
    for e in events {
        match &e.kind {
            EventKind::NewRequest { name, risk, .. } => requests.add(name, *risk == Risk::High),
            EventKind::StartedByBlocked { name, by_name, .. } => {
                let _ = platform::toast(
                    &format!("{} {} {}", quoted(by_name), t("hat gestartet:", "started"), quoted(name)),
                    t(
                        "Das startende Programm darf selbst nicht ins Netz. Was es dem gestarteten übergibt, lädt dieses trotzdem.",
                        "The program that started it is not allowed online itself. Whatever it passes on is fetched all the same.",
                    ),
                    Some(t("Ansehen", "View")),
                );
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

/// Typographic quotes matching the UI language.
fn quoted(name: &str) -> String {
    format!("{}{name}{}", t("„", "“"), t("“", "”"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(revision: u64, activity: u64) -> Status {
        Status {
            version: String::new(),
            mode: Mode::Balanced,
            engine_ok: true,
            engine_error: None,
            privileged: false,
            networks: Vec::new(),
            network_trusted: false,
            apps_total: 0,
            apps_allowed: 0,
            apps_blocked: 0,
            pending: 0,
            blocked_session: 0,
            started: 1,
            revision,
            activity,
            settings: Settings::default(),
            hello_users: Vec::new(),
        }
    }

    #[test]
    fn app_list_is_fetched_only_when_someone_can_see_it() {
        let secs = Duration::from_secs;
        let have = Cursor { started: 1, last_seq: 0, apps_rev: 5, apps_activity: 9 };
        // The frontend starts from one list, shown or not.
        assert!(apps_wanted(&Cursor::default(), &status(5, 9), false, false, secs(0)));
        // Up to date.
        assert!(!apps_wanted(&have, &status(5, 9), true, true, secs(60)));
        // A new request or rule: immediately.
        assert!(apps_wanted(&have, &status(6, 9), true, true, secs(0)));
        // Only counters moved: not on every tick …
        assert!(!apps_wanted(&have, &status(5, 10), true, true, secs(1)));
        // … but soon.
        assert!(apps_wanted(&have, &status(5, 10), true, true, secs(5)));
        // Hidden in the tray: nothing, whatever changed.
        assert!(!apps_wanted(&have, &status(6, 10), false, true, secs(600)));
        // Shown again: what was missed is fetched right away.
        assert!(apps_wanted(&have, &status(6, 10), true, true, secs(0)));
        // An older service without the activity count reports 0 forever.
        let old = Cursor { started: 1, last_seq: 0, apps_rev: 5, apps_activity: 0 };
        assert!(!apps_wanted(&old, &status(5, 0), true, true, secs(600)));
        assert!(apps_wanted(&old, &status(6, 0), true, true, secs(0)));
    }

    #[test]
    fn several_requests_become_one_notification() {
        i18n::set("en");
        let t0 = Instant::now();
        let mut toasts = RequestToasts::default();
        assert_eq!(toasts.due(t0), None, "nothing to say");

        // One request: named, as before.
        toasts.add("QuickNotes", false);
        let (title, body) = toasts.due(t0).unwrap();
        assert!(title.contains("QuickNotes") && title.contains("wants to go online"));
        assert!(body.contains("Click to decide"));
        assert_eq!(toasts.due(t0), None, "shown once");

        // A burst right after: held back, then one notification for all.
        for name in ["a", "b", "c", "d", "b"] {
            toasts.add(name, name == "c");
        }
        assert_eq!(toasts.due(t0 + Duration::from_secs(3)), None, "too soon after the last one");
        let (title, body) = toasts.due(t0 + Duration::from_secs(11)).unwrap();
        assert!(title.starts_with("4 programs"), "{title}");
        assert!(body.contains("“a”") && body.contains("“c”") && !body.contains("“d”") && body.contains('…'), "{body}");
        assert!(body.contains("high risk"));
        assert_eq!(toasts.due(t0 + Duration::from_secs(60)), None);

        // High risk on its own keeps its warning.
        toasts.add("Dropper", true);
        assert!(toasts.due(t0 + Duration::from_secs(60)).unwrap().1.contains("high risk"));
    }

    #[test]
    fn a_poke_ends_the_wait() {
        let shared = Shared::new(true);
        let t = Instant::now();
        shared.wait(Duration::from_millis(30));
        assert!(t.elapsed() >= Duration::from_millis(25), "sleeps when nothing happens");

        let s = shared.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            s.poke();
        });
        let t = Instant::now();
        shared.wait(Duration::from_secs(20));
        assert!(t.elapsed() < Duration::from_secs(5), "woken by the poke");

        // A poke that came before the wait is not lost.
        shared.poke();
        let t = Instant::now();
        shared.wait(Duration::from_secs(20));
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn positions_start_over_with_a_new_service_instance() {
        let mut c = Cursor::default();
        assert!(!c.observe(1000), "first contact is not a restart");
        c.last_seq = 742;
        c.apps_rev = 91;
        c.apps_activity = 17;
        assert!(!c.observe(1000), "same instance");
        assert_eq!((c.last_seq, c.apps_rev, c.apps_activity), (742, 91, 17));

        // The service was restarted: it numbers its events from 1 again.
        assert!(c.observe(1300));
        assert_eq!((c.last_seq, c.apps_rev, c.apps_activity), (0, 0, 0), "ask for everything the new instance has");
        c.last_seq = 3;
        assert!(!c.observe(1300));
        assert_eq!(c.last_seq, 3);
    }
}
