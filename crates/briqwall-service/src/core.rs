//! The service core: a single-threaded actor that owns all state.
//! Every input (process starts, WFP drop events, IPC requests, timers) arrives
//! as a [`Msg`], so no locking is needed.

use crate::compiler::{self, Compiled, DirPolicy, Purpose};
use crate::hello;
use crate::policy::{self, Inputs};
use crate::store::{self, State};
use crate::trust;
use crate::watchers::{self, Coalescer, DevMap, NetEvt, NetworkWatcher};
use crate::wfp::{self, Engine};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};
use briqwall_common::*;

pub enum Msg {
    Process { path: String },
    Net(NetEvt),
    Ipc { req: Request, privileged: bool, reply: Sender<Response> },
    Shutdown,
}

const MAX_EVENTS: usize = 1000;
const SNOOZE_SECS: u64 = 24 * 3600;
const PRUNE_AFTER_SECS: u64 = 90 * 24 * 3600;
const CHALLENGE_TTL: Duration = Duration::from_secs(120);

pub struct Core {
    dir: PathBuf,
    state: State,
    engine: Option<Engine>,
    engine_error: Option<String>,
    app_filter_ids: HashMap<String, Vec<u64>>,
    purposes: HashMap<u64, Purpose>,
    app_id_cache: HashMap<String, Vec<u8>>,
    events: VecDeque<Event>,
    seq: u64,
    networks: Vec<NetworkInfo>,
    network_trusted: bool,
    devmap: DevMap,
    revision: u64,
    dirty: bool,
    last_save: Instant,
    blocked_session: u64,
    coalescer: Coalescer,
    started: u64,
    win_dir: String,
    netwatch: NetworkWatcher,
    last_net_check: Instant,
    /// During startup, per-app filter updates are skipped; one rebuild follows.
    defer_apply: bool,
    /// Outstanding Windows Hello challenges (single use, short lived).
    challenges: HashMap<String, Instant>,
}

impl Core {
    pub fn new(dir: PathBuf, engine: Result<Engine, String>) -> Self {
        let mut state = store::load(&dir);
        let now = now_secs();
        state.apps.retain(|_, a| a.rule.is_some() || now.saturating_sub(a.last_seen) < PRUNE_AFTER_SECS);

        let (engine, engine_error) = match engine {
            Ok(e) => (Some(e), None),
            Err(e) => (None, Some(e)),
        };
        let mut devmap = DevMap::default();
        devmap.refresh();

        let mut core = Self {
            dir,
            state,
            engine,
            engine_error,
            app_filter_ids: HashMap::new(),
            purposes: HashMap::new(),
            app_id_cache: HashMap::new(),
            events: VecDeque::new(),
            seq: 0,
            networks: Vec::new(),
            network_trusted: false,
            devmap,
            revision: 1,
            dirty: false,
            last_save: Instant::now(),
            blocked_session: 0,
            coalescer: Coalescer::default(),
            started: now,
            win_dir: trust::windows_dir(),
            netwatch: NetworkWatcher::new(),
            last_net_check: Instant::now() - Duration::from_secs(60),
            defer_apply: true,
            challenges: HashMap::new(),
        };
        core.observe_pseudo("System", &wfp::system_app_id());
        // Evaluate everything that is already running *before* the first rebuild,
        // so the default block never hits legitimate apps on first start.
        let t = Instant::now();
        for pid in watchers::list_pids() {
            if let Some(path) = watchers::process_path(pid) {
                core.observe(&path);
            }
        }
        log::info!("{} laufende Programme in {} ms bewertet", core.state.apps.len(), t.elapsed().as_millis());
        core.reevaluate_all();
        core.refresh_networks(false);
        core.rebuild();
        core.defer_apply = false;
        core.push(EventKind::Started { version: VERSION.into(), mode: core.state.settings.mode });
        core
    }

    pub fn set_audit_enabled_by_us(&mut self, v: bool) {
        if v && !self.state.audit_enabled_by_us {
            self.state.audit_enabled_by_us = true;
            self.dirty = true;
        }
    }

    pub fn run(mut self, rx: Receiver<Msg>) {
        loop {
            match rx.recv_timeout(Duration::from_millis(1000)) {
                Ok(Msg::Shutdown) => break,
                Ok(msg) => self.handle(msg),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            // Drain bursts before running timers.
            while let Ok(msg) = rx.try_recv() {
                if matches!(msg, Msg::Shutdown) {
                    self.save();
                    return;
                }
                self.handle(msg);
            }
            self.tick();
        }
        self.save();
        log::info!("Kern beendet");
    }

    fn handle(&mut self, msg: Msg) {
        match msg {
            Msg::Process { path } => {
                self.observe(&path);
            }
            Msg::Net(evt) => self.on_net_event(evt),
            Msg::Ipc { req, privileged, reply } => {
                let resp = self.on_request(req, privileged);
                let _ = reply.send(resp);
            }
            Msg::Shutdown => {}
        }
    }

    fn tick(&mut self) {
        let now = now_secs();
        // Expire temporary rules.
        let expired: Vec<String> = self
            .state
            .apps
            .values()
            .filter(|a| a.rule.as_ref().and_then(|r| r.expires).is_some_and(|t| t <= now))
            .map(|a| a.key.clone())
            .collect();
        for key in expired {
            if let Some(app) = self.state.apps.get_mut(&key) {
                app.rule = None;
                let name = app.name.clone();
                self.push(EventKind::RuleExpired { key: key.clone(), name });
                self.reevaluate(&key);
                self.apply_app(&key);
            }
        }
        if self.last_net_check.elapsed() > Duration::from_secs(5) {
            self.refresh_networks(true);
        }
        if self.dirty && self.last_save.elapsed() > Duration::from_secs(2) {
            self.save();
        }
    }

    fn save(&mut self) {
        if let Err(e) = store::save(&self.dir, &self.state) {
            log::error!("Speichern fehlgeschlagen: {e:#}");
        }
        self.dirty = false;
        self.last_save = Instant::now();
    }

    fn push(&mut self, kind: EventKind) {
        self.seq += 1;
        self.events.push_back(Event { seq: self.seq, time: now_secs(), kind });
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    fn changed(&mut self) {
        self.revision += 1;
        self.dirty = true;
    }

    // -----------------------------------------------------------------------
    // Evaluation
    // -----------------------------------------------------------------------

    /// Mode used for evaluating apps. Lockdown/Off are global overrides and
    /// keep the per-app picture of the mode the user came from.
    fn policy_mode(&self) -> Mode {
        match self.state.settings.mode {
            Mode::Off | Mode::Lockdown => match self.state.settings.previous_mode {
                Mode::Off | Mode::Lockdown => Mode::Balanced,
                m => m,
            },
            m => m,
        }
    }

    fn evaluate(&self, app: &mut AppInfo) {
        let s = &self.state.settings;
        let v = policy::auto_verdict(&Inputs {
            category: app.category,
            signature: &app.signature,
            mode: self.policy_mode(),
            learned: &s.learned_publishers,
            lan_discovery: s.lan_discovery,
        });
        app.auto_out = v.out;
        app.auto_in = v.inn;
        app.reason = v.reason;
        let (o, i) = policy::effective(app);
        app.effective_out = o;
        app.effective_in = i;
        app.risk = policy::risk(app, &s.learned_publishers);
        if app.effective_out != Access::Ask {
            app.pending = false;
        }
    }

    fn reevaluate(&mut self, key: &str) {
        if let Some(mut app) = self.state.apps.remove(key) {
            self.evaluate(&mut app);
            self.state.apps.insert(key.to_string(), app);
        }
    }

    fn reevaluate_all(&mut self) {
        let keys: Vec<String> = self.state.apps.keys().cloned().collect();
        for k in keys {
            self.reevaluate(&k);
        }
        self.changed();
    }

    // -----------------------------------------------------------------------
    // Observation
    // -----------------------------------------------------------------------

    /// Called for every new process and every blocked connection. Returns the app key.
    fn observe(&mut self, path: &str) -> String {
        let key = path.to_lowercase();
        let now = now_secs();
        if let Some(app) = self.state.apps.get_mut(&key) {
            if now.saturating_sub(app.last_seen) > 3600 {
                app.last_seen = now;
                self.dirty = true;
            }
            let stamp = trust::file_stamp(path);
            if stamp.is_some() && stamp != app.file_stamp {
                self.refresh_facts(&key, path);
            }
            return key;
        }

        let f = trust::gather(path, &self.win_dir);
        let mut app = AppInfo {
            key: key.clone(),
            path: path.to_string(),
            name: f.name,
            signature: f.signature,
            category: f.category,
            protected: f.protected,
            location_hint: f.location_hint,
            first_seen: now,
            last_seen: now,
            last_blocked: None,
            blocked_count: 0,
            inbound_blocked_count: 0,
            last_remote: None,
            rule: None,
            auto_out: Access::Ask,
            auto_in: Access::Block,
            reason: Reason::Unknown,
            effective_out: Access::Ask,
            effective_in: Access::Block,
            risk: Risk::Medium,
            pending: false,
            snoozed_until: None,
            tampered: false,
            identity: None,
            file_stamp: f.stamp,
            raw_app_id: None,
        };
        self.evaluate(&mut app);
        log::debug!("Neue App {} → {:?} ({:?})", app.path, app.effective_out, app.reason);
        if app.category == Category::UserSpace && app.effective_out == Access::Allow {
            self.push(EventKind::AutoAllowed { key: key.clone(), name: app.name.clone(), reason: app.reason.clone() });
        }
        self.state.apps.insert(key.clone(), app);
        self.apply_app(&key);
        self.changed();
        key
    }

    fn observe_pseudo(&mut self, name: &str, blob: &[u8]) -> String {
        let key = format!("pseudo:{}", name.to_lowercase());
        if self.state.apps.contains_key(&key) {
            return key;
        }
        let now = now_secs();
        let mut app = AppInfo {
            key: key.clone(),
            path: name.to_string(),
            name: if name.eq_ignore_ascii_case("system") { "Windows-Kernel (System)".into() } else { name.into() },
            signature: Signature::Unknown,
            category: Category::Pseudo,
            protected: true,
            location_hint: None,
            first_seen: now,
            last_seen: now,
            last_blocked: None,
            blocked_count: 0,
            inbound_blocked_count: 0,
            last_remote: None,
            rule: None,
            auto_out: Access::Allow,
            auto_in: Access::Block,
            reason: Reason::Unknown,
            effective_out: Access::Allow,
            effective_in: Access::Block,
            risk: Risk::Low,
            pending: false,
            snoozed_until: None,
            tampered: false,
            identity: None,
            file_stamp: None,
            raw_app_id: Some(blob.to_vec()),
        };
        self.evaluate(&mut app);
        self.state.apps.insert(key.clone(), app);
        self.apply_app(&key);
        self.changed();
        key
    }

    /// The file behind a known app changed (update or replacement).
    fn refresh_facts(&mut self, key: &str, path: &str) {
        let f = trust::gather(path, &self.win_dir);
        let Some(mut app) = self.state.apps.remove(key) else { return };
        app.name = f.name;
        app.signature = f.signature;
        app.category = f.category;
        app.protected = f.protected;
        app.location_hint = f.location_hint;
        app.file_stamp = f.stamp;
        self.app_id_cache.remove(key);

        let grants_access = app
            .rule
            .as_ref()
            .is_some_and(|r| matches!(r.outbound, RuleAccess::Allow | RuleAccess::Lan) || matches!(r.inbound, RuleAccess::Allow | RuleAccess::Lan));
        if grants_access && !app.tampered {
            if let Some(expected) = &app.identity {
                let now_id = trust::identity(path, &app.signature);
                if now_id.as_ref() != Some(expected) {
                    log::warn!("Manipulation erkannt: {path} ({expected} → {now_id:?})");
                    app.tampered = true;
                    self.push(EventKind::Tampered { key: key.to_string(), name: app.name.clone() });
                }
            }
        }
        self.evaluate(&mut app);
        if app.tampered && app.effective_out == Access::Ask {
            app.pending = true;
        }
        self.state.apps.insert(key.to_string(), app);
        self.apply_app(key);
        self.changed();
    }

    fn on_net_event(&mut self, evt: NetEvt) {
        let Some(purpose) = self.purposes.get(&evt.filter_id).cloned() else {
            return; // dropped by someone else (e.g. Windows Firewall)
        };
        let (dir, by_rule) = match purpose {
            Purpose::DefaultBlock(d) => (d, false),
            Purpose::AppBlock(_, d) | Purpose::Lockdown(d) => (d, true),
            Purpose::Other => return,
        };
        self.blocked_session += 1;

        let id = wfp::app_id_to_string(&evt.app_id);
        let key = if id.starts_with("\\device\\") {
            match self.devmap.to_dos(&id) {
                Some(p) => self.observe(&p),
                None => return,
            }
        } else if id.is_empty() {
            return;
        } else {
            self.observe_pseudo(&id, &evt.app_id)
        };

        let remote = match evt.remote {
            Some(ip) => {
                let port = if dir == Direction::Out { evt.remote_port } else { evt.local_port };
                let label = port_label(evt.proto, port).map(|l| format!(" ({l})")).unwrap_or_default();
                if ip.is_ipv6() { format!("[{ip}]:{port}{label}") } else { format!("{ip}:{port}{label}") }
            }
            None => "unbekannt".into(),
        };

        let now = now_secs();
        let mut new_request = None;
        let name;
        {
            let Some(app) = self.state.apps.get_mut(&key) else { return };
            name = app.name.clone();
            match dir {
                Direction::Out => {
                    app.blocked_count = app.blocked_count.saturating_add(1);
                    app.last_blocked = Some(now);
                    app.last_remote = Some(remote.clone());
                    let snoozed = app.snoozed_until.is_some_and(|t| now < t);
                    if !by_rule && app.effective_out == Access::Ask && !app.pending && !snoozed {
                        app.pending = true;
                        new_request = Some(app.risk);
                    }
                }
                Direction::In => {
                    app.inbound_blocked_count = app.inbound_blocked_count.saturating_add(1);
                }
            }
        }
        self.dirty = true;
        if let Some(risk) = new_request {
            self.push(EventKind::NewRequest { key: key.clone(), name: name.clone(), risk });
            self.revision += 1;
        }
        let dkey = format!("{key}|{dir:?}|{remote}");
        if self.coalescer.should_log(&dkey, Duration::from_secs(30)) {
            self.push(EventKind::Blocked { key, name, remote, direction: dir, by_rule });
            self.revision += 1;
        }
    }

    // -----------------------------------------------------------------------
    // Filters
    // -----------------------------------------------------------------------

    fn app_id_for(&mut self, key: &str) -> Option<Vec<u8>> {
        let app = self.state.apps.get(key)?;
        if let Some(raw) = &app.raw_app_id {
            return Some(raw.clone());
        }
        if let Some(id) = self.app_id_cache.get(key) {
            return Some(id.clone());
        }
        let path = app.path.clone();
        match wfp::app_id_for_path(&path) {
            Ok(id) => {
                self.app_id_cache.insert(key.to_string(), id.clone());
                Some(id)
            }
            Err(_) => None, // file gone; nothing to filter
        }
    }

    fn compile_app(&mut self, key: &str) -> Compiled {
        if self.engine.is_none() {
            return Vec::new();
        }
        let Some(id) = self.app_id_for(key) else { return Vec::new() };
        let Some(app) = self.state.apps.get(key) else { return Vec::new() };
        compiler::app_filters(
            key,
            &app.name,
            &id,
            DirPolicy { access: app.effective_out, explicit: policy::explicit(app, true) },
            DirPolicy { access: app.effective_in, explicit: policy::explicit(app, false) },
            self.state.settings.mode,
            self.network_trusted,
        )
    }

    /// Incrementally replace the filters of one app (atomic).
    fn apply_app(&mut self, key: &str) {
        if self.defer_apply {
            return;
        }
        let compiled = self.compile_app(key);
        let Some(engine) = &self.engine else { return };
        let old = self.app_filter_ids.get(key).cloned().unwrap_or_default();
        if old.is_empty() && compiled.is_empty() {
            return;
        }
        let res = engine.transaction(|e| {
            for id in &old {
                e.delete_filter(*id);
            }
            let mut added = Vec::new();
            for (spec, purpose) in &compiled {
                added.push((e.add_filter(spec)?, purpose.clone()));
            }
            Ok(added)
        });
        match res {
            Ok(added) => {
                for id in &old {
                    self.purposes.remove(id);
                }
                let ids = added.iter().map(|(id, _)| *id).collect();
                for (id, p) in added {
                    self.purposes.insert(id, p);
                }
                self.app_filter_ids.insert(key.to_string(), ids);
            }
            Err(e) => log::error!("Filter für {key} konnten nicht gesetzt werden: {e:#}"),
        }
    }

    /// Replace *all* Briqwall filters in one transaction. There is never a moment
    /// without protection.
    fn rebuild(&mut self) {
        if self.engine.is_none() {
            return;
        }
        let started = Instant::now();
        let mode = self.state.settings.mode;
        let base = compiler::base_filters(mode);
        let keys: Vec<String> = self.state.apps.keys().cloned().collect();
        let mut per_app: Vec<(String, Compiled)> = Vec::new();
        for k in keys {
            let c = self.compile_app(&k);
            if !c.is_empty() {
                per_app.push((k, c));
            }
        }
        let engine = self.engine.as_ref().unwrap();
        let res = engine.transaction(|e| {
            let purged = e.purge_filters()?;
            let mut base_ids = Vec::new();
            for (spec, p) in &base {
                base_ids.push((e.add_filter(spec)?, p.clone()));
            }
            let mut app_ids = Vec::new();
            for (key, compiled) in &per_app {
                let mut ids = Vec::new();
                for (spec, p) in compiled {
                    match e.add_filter(spec) {
                        Ok(id) => ids.push((id, p.clone())),
                        // One broken app must not take down the whole policy.
                        Err(err) => log::warn!("{err:#}"),
                    }
                }
                app_ids.push((key.clone(), ids));
            }
            Ok((purged, base_ids, app_ids))
        });
        match res {
            Ok((purged, base_ids, app_ids)) => {
                self.purposes.clear();
                self.app_filter_ids.clear();
                let mut total = base_ids.len();
                for (id, p) in base_ids {
                    self.purposes.insert(id, p);
                }
                for (key, ids) in app_ids {
                    total += ids.len();
                    let mut v = Vec::new();
                    for (id, p) in ids {
                        self.purposes.insert(id, p);
                        v.push(id);
                    }
                    self.app_filter_ids.insert(key, v);
                }
                log::info!(
                    "Regelwerk neu aufgebaut: {total} Filter (vorher {purged}), Modus {:?}, {} ms",
                    mode,
                    started.elapsed().as_millis()
                );
            }
            Err(e) => {
                log::error!("Neuaufbau fehlgeschlagen (altes Regelwerk bleibt aktiv): {e:#}");
                self.push(EventKind::ApplyFailed { detail: format!("{e:#}") });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Networks
    // -----------------------------------------------------------------------

    fn refresh_networks(&mut self, rebuild_on_change: bool) {
        self.last_net_check = Instant::now();
        let nets = watchers::apply_trust(self.netwatch.connected(), &self.state.settings.network_trust);
        let trusted = !nets.is_empty() && nets.iter().all(|n| n.trusted);
        if nets == self.networks && trusted == self.network_trusted {
            return;
        }
        let trust_changed = trusted != self.network_trusted;
        self.networks = nets;
        self.network_trusted = trusted;
        self.revision += 1;
        if trust_changed {
            let name = self.networks.iter().map(|n| n.name.clone()).collect::<Vec<_>>().join(", ");
            let name = if name.is_empty() { "kein Netzwerk".into() } else { name };
            self.push(EventKind::NetworkChanged { name, trusted });
            if rebuild_on_change {
                self.rebuild();
            }
        }
    }

    // -----------------------------------------------------------------------
    // IPC
    // -----------------------------------------------------------------------

    fn status(&self, privileged: bool) -> Status {
        let apps = self.state.apps.values();
        let (mut allowed, mut blocked, mut pending) = (0, 0, 0);
        for a in apps {
            match a.effective_out {
                Access::Allow | Access::Lan => allowed += 1,
                Access::Block | Access::Ask => blocked += 1,
            }
            if a.pending {
                pending += 1;
            }
        }
        Status {
            version: VERSION.into(),
            mode: self.state.settings.mode,
            engine_ok: self.engine.is_some(),
            engine_error: self.engine_error.clone(),
            privileged,
            networks: self.networks.clone(),
            network_trusted: self.network_trusted,
            apps_total: self.state.apps.len(),
            apps_allowed: allowed,
            apps_blocked: blocked,
            pending,
            blocked_session: self.blocked_session,
            started: self.started,
            revision: self.revision,
            settings: self.state.settings.clone(),
            hello_enrolled: self.state.hello_key.is_some(),
        }
    }

    fn on_request(&mut self, req: Request, privileged: bool) -> Response {
        match req {
            Request::Status => Response::Status(Box::new(self.status(privileged))),
            Request::Apps => Response::Apps(self.state.apps.values().cloned().collect()),
            Request::Events { after } => {
                let v: Vec<Event> = self.events.iter().filter(|e| e.seq > after).cloned().collect();
                let skip = v.len().saturating_sub(300);
                Response::Events(v.into_iter().skip(skip).collect())
            }
            Request::SetMode(m) => {
                let cur = self.state.settings.mode;
                if m == cur {
                    return Response::Ok;
                }
                if m.strictness() < cur.strictness() && !privileged {
                    return Response::Denied;
                }
                if matches!(m, Mode::Off | Mode::Lockdown) && !matches!(cur, Mode::Off | Mode::Lockdown) {
                    self.state.settings.previous_mode = cur;
                }
                self.state.settings.mode = m;
                log::info!("Modus {cur:?} → {m:?}");
                self.push(EventKind::ModeChanged { from: cur, to: m });
                self.reevaluate_all();
                self.rebuild();
                Response::Ok
            }
            Request::SetRule { key, rule } => self.set_rule(&key, rule, privileged),
            Request::Snooze { key } => {
                let Some(app) = self.state.apps.get_mut(&key) else { return Response::Error(ErrorCode::UnknownApp) };
                app.pending = false;
                app.snoozed_until = Some(now_secs() + SNOOZE_SECS);
                self.changed();
                Response::Ok
            }
            Request::Forget { key } => {
                let Some(app) = self.state.apps.get(&key) else { return Response::Ok };
                if app.rule.is_some() && !privileged {
                    return Response::Denied;
                }
                if app.category == Category::Pseudo {
                    return Response::Error(ErrorCode::SystemEntry);
                }
                self.state.apps.remove(&key);
                self.app_id_cache.remove(&key);
                if let (Some(engine), Some(ids)) = (&self.engine, self.app_filter_ids.remove(&key)) {
                    let _ = engine.transaction(|e| {
                        ids.iter().for_each(|id| e.delete_filter(*id));
                        Ok(())
                    });
                    ids.iter().for_each(|id| {
                        self.purposes.remove(id);
                    });
                }
                self.changed();
                Response::Ok
            }
            Request::SetNetworkTrust { id, trusted } => {
                let windows_trusted = self.networks.iter().find(|n| n.id == id).map(|n| n.windows_category != NetCategory::Public);
                let resulting = trusted.or(windows_trusted).unwrap_or(false);
                if resulting && !privileged {
                    return Response::Denied;
                }
                match trusted {
                    Some(t) => self.state.settings.network_trust.insert(id, t),
                    None => self.state.settings.network_trust.remove(&id),
                };
                self.changed();
                self.refresh_networks(true);
                Response::Ok
            }
            Request::SetOptions { lan_discovery, learn_publishers } => {
                if (lan_discovery == Some(true) || learn_publishers == Some(true)) && !privileged {
                    return Response::Denied;
                }
                if let Some(v) = lan_discovery {
                    self.state.settings.lan_discovery = v;
                }
                if let Some(v) = learn_publishers {
                    self.state.settings.learn_publishers = v;
                }
                self.reevaluate_all();
                self.rebuild();
                Response::Ok
            }
            Request::RemovePublisher(p) => {
                self.state.settings.learned_publishers.retain(|x| !x.eq_ignore_ascii_case(&p));
                self.reevaluate_all();
                self.rebuild();
                Response::Ok
            }
            Request::Batch(reqs) => self.run_all(reqs, privileged),
            Request::Challenge => {
                self.challenges.retain(|_, t| t.elapsed() < CHALLENGE_TTL);
                if self.challenges.len() > 32 {
                    return Response::Error(ErrorCode::TooManyApprovals);
                }
                let n = hello::nonce();
                self.challenges.insert(n.clone(), Instant::now());
                Response::Challenge(n)
            }
            Request::Approved { nonce, payload, signature } => {
                // Single use: the nonce is consumed whether or not the signature is valid.
                let Some(issued) = self.challenges.remove(&nonce) else {
                    return Response::Error(ErrorCode::ApprovalExpired);
                };
                if issued.elapsed() > CHALLENGE_TTL {
                    return Response::Error(ErrorCode::ApprovalExpired);
                }
                let Some(key) = self.state.hello_key.clone() else {
                    return Response::Error(ErrorCode::HelloNotEnrolled);
                };
                if !hello::verify(&key, &approval_message(&nonce, &payload), &signature) {
                    log::warn!("Ungültige Windows-Hello-Signatur abgewiesen");
                    return Response::Denied;
                }
                let reqs: Vec<Request> = match serde_json::from_str(&payload) {
                    Ok(r) => r,
                    Err(e) => return Response::Error(ErrorCode::BadRequest(e.to_string())),
                };
                // Only plain policy changes may be approved this way.
                let plain = reqs.iter().all(|r| {
                    !matches!(
                        r,
                        Request::Batch(_) | Request::Challenge | Request::Approved { .. } | Request::EnrollHello { .. }
                    )
                });
                if !plain {
                    return Response::Error(ErrorCode::NotApprovableWithHello);
                }
                log::info!("{} Änderung(en) per Windows Hello bestätigt", reqs.len());
                self.run_all(reqs, true)
            }
            Request::EnrollHello { public_key } => {
                if !privileged {
                    return Response::Denied;
                }
                if hello::parse_key(&public_key).is_none() {
                    return Response::Error(ErrorCode::InvalidKey);
                }
                self.state.hello_key = Some(public_key);
                self.push(EventKind::HelloEnrolled);
                self.changed();
                self.save();
                Response::Ok
            }
            Request::RemoveHello => {
                // Tightening: afterwards every loosening change needs UAC again.
                self.state.hello_key = None;
                self.push(EventKind::HelloRemoved);
                self.changed();
                Response::Ok
            }
        }
    }

    /// Apply requests in order; stop at the first one that is not accepted.
    fn run_all(&mut self, reqs: Vec<Request>, privileged: bool) -> Response {
        for r in reqs {
            match self.on_request(r, privileged) {
                Response::Ok | Response::Status(_) | Response::Apps(_) | Response::Events(_) => {}
                other => return other,
            }
        }
        Response::Ok
    }

    fn set_rule(&mut self, key: &str, rule: Option<UserRule>, privileged: bool) -> Response {
        let Some(current) = self.state.apps.get(key).cloned() else {
            return Response::Error(ErrorCode::UnknownApp);
        };
        let rule = rule.filter(|r| !(r.outbound == RuleAccess::Auto && r.inbound == RuleAccess::Auto));
        let mut cand = current.clone();
        cand.rule = rule.map(|mut r| {
            if r.created == 0 {
                r.created = now_secs();
            }
            r
        });
        cand.tampered = false; // a fresh decision supersedes a tamper warning
        self.evaluate(&mut cand);

        let loosens = cand.effective_out.rank() > current.effective_out.rank()
            || cand.effective_in.rank() > current.effective_in.rank()
            || (current.tampered && cand.effective_out.rank() > 0);
        if loosens && !privileged {
            return Response::Denied;
        }

        let grants = cand.rule.as_ref().is_some_and(|r| {
            matches!(r.outbound, RuleAccess::Allow | RuleAccess::Lan) || matches!(r.inbound, RuleAccess::Allow | RuleAccess::Lan)
        });
        if grants && cand.category != Category::Pseudo {
            cand.identity = trust::identity(&cand.path, &cand.signature);
        }
        cand.pending = false;
        cand.snoozed_until = None;


        // Learn the publisher on a *permanent* allow of a signed user-space app.
        let learn = self.state.settings.learn_publishers
            && cand.category == Category::UserSpace
            && cand.rule.as_ref().is_some_and(|r| r.expires.is_none() && r.outbound == RuleAccess::Allow);
        let publisher = cand.signature.publisher().map(str::to_string);

        let name = cand.name.clone();
        let rule = cand.rule.clone();
        self.state.apps.insert(key.to_string(), cand);
        self.push(EventKind::RuleChanged { key: key.to_string(), name, rule });

        match publisher {
            Some(p) if learn && !policy::is_learned_publisher(&p, &self.state.settings.learned_publishers) => {
                log::info!("Herausgeber gelernt: {p}");
                self.state.settings.learned_publishers.push(p.clone());
                self.push(EventKind::PublisherLearned { publisher: p.clone() });
                self.reevaluate_all();
                self.rebuild();
            }
            _ => {
                self.apply_app(key);
                self.changed();
            }
        }
        Response::Ok
    }
}
