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
    /// Process details of a blocked attempt (from Security audit event 5157).
    Origin { filter_id: u64, path: Option<String>, origin: ProcessOrigin },
    /// `caller_sid`: account of the client, if it could be determined.
    Ipc { req: Request, privileged: bool, caller_sid: Option<String>, reply: Sender<Response> },
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
    /// Recent process origins of blocked attempts per app (memory only:
    /// command lines can contain private data and are never written to disk).
    origins: HashMap<String, Vec<ProcessOrigin>>,
    /// Address and name of the last blocked attempt per app (memory only,
    /// see [`crate::dns`]).
    last_hosts: HashMap<String, crate::dns::Host>,
    last_ips: HashMap<String, std::net::IpAddr>,
}

impl Core {
    pub fn new(dir: PathBuf, engine: Result<Engine, String>) -> Self {
        let mut state = store::load(&dir);
        let now = now_secs();
        state.apps.retain(|_, a| a.rule.is_some() || now.saturating_sub(a.last_seen) < PRUNE_AFTER_SECS);
        // Names taken from files nobody vouches for (see `trust::gather`) may
        // still be stored from earlier versions.
        for a in state.apps.values_mut() {
            if a.category != Category::Pseudo && !a.protected && !a.signature.is_valid() {
                a.name = trust::file_title(&a.path);
            }
        }

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
            origins: HashMap::new(),
            last_hosts: HashMap::new(),
            last_ips: HashMap::new(),
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
                    crate::dns::stop();
                    return;
                }
                self.handle(msg);
            }
            self.tick();
        }
        self.save();
        crate::dns::stop();
        log::info!("Kern beendet");
    }

    fn handle(&mut self, msg: Msg) {
        match msg {
            Msg::Process { path } => {
                self.observe(&path);
            }
            Msg::Net(evt) => self.on_net_event(evt),
            Msg::Origin { filter_id, path, origin } => self.on_origin(filter_id, path, origin),
            Msg::Ipc { req, privileged, caller_sid, reply } => {
                let resp = match req {
                    // The one answer that depends on who is asking.
                    Request::Apps => self.apps_for(privileged, caller_sid.as_deref()),
                    req => self.on_request(req, privileged),
                };
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
        // DNS events arrive about a second after the block; once the name for
        // a blocked attempt is known, let the UI know there is something new.
        let resolved: Vec<(String, crate::dns::Host)> = self
            .last_ips
            .iter()
            .filter(|(key, _)| !self.last_hosts.contains_key(*key))
            .filter_map(|(key, ip)| crate::dns::lookup(*ip).map(|h| (key.clone(), h)))
            .collect();
        if !resolved.is_empty() {
            self.last_hosts.extend(resolved);
            self.revision += 1;
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
            protected: app.protected,
            location: app.location_hint,
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
        self.observe_inner(path, true)
    }

    /// `announce`: log an automatic allow as an event. Off when the user adds
    /// a program by hand – nothing happened yet that is worth reporting.
    fn observe_inner(&mut self, path: &str, announce: bool) -> String {
        let key = path.to_lowercase();
        let now = now_secs();
        if let Some(app) = self.state.apps.get_mut(&key) {
            if now.saturating_sub(app.last_seen) > 3600 {
                app.last_seen = now;
                self.dirty = true;
            }
            // A file that is not on a local disk is only looked at once a
            // person has confirmed a permission for it (see `trust::is_local_path`).
            if trust::is_local_path(path) || policy::grants(app.rule.as_ref()) {
                let stamp = trust::file_stamp(path);
                if stamp.is_some() && stamp != app.file_stamp {
                    self.refresh_facts(&key, path);
                }
            }
            return key;
        }

        let f = if trust::is_local_path(path) { trust::gather(path, &self.win_dir) } else { trust::unverified(path, None) };
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
            origins: Vec::new(),
            last_host: None,
            last_host_verified: false,
        };
        self.evaluate(&mut app);
        log::debug!("Neue App {} → {:?} ({:?})", app.path, app.effective_out, app.reason);
        if announce && app.category == Category::UserSpace && app.effective_out == Access::Allow {
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
            origins: Vec::new(),
            last_host: None,
            last_host_verified: false,
        };
        self.evaluate(&mut app);
        self.state.apps.insert(key.clone(), app);
        self.apply_app(&key);
        self.changed();
        key
    }

    /// The file behind a known app changed (update or replacement).
    fn refresh_facts(&mut self, key: &str, path: &str) {
        // Only reached for files the service may look at (see `observe_inner`).
        // Off a local disk that is the content, not signature or permissions.
        let f = if trust::is_local_path(path) {
            trust::gather(path, &self.win_dir)
        } else {
            trust::unverified(path, trust::file_stamp(path))
        };
        let Some(mut app) = self.state.apps.remove(key) else { return };
        app.name = f.name;
        app.signature = f.signature;
        app.category = f.category;
        app.protected = f.protected;
        app.location_hint = f.location_hint;
        app.file_stamp = f.stamp;
        self.app_id_cache.remove(key);

        if policy::grants(app.rule.as_ref()) && !app.tampered {
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

        let host = evt.remote.and_then(crate::dns::lookup);

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
                    match &host {
                        Some(h) => self.last_hosts.insert(key.clone(), h.clone()),
                        None => self.last_hosts.remove(&key),
                    };
                    match evt.remote {
                        Some(ip) => self.last_ips.insert(key.clone(), ip),
                        None => self.last_ips.remove(&key),
                    };
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
            let host_verified = host.as_ref().is_some_and(|h| h.verified);
            let host = host.map(|h| h.name);
            self.push(EventKind::Blocked { key, name, remote, host, host_verified, ip: evt.remote, direction: dir, by_rule });
            self.revision += 1;
        }
    }

    /// Tell the audit-event callback which filters are Briqwall's blocking
    /// filters, so it only inspects processes for drops caused by Briqwall.
    fn publish_block_filters(&self) {
        watchers::set_block_filters(
            self.purposes
                .iter()
                .filter(|(_, p)| matches!(p, Purpose::DefaultBlock(_) | Purpose::AppBlock(..) | Purpose::Lockdown(_)))
                .map(|(id, _)| *id),
        );
    }

    /// Remember which process instance triggered a blocked attempt. Origins
    /// with the same command line and parents are merged.
    fn on_origin(&mut self, filter_id: u64, path: Option<String>, origin: ProcessOrigin) {
        const KEEP: usize = 5;
        if !matches!(
            self.purposes.get(&filter_id),
            Some(Purpose::DefaultBlock(_) | Purpose::AppBlock(..) | Purpose::Lockdown(_))
        ) {
            return; // not blocked by Briqwall
        }
        let Some(key) = path.map(|p| p.to_lowercase()).filter(|k| self.state.apps.contains_key(k)) else { return };
        let list = self.origins.entry(key).or_default();
        let same = |o: &ProcessOrigin| {
            o.command_line == origin.command_line
                && o.owner_sid == origin.owner_sid
                && o.parents.iter().map(|p| &p.name).eq(origin.parents.iter().map(|p| &p.name))
        };
        if let Some(i) = list.iter().position(same) {
            let mut known = list.remove(i);
            known.pid = origin.pid;
            known.last_seen = origin.last_seen;
            known.count = known.count.saturating_add(1);
            known.parents = origin.parents;
            list.insert(0, known);
        } else {
            list.insert(0, origin);
            list.truncate(KEEP);
        }
        self.revision += 1;
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
        // Resolving the id opens the file. Off a local disk only for a
        // permission a person confirmed – without one there is nothing to
        // permit anyway, the app waits at the default block.
        if !trust::is_local_path(&app.path) && !policy::grants(app.rule.as_ref()) {
            return None;
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
                self.publish_block_filters();
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
        // The DHCP client lives in svchost.exe; binding the DHCP permits to it
        // keeps other programs from using the client ports as a way out.
        let dhcp_client = wfp::app_id_for_path(&format!("{}\\system32\\svchost.exe", self.win_dir));
        if let Err(e) = &dhcp_client {
            log::warn!("svchost.exe nicht auflösbar, DHCP-Filter nur an Ports gebunden: {e:#}");
        }
        let base = compiler::base_filters(mode, dhcp_client.ok().as_deref());
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
                self.publish_block_filters();
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
            hello_users: self
                .state
                .hello_keys
                .iter()
                .map(|k| HelloUser { sid: k.sid.clone(), name: k.name.clone() })
                .collect(),
        }
    }

    /// The app list as this client may see it. Command lines of blocked
    /// processes can hold passwords and tokens; they go to the account the
    /// process ran as, and to administrators.
    fn apps_for(&self, privileged: bool, caller_sid: Option<&str>) -> Response {
        Response::Apps(
            self.state
                .apps
                .values()
                .map(|a| {
                    let mut a = a.clone();
                    a.origins = self
                        .origins
                        .get(&a.key)
                        .map(|list| list.iter().filter(|o| may_see_origin(o, privileged, caller_sid)).cloned().collect())
                        .unwrap_or_default();
                    let host = self
                        .last_hosts
                        .get(&a.key)
                        .cloned()
                        .or_else(|| self.last_ips.get(&a.key).and_then(|ip| crate::dns::lookup(*ip)));
                    a.last_host_verified = host.as_ref().is_some_and(|h| h.verified);
                    a.last_host = host.map(|h| h.name);
                    a
                })
                .collect(),
        )
    }

    fn on_request(&mut self, req: Request, privileged: bool) -> Response {
        match req {
            Request::Status => Response::Status(Box::new(self.status(privileged))),
            // Inside a batch nobody reads the answer; see `handle`.
            Request::Apps => self.apps_for(false, None),
            Request::Events { after } => {
                // A name may only have arrived after the block was recorded.
                let v: Vec<Event> = self
                    .events
                    .iter()
                    .filter(|e| e.seq > after)
                    .cloned()
                    .map(|mut e| {
                        if let EventKind::Blocked { host: host @ None, host_verified, ip: Some(ip), .. } = &mut e.kind {
                            if let Some(h) = crate::dns::lookup(*ip) {
                                *host = Some(h.name);
                                *host_verified = h.verified;
                            }
                        }
                        e
                    })
                    .collect();
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
                self.origins.remove(&key);
                self.last_hosts.remove(&key);
                self.last_ips.remove(&key);
                if let (Some(engine), Some(ids)) = (&self.engine, self.app_filter_ids.remove(&key)) {
                    let _ = engine.transaction(|e| {
                        ids.iter().for_each(|id| e.delete_filter(*id));
                        Ok(())
                    });
                    ids.iter().for_each(|id| {
                        self.purposes.remove(id);
                    });
                    self.publish_block_filters();
                }
                self.changed();
                Response::Ok
            }
            Request::AddApp { path } => self.add_app(&path),
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
                if self.state.hello_keys.is_empty() {
                    return Response::Error(ErrorCode::HelloNotEnrolled);
                }
                let message = approval_message(&nonce, &payload);
                // Any enrolled account may approve; the key says which one it was.
                let Some(signer) = self.state.hello_keys.iter().find(|k| hello::verify(&k.key, &message, &signature)) else {
                    log::warn!("Ungültige Windows-Hello-Signatur abgewiesen");
                    return Response::Denied;
                };
                let signer = if signer.name.is_empty() { "unbekanntes Konto".to_string() } else { signer.name.clone() };
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
                log::info!("{} Änderung(en) per Windows Hello bestätigt ({signer})", reqs.len());
                self.run_all(reqs, true)
            }
            Request::EnrollHello { public_key, sid, name } => {
                if !privileged {
                    return Response::Denied;
                }
                if hello::parse_key(&public_key).is_none() {
                    return Response::Error(ErrorCode::InvalidKey);
                }
                // One key per account: enrolling again replaces the old one.
                self.state.hello_keys.retain(|k| k.sid != sid);
                self.state.hello_keys.push(store::HelloKey { sid, name, key: public_key });
                self.push(EventKind::HelloEnrolled);
                self.changed();
                self.save();
                Response::Ok
            }
            Request::RemoveHello { sid } => {
                // Tightening: afterwards loosening changes need UAC again. A key
                // from before per-account enrollment has no owner to compare, so
                // "switch Hello off" removes that one too.
                self.state.hello_keys.retain(|k| k.sid != sid && !k.sid.is_empty());
                self.push(EventKind::HelloRemoved);
                self.changed();
                self.save();
                Response::Ok
            }
        }
    }

    /// Apply requests in order; stop at the first one that is not accepted.
    fn run_all(&mut self, reqs: Vec<Request>, privileged: bool) -> Response {
        for r in reqs {
            match self.on_request(r, privileged) {
                Response::Ok | Response::Status(_) | Response::Apps(_) | Response::Events(_) | Response::Added { .. } => {}
                other => return other,
            }
        }
        Response::Ok
    }

    /// Put a program the user picked into the list. Changes nothing about what
    /// is allowed – the entry gets the same automatic verdict it would get on
    /// its first connection – so this needs no elevation.
    fn add_app(&mut self, path: &str) -> Response {
        let Some(full) = full_path(path) else { return Response::Error(ErrorCode::NoSuchFile) };
        let existed = self.state.apps.contains_key(&full.to_lowercase());
        let key = self.observe_inner(&full, false);
        if !existed {
            log::info!("Programm manuell aufgenommen: {full}");
        }
        Response::Added { key, existed }
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

        if policy::loosens(&current, &cand) && !privileged {
            return Response::Denied;
        }

        let grants = policy::grants(cand.rule.as_ref());
        // Which binary the permission is for is only (re)recorded together
        // with a confirmed decision. Otherwise anyone could swap the file and
        // then "renew" the existing rule to make the new file the expected one.
        if privileged && grants && cand.category != Category::Pseudo {
            cand.identity = trust::identity(&cand.path, &cand.signature);
        }
        cand.pending = false;
        cand.snoozed_until = None;

        // Learn the publisher on a confirmed, *permanent* allow of a signed
        // user-space app. A catalog signature names Windows itself, not the
        // vendor of an app – nothing to learn from.
        let learn = privileged
            && self.state.settings.learn_publishers
            && cand.category == Category::UserSpace
            && !matches!(cand.signature, Signature::Valid { catalog: true, .. })
            && cand.rule.as_ref().is_some_and(|r| r.expires.is_none() && r.outbound == RuleAccess::Allow);
        let publisher = cand.signature.publisher().map(str::to_string).filter(|p| !p.trim().is_empty());

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

/// May this client see the command line of that blocked process?
fn may_see_origin(o: &ProcessOrigin, privileged: bool, caller_sid: Option<&str>) -> bool {
    privileged || (caller_sid.is_some() && o.owner_sid.as_deref() == caller_sid)
}

/// Full path of an existing file on a local disk, resolved the way the kernel
/// reports it for a running process (long names, no relative parts). `None`
/// if it is no file, or if the path leads off this computer.
///
/// Any user may send a path. The service must not open one that points to a
/// network share – as SYSTEM it would log this computer on to a server of the
/// sender's choosing.
fn full_path(path: &str) -> Option<String> {
    let local = resolve_local(path)?;
    if !std::fs::symlink_metadata(&local).ok()?.is_file() {
        return None;
    }
    let full = strip_verbatim(&std::fs::canonicalize(&local).ok()?.to_string_lossy());
    trust::is_local_path(&full).then_some(full)
}

/// Follow links by hand, one component at a time, so that none is followed
/// before its target is known to be on a local disk. `None` if any step
/// leaves the local disks (or the links do not end).
fn resolve_local(path: &str) -> Option<PathBuf> {
    let mut current = PathBuf::from(path);
    for _ in 0..16 {
        if !trust::is_local_path(&current.to_string_lossy()) {
            return None;
        }
        let parts: Vec<std::path::Component> = current.components().collect();
        let mut prefix = PathBuf::new();
        let mut next = None;
        for (i, part) in parts.iter().enumerate() {
            prefix.push(part);
            if i < 2 {
                continue; // drive and root
            }
            let Ok(meta) = std::fs::symlink_metadata(&prefix) else { return None };
            if !meta.file_type().is_symlink() {
                continue;
            }
            // Read where the link points without going there.
            let target = std::fs::read_link(&prefix).ok()?;
            let target = if target.is_absolute() { target } else { prefix.parent()?.join(target) };
            let mut resolved = PathBuf::from(strip_verbatim(&target.to_string_lossy()));
            resolved.extend(&parts[i + 1..]);
            next = Some(resolved);
            break;
        }
        match next {
            Some(n) => current = n,
            None => return Some(current),
        }
    }
    None
}

/// Remove the verbatim prefix that [`std::fs::canonicalize`] returns.
fn strip_verbatim(s: &str) -> String {
    const BS: char = '\\';
    let verbatim: String = [BS, BS, '?', BS].iter().collect();
    let unc = format!("{verbatim}UNC{BS}");
    if let Some(rest) = s.strip_prefix(&unc) {
        return format!("{BS}{BS}{rest}");
    }
    s.strip_prefix(&verbatim).unwrap_or(s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_canonicalize_prefixes() {
        let bs = '\\';
        assert_eq!(strip_verbatim(&format!("{bs}{bs}?{bs}C:{bs}dir{bs}a.exe")), format!("C:{bs}dir{bs}a.exe"));
        assert_eq!(strip_verbatim(&format!("{bs}{bs}?{bs}UNC{bs}srv{bs}share{bs}a.exe")), format!("{bs}{bs}srv{bs}share{bs}a.exe"));
        assert_eq!(strip_verbatim(&format!("C:{bs}dir{bs}a.exe")), format!("C:{bs}dir{bs}a.exe"));
    }

    #[test]
    fn full_path_resolves_file_and_rejects_others() {
        let exe = std::env::current_exe().expect("current exe");
        let dir = exe.parent().expect("parent dir");
        // A detour through the parent directory must lead back to the same path.
        let detour = dir.join("..").join(dir.file_name().unwrap()).join(exe.file_name().unwrap());
        let resolved = full_path(&exe.to_string_lossy()).expect("own exe is a file");
        assert!(!resolved.starts_with('\\'), "no verbatim prefix: {resolved}");
        assert_eq!(full_path(&detour.to_string_lossy()), Some(resolved));
        assert!(full_path(&dir.to_string_lossy()).is_none(), "a directory is no program");
        assert!(full_path(&format!("{}{}no-such-file.exe", dir.display(), '\\')).is_none());
    }

    /// Paths that would make the service contact another machine are turned
    /// down by their form alone, before anything is opened.
    #[test]
    fn paths_off_this_computer_are_rejected_unopened() {
        for p in [
            r"\\198.51.100.7\share\tool.exe",
            r"\\?\UNC\198.51.100.7\share\tool.exe",
            r"\\.\pipe\briqwall-control",
            r"tool.exe",
            r"..\tool.exe",
            "",
        ] {
            let t = Instant::now();
            assert!(full_path(p).is_none(), "{p}");
            // No name lookup, no connection attempt.
            assert!(t.elapsed() < Duration::from_millis(500), "{p} took {:?}", t.elapsed());
        }
    }

    #[test]
    fn command_lines_go_to_their_own_account_only() {
        let origin = |owner: Option<&str>| ProcessOrigin {
            pid: 1,
            command_line: Some("tool --password hunter2".into()),
            parents: Vec::new(),
            last_seen: 0,
            count: 1,
            owner_sid: owner.map(str::to_string),
        };
        let mine = origin(Some("S-1-5-21-1-1001"));
        assert!(may_see_origin(&mine, false, Some("S-1-5-21-1-1001")));
        assert!(!may_see_origin(&mine, false, Some("S-1-5-21-1-1002")), "another account");
        assert!(!may_see_origin(&mine, false, None), "unidentified client");
        assert!(may_see_origin(&mine, true, Some("S-1-5-21-1-1002")), "administrator");
        // Owner unknown: nobody but an administrator.
        assert!(!may_see_origin(&origin(None), false, Some("S-1-5-21-1-1001")));
        assert!(!may_see_origin(&origin(None), false, None));
        assert!(may_see_origin(&origin(None), true, None));
    }

    /// The owner is service-internal and must not travel over the pipe.
    #[test]
    fn owner_of_an_origin_is_not_serialized() {
        let o = ProcessOrigin { pid: 1, command_line: None, parents: Vec::new(), last_seen: 0, count: 1, owner_sid: Some("S-1-5-18".into()) };
        assert!(!serde_json::to_string(&o).unwrap().contains("S-1-5-18"));
    }
}
