//! The service core: a single-threaded actor that owns all state.
//! Every input (process starts, WFP drop events, IPC requests, timers) arrives
//! as a [`Msg`], so no locking is needed.

use crate::compiler::{self, Compiled, DirPolicy, Purpose};
use crate::evaluator::{self, KnownFiles};
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
    /// A program started. `facts`: already gathered by a worker where the
    /// program is new or its file changed (see [`crate::evaluator`]).
    /// `pid`: the process, if this is about one that just started.
    Process { path: String, facts: Option<trust::Facts>, pid: Option<u32> },
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

/// On whose word the request being handled may loosen protection.
enum Acting {
    /// A client running with administrator rights (its account SID).
    Admin(Option<String>),
    /// The account whose Windows Hello key signed the changes.
    Hello(String),
}

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
    /// See [`Status::activity`].
    activity: u64,
    /// Something changed that must not be lost: rules, settings, requests.
    dirty: bool,
    /// Only statistics changed (counters, last seen). Written now and then.
    stats_dirty: bool,
    last_save: Instant,
    /// Files of known apps, for the workers that evaluate new programs.
    known: KnownFiles,
    /// The filters of a previous run have been removed; from then on this
    /// process knows every Briqwall filter by id.
    purged: bool,
    /// The activity log changed since it was last written.
    events_dirty: bool,
    /// Windows' program folders (lower-case), see [`policy::install_folder`].
    program_dirs: Vec<String>,
    /// Set while a request is handled that came with a confirmation.
    acting: Option<Acting>,
    /// Keeps "started by a blocked program" from repeating all day.
    launches: Coalescer,
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
    pub fn new(dir: PathBuf, engine: Result<Engine, String>, known: KnownFiles) -> Self {
        Self::new_with(dir, engine, known, true)
    }

    /// `scan_running`: evaluate the programs that are already running
    /// (always, except in tests that want an empty app list).
    fn new_with(dir: PathBuf, engine: Result<Engine, String>, known: KnownFiles, scan_running: bool) -> Self {
        let mut state = store::load(&dir);
        // The activity log continues where the last run stopped.
        let mut events: VecDeque<Event> = store::load_events(&dir).into();
        while events.len() > MAX_EVENTS {
            events.pop_front();
        }
        let seq = events.back().map_or(0, |e| e.seq);
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
            events,
            seq,
            networks: Vec::new(),
            network_trusted: false,
            devmap,
            revision: 1,
            activity: 0,
            dirty: false,
            stats_dirty: false,
            last_save: Instant::now(),
            known,
            purged: false,
            events_dirty: false,
            program_dirs: trust::program_dirs(),
            acting: None,
            launches: Coalescer::default(),
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
        for (key, app) in &core.state.apps {
            core.known.set(key, app.file_stamp);
        }
        let running: std::collections::BTreeSet<String> = if scan_running {
            watchers::list_pids().into_iter().filter_map(watchers::process_path).collect()
        } else {
            Default::default()
        };
        let running: Vec<String> = running.into_iter().collect();
        // What is new, or changed since the last run, is checked on several
        // threads at once: on a first start that is every running program.
        let wanted: Vec<bool> = running
            .iter()
            .map(|path| {
                let known = core.state.apps.get(&path.to_lowercase()).map(|a| a.file_stamp);
                trust::is_local_path(path) && evaluator::needs_facts(known, trust::file_stamp(path))
            })
            .collect();
        let checked = wanted.iter().filter(|w| **w).count();
        let facts = evaluator::gather_all(&running, &wanted, &core.win_dir);
        for (path, facts) in running.iter().zip(facts) {
            core.observe_inner(path, true, facts);
        }
        log::info!(
            "{} laufende Programme in {} ms bewertet ({checked} neu geprüft)",
            running.len(),
            t.elapsed().as_millis()
        );
        core.reevaluate_all();
        core.refresh_networks(false);
        core.rebuild();
        core.defer_apply = false;
        core.push(EventKind::Started { version: VERSION.into(), mode: core.state.settings.mode });
        core
    }

    /// Remember which audit subcategories this start had to switch on.
    pub fn note_audit_enabled(&mut self, subcategories: Vec<String>) {
        for sc in subcategories {
            if !self.state.audit_enabled.contains(&sc) {
                self.state.audit_enabled.push(sc);
                self.dirty = true;
            }
        }
        // Older versions only read the flag.
        if !self.state.audit_enabled.is_empty() && !self.state.audit_enabled_by_us {
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
            Msg::Process { path, facts, pid } => {
                let key = self.observe_inner(&path, true, facts);
                if let Some(pid) = pid {
                    self.flag_launch(pid, &key);
                }
            }
            Msg::Net(evt) => self.on_net_event(evt),
            Msg::Origin { filter_id, path, origin } => self.on_origin(filter_id, path, origin),
            Msg::Ipc { req, privileged, caller_sid, reply } => {
                let resp = match req {
                    // The one answer that depends on who is asking.
                    Request::Apps => self.apps_for(privileged, caller_sid.as_deref()),
                    req => {
                        self.acting = privileged.then(|| Acting::Admin(caller_sid));
                        let resp = self.on_request(req, privileged);
                        self.acting = None;
                        resp
                    }
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
            self.activity += 1;
        }

        if self.last_net_check.elapsed() > Duration::from_secs(5) {
            self.refresh_networks(true);
        }
        if save_due(self.dirty, self.stats_dirty, self.last_save.elapsed()) {
            self.save();
        }
    }

    fn save(&mut self) {
        if let Err(e) = store::save(&self.dir, &self.state) {
            log::error!("Speichern fehlgeschlagen: {e:#}");
        }
        if self.events_dirty {
            if let Err(e) = store::save_events(&self.dir, self.events.iter()) {
                log::error!("Aktivitätsprotokoll konnte nicht gespeichert werden: {e:#}");
            }
            self.events_dirty = false;
        }
        self.dirty = false;
        self.stats_dirty = false;
        self.last_save = Instant::now();
    }

    fn push(&mut self, kind: EventKind) {
        self.seq += 1;
        self.events.push_back(Event { seq: self.seq, time: now_secs(), kind });
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
        // Written along with the next save: at once if something to keep
        // changed as well, otherwise with the statistics.
        self.events_dirty = true;
        self.stats_dirty = true;
    }

    /// Who confirmed the request being handled, for the activity log.
    fn approval(&self) -> Option<Approval> {
        Some(match self.acting.as_ref()? {
            Acting::Hello(account) => Approval { account: account.clone(), method: ApprovalMethod::Hello },
            Acting::Admin(sid) => Approval {
                account: sid.as_deref().and_then(trust::account_name).unwrap_or_default(),
                method: ApprovalMethod::Admin,
            },
        })
    }

    /// A program that may go online was started. If it is a browser or an
    /// abusable tool and one of its ancestors is a program that may *not* go
    /// online, say so: the browser will fetch whatever it is told to.
    fn flag_launch(&mut self, pid: u32, key: &str) {
        let Some(child) = self.state.apps.get(key) else { return };
        let file = key.rsplit('\\').next().unwrap_or(key);
        let candidate = matches!(child.effective_out, Access::Allow | Access::Lan)
            && (child.category == Category::Lolbin || policy::is_browser(file));
        if !candidate {
            return; // the common case, decided without looking at the process
        }
        let Some(origin) = crate::procinfo::origin(pid, Some(key)) else { return };
        let found = origin.parents.iter().find_map(|p| {
            let parent = self.state.apps.get(&p.path.as_ref()?.to_lowercase())?;
            policy::launch_worth_flagging(child, parent).then(|| (parent.key.clone(), parent.name.clone()))
        });
        let Some((by_key, by_name)) = found else { return };
        if self.launches.should_log(&format!("{by_key}>{key}"), Duration::from_secs(3600)) {
            let (key, name) = (key.to_string(), child.name.clone());
            log::info!("{name} wurde von {by_name} gestartet, das selbst nicht ins Netz darf");
            self.push(EventKind::StartedByBlocked { key, name, by_key, by_name });
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
            trusted_folder: (app.category == Category::Installed)
                .then(|| policy::trusted_folder(&app.path, &s.trusted_folders))
                .flatten(),
        });
        app.install_folder =
            (app.category == Category::Installed).then(|| policy::install_folder(&app.path, &self.program_dirs)).flatten();
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
        self.observe_inner(path, true, None)
    }

    /// `announce`: log an automatic allow as an event. Off when the user adds
    /// a program by hand – nothing happened yet that is worth reporting.
    /// `facts`: what a worker already found out about the file. Without them
    /// the file is checked here if need be, which holds up everything else.
    fn observe_inner(&mut self, path: &str, announce: bool, facts: Option<trust::Facts>) -> String {
        let key = path.to_lowercase();
        let now = now_secs();
        if let Some(app) = self.state.apps.get_mut(&key) {
            if now.saturating_sub(app.last_seen) > 3600 {
                app.last_seen = now;
                self.stats_dirty = true;
            }
            // A file that is not on a local disk is only looked at once a
            // person has confirmed a permission for it (see `trust::is_local_path`).
            if trust::is_local_path(path) || policy::grants(app.rule.as_ref()) {
                let stamp = match &facts {
                    Some(f) => f.stamp,
                    None => trust::file_stamp(path),
                };
                if stamp.is_some() && stamp != app.file_stamp {
                    self.refresh_facts(&key, path, facts);
                }
            }
            return key;
        }

        let f = match facts {
            Some(f) => f,
            None if trust::is_local_path(path) => trust::gather(path, &self.win_dir),
            None => trust::unverified(path, None),
        };
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
            install_folder: None,
        };
        self.evaluate(&mut app);
        log::debug!("Neue App {} → {:?} ({:?})", app.path, app.effective_out, app.reason);
        if announce && app.category == Category::UserSpace && app.effective_out == Access::Allow {
            self.push(EventKind::AutoAllowed { key: key.clone(), name: app.name.clone(), reason: app.reason.clone() });
        }
        self.known.set(&key, app.file_stamp);
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
            install_folder: None,
        };
        self.evaluate(&mut app);
        self.state.apps.insert(key.clone(), app);
        self.apply_app(&key);
        self.changed();
        key
    }

    /// The file behind a known app changed (update or replacement).
    fn refresh_facts(&mut self, key: &str, path: &str, facts: Option<trust::Facts>) {
        // Only reached for files the service may look at (see `observe_inner`).
        // Off a local disk that is the content, not signature or permissions.
        let f = match facts {
            Some(f) => f,
            None if trust::is_local_path(path) => trust::gather(path, &self.win_dir),
            None => trust::unverified(path, trust::file_stamp(path)),
        };
        let Some(mut app) = self.state.apps.remove(key) else { return };
        self.known.set(key, f.stamp);
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
        // Counters can wait; a new request must survive a crash.
        self.stats_dirty = true;
        if let Some(risk) = new_request {
            self.push(EventKind::NewRequest { key: key.clone(), name: name.clone(), risk });
            self.changed();
        }
        let dkey = format!("{key}|{dir:?}|{remote}");
        if self.coalescer.should_log(&dkey, Duration::from_secs(30)) {
            let host_verified = host.as_ref().is_some_and(|h| h.verified);
            let host = host.map(|h| h.name);
            self.push(EventKind::Blocked { key, name, remote, host, host_verified, ip: evt.remote, direction: dir, by_rule });
            self.activity += 1;
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
        self.activity += 1;
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
            // Follow Windows' own view of the network – unless the user told
            // Briqwall to trust a network that Windows has down as public.
            !self.networks.iter().any(|n| n.explicit && n.trusted && n.windows_category == NetCategory::Public),
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
        // Finding Briqwall's filters means reading every filter on the
        // system, Windows Firewall's thousands included. That is only needed
        // once, for what an earlier run left behind. After that, every filter
        // was added by this process and is known by its id.
        let tracked: Option<Vec<u64>> = self.purged.then(|| self.purposes.keys().copied().collect());
        let engine = self.engine.as_ref().unwrap();
        let res = engine.transaction(|e| {
            let purged = match &tracked {
                Some(ids) => {
                    ids.iter().for_each(|id| e.delete_filter(*id));
                    ids.len()
                }
                None => e.purge_filters()?,
            };
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
                self.purged = true;
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
            activity: self.activity,
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
                let by = if m.strictness() < cur.strictness() { self.approval() } else { None };
                self.push(EventKind::ModeChanged { from: cur, to: m, by });
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
                self.known.remove(&key);
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
            Request::TrustFolder { key } => {
                // Checked first: an unconfirmed client learns nothing about the app.
                if !privileged {
                    return Response::Denied;
                }
                let Some(app) = self.state.apps.get(&key) else { return Response::Error(ErrorCode::UnknownApp) };
                // Only where the folder is the administrators' (an installed
                // app); elsewhere "everything in this folder" is whatever
                // anyone drops there.
                let Some(folder) = app.install_folder.clone().filter(|_| app.category == Category::Installed) else {
                    return Response::Error(ErrorCode::BadRequest("no program folder".into()));
                };
                if !self.state.settings.trusted_folders.iter().any(|f| f.eq_ignore_ascii_case(&folder)) {
                    log::info!("Programmordner vertraut: {folder}");
                    self.state.settings.trusted_folders.push(folder.clone());
                    let by = self.approval();
                    self.push(EventKind::FolderTrusted { folder, by });
                    self.reevaluate_all();
                    self.rebuild();
                }
                Response::Ok
            }
            Request::UntrustFolder(folder) => {
                let before = self.state.settings.trusted_folders.len();
                self.state.settings.trusted_folders.retain(|f| !f.eq_ignore_ascii_case(&folder));
                if self.state.settings.trusted_folders.len() != before {
                    self.push(EventKind::FolderUntrusted { folder });
                    self.reevaluate_all();
                    self.rebuild();
                }
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
                let account = signer.name.clone();
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
                let before = self.acting.replace(Acting::Hello(account));
                let resp = self.run_all(reqs, true);
                self.acting = before;
                resp
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
        let key = self.observe_inner(&full, false, None);
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

        let loosens = policy::loosens(&current, &cand);
        if loosens && !privileged {
            return Response::Denied;
        }
        // Tightening needs nobody's word; only a loosening has a confirmer.
        let by = if loosens { self.approval() } else { None };

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
        self.push(EventKind::RuleChanged { key: key.to_string(), name, rule, by });

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

/// Is it time to write the state file? What must not be lost goes out
/// within seconds. Statistics alone are not worth a rewrite of the whole
/// file every other second while something is being blocked – they wait
/// for the next real change, or a few minutes.
fn save_due(dirty: bool, stats_dirty: bool, since_last_save: Duration) -> bool {
    (dirty && since_last_save > Duration::from_secs(2)) || (stats_dirty && since_last_save > Duration::from_secs(300))
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

    // -------------------------------------------------------------------
    // What a client may do. The promise is: anyone may tighten protection,
    // loosening it takes a confirmation – an elevated client or a Windows
    // Hello signature. These tests drive the core the way the pipe does.
    // -------------------------------------------------------------------

    /// A core without WFP and without the programs running on this machine,
    /// in a folder of its own.
    fn test_core(name: &str) -> (Core, PathBuf) {
        let dir = std::env::temp_dir().join(format!("briqwall-core-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (Core::new_with(dir.clone(), Err("test".into()), KnownFiles::default(), false), dir)
    }

    /// Send a request as the pipe server would.
    fn ask(core: &mut Core, req: Request, privileged: bool) -> Response {
        let (tx, rx) = std::sync::mpsc::channel();
        // SYSTEM has a name on every Windows, in every language.
        core.handle(Msg::Ipc { req, privileged, caller_sid: Some("S-1-5-18".into()), reply: tx });
        rx.recv().unwrap()
    }

    /// Make an app known without touching a file.
    fn add_app(core: &mut Core, path: &str, category: Category, signature: Signature) -> String {
        let facts = trust::Facts {
            exists: true,
            name: "Test".into(),
            signature,
            protected: category != Category::UserSpace,
            category,
            location_hint: None,
            stamp: Some((1, 1)),
        };
        core.observe_inner(path, false, Some(facts))
    }

    fn rule(outbound: RuleAccess, expires: Option<u64>) -> Option<UserRule> {
        Some(UserRule { outbound, inbound: RuleAccess::Auto, expires, created: 1 })
    }

    fn out_of(core: &Core, key: &str) -> Access {
        core.state.apps[key].effective_out
    }

    #[test]
    fn unconfirmed_clients_can_only_tighten() {
        let (mut core, dir) = test_core("tighten");
        let key = add_app(&mut core, r"c:\users\t\downloads\tool.exe", Category::UserSpace, Signature::Unsigned);
        assert_eq!(out_of(&core, &key), Access::Ask);
        let denied = |r: Response| matches!(r, Response::Denied);
        let ok = |r: Response| matches!(r, Response::Ok);

        // Rules: no permission of any kind, but a block at once.
        for access in [RuleAccess::Allow, RuleAccess::Lan] {
            assert!(denied(ask(&mut core, Request::SetRule { key: key.clone(), rule: rule(access, None) }, false)));
            assert!(denied(ask(&mut core, Request::SetRule { key: key.clone(), rule: rule(access, Some(now_secs() + 60)) }, false)));
        }
        assert_eq!(out_of(&core, &key), Access::Ask, "a denied request changes nothing");
        assert!(ok(ask(&mut core, Request::SetRule { key: key.clone(), rule: rule(RuleAccess::Block, None) }, false)));
        assert_eq!(out_of(&core, &key), Access::Block);
        // Hiding a request is no permission either way.
        assert!(ok(ask(&mut core, Request::Snooze { key: key.clone() }, false)));
        // Forgetting an app would drop its block with it.
        assert!(denied(ask(&mut core, Request::Forget { key: key.clone() }, false)));
        assert!(core.state.apps.contains_key(&key));

        // Protection level: up yes, down no.
        assert!(ok(ask(&mut core, Request::SetMode(Mode::Strict), false)));
        for lower in [Mode::Balanced, Mode::Relaxed, Mode::Off] {
            assert!(denied(ask(&mut core, Request::SetMode(lower), false)), "{lower:?}");
        }
        assert!(ok(ask(&mut core, Request::SetMode(Mode::Lockdown), false)));
        assert!(denied(ask(&mut core, Request::SetMode(Mode::Strict), false)), "leaving lockdown is loosening");
        assert_eq!(core.state.settings.mode, Mode::Lockdown);

        // Settings that open something.
        assert!(denied(ask(&mut core, Request::SetOptions { lan_discovery: Some(true), learn_publishers: None }, false)));
        assert!(denied(ask(&mut core, Request::SetOptions { lan_discovery: None, learn_publishers: Some(true) }, false)));
        assert!(ok(ask(&mut core, Request::SetOptions { lan_discovery: Some(false), learn_publishers: Some(false) }, false)));
        assert!(denied(ask(&mut core, Request::SetNetworkTrust { id: "net".into(), trusted: Some(true) }, false)));
        assert!(ok(ask(&mut core, Request::SetNetworkTrust { id: "net".into(), trusted: Some(false) }, false)));
        // A key of one's own would be a standing permission to confirm.
        let enroll = Request::EnrollHello { public_key: "00".into(), sid: "S-1-5-21-1".into(), name: "x".into() };
        assert!(denied(ask(&mut core, enroll, false)));
        assert!(core.state.hello_keys.is_empty());
        assert!(denied(ask(&mut core, Request::TrustFolder { key: key.clone() }, false)));
        assert!(denied(ask(&mut core, Request::TrustFolder { key: "no such app".into() }, false)), "no hint whether the app exists");
        // Taking trust away is always possible.
        assert!(ok(ask(&mut core, Request::RemovePublisher("Someone".into()), false)));
        assert!(ok(ask(&mut core, Request::UntrustFolder(r"C:\Program Files\X".into()), false)));
        assert!(ok(ask(&mut core, Request::RemoveHello { sid: "S-1-5-21-1".into() }, false)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_batch_stops_at_the_first_change_that_needs_confirmation() {
        let (mut core, dir) = test_core("batch");
        let a = add_app(&mut core, r"c:\users\t\downloads\a.exe", Category::UserSpace, Signature::Unsigned);
        let b = add_app(&mut core, r"c:\users\t\downloads\b.exe", Category::UserSpace, Signature::Unsigned);
        let batch = Request::Batch(vec![
            Request::SetRule { key: a.clone(), rule: rule(RuleAccess::Block, None) },
            Request::SetRule { key: b.clone(), rule: rule(RuleAccess::Allow, None) },
            Request::SetMode(Mode::Strict),
        ]);
        assert!(matches!(ask(&mut core, batch.clone(), false), Response::Denied));
        assert_eq!(out_of(&core, &b), Access::Ask);
        assert_eq!(core.state.settings.mode, Mode::Balanced, "nothing after the denied change is applied");
        // Confirmed, all of it goes through.
        assert!(matches!(ask(&mut core, batch, true), Response::Ok));
        assert_eq!((out_of(&core, &a), out_of(&core, &b)), (Access::Block, Access::Allow));
        assert_eq!(core.state.settings.mode, Mode::Strict);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_confirmed_permission_cannot_be_stretched_without_another_confirmation() {
        let (mut core, dir) = test_core("stretch");
        let key = add_app(&mut core, r"c:\users\t\downloads\tool.exe", Category::UserSpace, Signature::Unsigned);
        let hour = now_secs() + 3600;
        assert!(matches!(ask(&mut core, Request::SetRule { key: key.clone(), rule: rule(RuleAccess::Allow, Some(hour)) }, true), Response::Ok));
        assert_eq!(out_of(&core, &key), Access::Allow);
        let identity = core.state.apps[&key].identity.clone();

        for longer in [None, Some(hour + 1)] {
            let r = ask(&mut core, Request::SetRule { key: key.clone(), rule: rule(RuleAccess::Allow, longer) }, false);
            assert!(matches!(r, Response::Denied), "{longer:?}");
        }
        // Sending the same rule again is accepted, but is no new decision.
        assert!(matches!(ask(&mut core, Request::SetRule { key: key.clone(), rule: rule(RuleAccess::Allow, Some(hour)) }, false), Response::Ok));
        assert_eq!(core.state.apps[&key].identity, identity, "which file is meant is not re-recorded");
        assert!(core.state.settings.learned_publishers.is_empty());

        // The permission ends by itself.
        core.state.apps.get_mut(&key).unwrap().rule.as_mut().unwrap().expires = Some(now_secs() - 1);
        core.tick();
        assert_eq!(out_of(&core, &key), Access::Ask);
        assert!(core.state.apps[&key].rule.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_log_says_who_confirmed_a_loosening() {
        let (mut core, dir) = test_core("who");
        let key = add_app(&mut core, r"c:\users\t\downloads\tool.exe", Category::UserSpace, Signature::Unsigned);
        let last_rule_change = |core: &Core| {
            core.events.iter().rev().find_map(|e| match &e.kind {
                EventKind::RuleChanged { by, .. } => Some(by.clone()),
                _ => None,
            })
        };
        ask(&mut core, Request::SetRule { key: key.clone(), rule: rule(RuleAccess::Allow, None) }, true);
        let by = last_rule_change(&core).unwrap().expect("a loosening has a confirmer");
        assert_eq!(by.method, ApprovalMethod::Admin);
        assert!(!by.account.is_empty(), "the account of the elevated client");
        // Tightening needs nobody, whoever does it.
        ask(&mut core, Request::SetRule { key: key.clone(), rule: rule(RuleAccess::Block, None) }, true);
        assert_eq!(last_rule_change(&core), Some(None));
        ask(&mut core, Request::SetRule { key: key.clone(), rule: None }, false);
        assert_eq!(last_rule_change(&core), Some(None));

        ask(&mut core, Request::SetMode(Mode::Strict), false);
        ask(&mut core, Request::SetMode(Mode::Relaxed), true);
        let modes: Vec<Option<ApprovalMethod>> = core
            .events
            .iter()
            .filter_map(|e| if let EventKind::ModeChanged { by, .. } = &e.kind { Some(by.as_ref().map(|b| b.method)) } else { None })
            .collect();
        assert_eq!(modes, vec![None, Some(ApprovalMethod::Admin)]);
        assert!(core.acting.is_none(), "nothing carries over to the next request");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_hello_signature_confirms_exactly_what_was_signed_once() {
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::EncodePublicKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256;
        let (mut core, dir) = test_core("hello");
        let key = add_app(&mut core, r"c:\users\t\downloads\tool.exe", Category::UserSpace, Signature::Unsigned);
        let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let spki = briqwall_common::util::hex(private.to_public_key().to_public_key_der().unwrap().as_bytes());
        let sign = |nonce: &str, payload: &str| {
            briqwall_common::util::hex(&SigningKey::<Sha256>::new(private.clone()).sign(&approval_message(nonce, payload)).to_bytes())
        };
        let challenge = |core: &mut Core| match ask(core, Request::Challenge, false) {
            Response::Challenge(n) => n,
            other => panic!("{other:?}"),
        };
        let allow = serde_json::to_string(&vec![Request::SetRule { key: key.clone(), rule: rule(RuleAccess::Allow, None) }]).unwrap();
        let approved = |nonce: &str, payload: &str, signature: String| Request::Approved {
            nonce: nonce.into(),
            payload: payload.into(),
            signature,
        };

        // No key registered: nothing to check a signature against.
        let n = challenge(&mut core);
        let r = ask(&mut core, approved(&n, &allow, sign(&n, &allow)), false);
        assert!(matches!(r, Response::Error(ErrorCode::HelloNotEnrolled)));

        core.state.hello_keys.push(store::HelloKey { sid: "S-1-5-21-1".into(), name: "Kim".into(), key: spki });

        // A signature over something else does not confirm this.
        let n = challenge(&mut core);
        let off = serde_json::to_string(&vec![Request::SetMode(Mode::Off)]).unwrap();
        assert!(matches!(ask(&mut core, approved(&n, &off, sign(&n, &allow)), false), Response::Denied));
        // The nonce is used up even by a failed attempt.
        assert!(matches!(ask(&mut core, approved(&n, &allow, sign(&n, &allow)), false), Response::Error(ErrorCode::ApprovalExpired)));
        // A nonce the service never issued.
        assert!(matches!(ask(&mut core, approved("abcd", &allow, sign("abcd", &allow)), false), Response::Error(ErrorCode::ApprovalExpired)));
        assert_eq!(out_of(&core, &key), Access::Ask);
        assert_eq!(core.state.settings.mode, Mode::Balanced);

        // Hello cannot register further keys or wrap other requests.
        let n = challenge(&mut core);
        let enroll = serde_json::to_string(&vec![Request::EnrollHello { public_key: "00".into(), sid: "s".into(), name: "n".into() }]).unwrap();
        let r = ask(&mut core, approved(&n, &enroll, sign(&n, &enroll)), false);
        assert!(matches!(r, Response::Error(ErrorCode::NotApprovableWithHello)));
        assert_eq!(core.state.hello_keys.len(), 1);

        // The real thing: applied once, with the signer on record.
        let n = challenge(&mut core);
        assert!(matches!(ask(&mut core, approved(&n, &allow, sign(&n, &allow)), false), Response::Ok));
        assert_eq!(out_of(&core, &key), Access::Allow);
        let by = core.events.iter().rev().find_map(|e| match &e.kind {
            EventKind::RuleChanged { by, .. } => by.clone(),
            _ => None,
        });
        assert_eq!(by, Some(Approval { account: "Kim".into(), method: ApprovalMethod::Hello }));
        // Replaying it does nothing.
        ask(&mut core, Request::SetRule { key: key.clone(), rule: None }, false);
        assert!(matches!(ask(&mut core, approved(&n, &allow, sign(&n, &allow)), false), Response::Error(ErrorCode::ApprovalExpired)));
        assert_eq!(out_of(&core, &key), Access::Ask);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_trusted_program_folder_covers_its_unsigned_tools_in_strict_mode() {
        let (mut core, dir) = test_core("folder");
        core.program_dirs = vec![r"c:\program files".into()];
        ask(&mut core, Request::SetMode(Mode::Strict), false);
        let xargs = add_app(&mut core, r"C:\Program Files\Git\usr\bin\xargs.exe", Category::Installed, Signature::Unsigned);
        let sed = add_app(&mut core, r"C:\Program Files\Git\usr\bin\sed.exe", Category::Installed, Signature::Unsigned);
        let other = add_app(&mut core, r"C:\Program Files\Other\tool.exe", Category::Installed, Signature::Unsigned);
        let download = add_app(&mut core, r"c:\users\t\downloads\tool.exe", Category::UserSpace, Signature::Unsigned);
        assert_eq!(core.state.apps[&xargs].install_folder.as_deref(), Some(r"C:\Program Files\Git"));
        assert_eq!(core.state.apps[&download].install_folder, None);
        assert_eq!(out_of(&core, &xargs), Access::Ask);

        // Not for programs in user folders: "the folder" is whatever lands there.
        assert!(matches!(ask(&mut core, Request::TrustFolder { key: download.clone() }, true), Response::Error(ErrorCode::BadRequest(_))));

        assert!(matches!(ask(&mut core, Request::TrustFolder { key: xargs.clone() }, true), Response::Ok));
        assert_eq!(core.state.settings.trusted_folders, vec![r"C:\Program Files\Git".to_string()]);
        assert_eq!((out_of(&core, &xargs), out_of(&core, &sed)), (Access::Allow, Access::Allow));
        assert_eq!(core.state.apps[&sed].reason, Reason::TrustedFolder(r"C:\Program Files\Git".into()));
        assert_eq!(out_of(&core, &other), Access::Ask, "another product still asks");
        // Trusting it twice changes nothing.
        ask(&mut core, Request::TrustFolder { key: sed.clone() }, true);
        assert_eq!(core.state.settings.trusted_folders.len(), 1);
        let trusted_by = core.events.iter().find_map(|e| if let EventKind::FolderTrusted { by, .. } = &e.kind { by.clone() } else { None });
        assert_eq!(trusted_by.map(|b| b.method), Some(ApprovalMethod::Admin));

        // Anyone may take the trust away again.
        assert!(matches!(ask(&mut core, Request::UntrustFolder(r"c:\program files\git".into()), false), Response::Ok));
        assert_eq!(out_of(&core, &xargs), Access::Ask);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_activity_log_continues_after_a_restart() {
        let (mut core, dir) = test_core("log");
        let key = add_app(&mut core, r"c:\users\t\downloads\tool.exe", Category::UserSpace, Signature::Unsigned);
        ask(&mut core, Request::SetRule { key, rule: rule(RuleAccess::Block, None) }, false);
        let before: Vec<u64> = core.events.iter().map(|e| e.seq).collect();
        assert!(before.len() >= 2, "service start and the rule change");
        core.save();
        drop(core);

        let core = Core::new_with(dir.clone(), Err("test".into()), KnownFiles::default(), false);
        let after: Vec<u64> = core.events.iter().map(|e| e.seq).collect();
        assert_eq!(&after[..before.len()], &before[..], "what happened before is still there");
        assert!(after.len() > before.len(), "plus the new start (and the network it found)");
        assert!(after.windows(2).all(|w| w[0] < w[1]), "numbers go on, none is used twice");
        assert!(matches!(core.events.back().unwrap().kind, EventKind::Started { .. }));
        let _ = std::fs::remove_dir_all(dir);
    }

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
    fn statistics_alone_do_not_rewrite_the_state_file() {
        let secs = Duration::from_secs;
        assert!(!save_due(false, false, secs(3600)));
        assert!(!save_due(true, false, secs(1)));
        assert!(save_due(true, false, secs(3)), "rules and requests within seconds");
        assert!(!save_due(false, true, secs(3)), "counters wait");
        assert!(!save_due(false, true, secs(299)));
        assert!(save_due(false, true, secs(301)), "but not forever");
        assert!(save_due(true, true, secs(3)), "and go along with the next real change");
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
