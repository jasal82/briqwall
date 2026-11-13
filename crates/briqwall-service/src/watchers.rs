//! Background sources feeding the core: process starts, WFP drop events,
//! and network (NLM) state.

use crate::core::Msg;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::Sender;
use std::time::Duration;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use briqwall_common::util::{from_wide, wide};
use briqwall_common::{NetCategory, NetworkInfo};

// ---------------------------------------------------------------------------
// Process watcher
// ---------------------------------------------------------------------------

/// Polls the process ids and reports the image path of every newly started
/// process. This lets Briqwall evaluate (and usually permit) an app *before*
/// its first connection attempt.
///
/// Five times a second, so it has to be cheap: only the list of ids is
/// read. A full snapshot of all processes (names, parents, thread counts)
/// costs over two hundred times as much and is taken only when a new
/// process cannot be opened to ask it directly.
pub fn spawn_process_watcher(tx: Sender<String>) {
    std::thread::Builder::new()
        .name("procwatch".into())
        .spawn(move || {
            let mut known: HashSet<u32> = HashSet::new();
            let mut last_touch = std::time::Instant::now();
            loop {
                let pids = list_pids();
                let mut snapshot: Option<HashMap<u32, (u32, String)>> = None;
                for pid in &pids {
                    if known.contains(pid) {
                        continue;
                    }
                    // Remember command line and parent while the process
                    // still exists (short-lived tools exit quickly).
                    crate::procinfo::remember(*pid, || {
                        snapshot
                            .get_or_insert_with(|| list_processes().into_iter().map(|(pid, ppid, exe)| (pid, (ppid, exe))).collect())
                            .get(pid)
                            .cloned()
                    });
                    if let Some(path) = process_path(*pid) {
                        if tx.send(path).is_err() {
                            return;
                        }
                    }
                }
                // Keeps cached details of running processes alive; they
                // expire after minutes, so once a second is plenty.
                if last_touch.elapsed() >= Duration::from_secs(1) {
                    crate::procinfo::touch_running(&pids);
                    last_touch = std::time::Instant::now();
                }
                known.clear();
                known.extend(&pids);
                std::thread::sleep(Duration::from_millis(200));
            }
        })
        .expect("spawn procwatch");
}

/// Ids of all processes except Idle/System.
pub fn list_pids() -> Vec<u32> {
    use windows::Win32::System::ProcessStatus::EnumProcesses;
    let mut pids = vec![0u32; 2048];
    loop {
        let bytes = (pids.len() * 4) as u32;
        let mut used = 0u32;
        if unsafe { EnumProcesses(pids.as_mut_ptr(), bytes, &mut used) }.is_err() {
            // Should not happen; the snapshot is the slow but sure way.
            return list_processes().into_iter().map(|p| p.0).collect();
        }
        if used < bytes {
            pids.truncate(used as usize / 4);
            pids.retain(|pid| *pid > 4);
            return pids;
        }
        // Filled to the brim: there may be more.
        pids = vec![0u32; pids.len() * 2];
    }
}

/// (pid, parent pid, exe file name) of all processes except Idle/System.
pub fn list_processes() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return out };
        let mut pe = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                if pe.th32ProcessID > 4 {
                    out.push((pe.th32ProcessID, pe.th32ParentProcessID, from_wide(&pe.szExeFile)));
                }
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

pub fn process_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let r = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(h);
        r.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

// ---------------------------------------------------------------------------
// NT device path -> DOS path
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct DevMap {
    map: Vec<(String, String)>, // ("\device\harddiskvolume3", "c:")
}

impl DevMap {
    pub fn refresh(&mut self) {
        self.map.clear();
        let drives = unsafe { GetLogicalDrives() };
        for i in 0..26u32 {
            if drives & (1 << i) == 0 {
                continue;
            }
            let letter = format!("{}:", (b'A' + i as u8) as char);
            let w = wide(&letter);
            let mut buf = [0u16; 512];
            let n = unsafe { QueryDosDeviceW(PCWSTR(w.as_ptr()), Some(&mut buf)) };
            if n > 0 {
                let dev = from_wide(&buf).to_lowercase();
                self.map.push((dev, letter.to_lowercase()));
            }
        }
        // Volumes without a drive letter: mounted into a folder, or not
        // mounted at all. Without them a program there would be blocked
        // without ever showing up as a request.
        for (dev, path) in mounted_volumes() {
            if !self.map.iter().any(|(known, _)| *known == dev) {
                self.map.push((dev, path));
            }
        }
    }

    /// `\device\harddiskvolume3\windows\x.exe` -> `c:\windows\x.exe` (lower-case).
    pub fn to_dos(&mut self, dev_path: &str) -> Option<String> {
        let lower = dev_path.to_lowercase();
        // A program on a network share: the redirector device, then server
        // and share. Its Win32 name is the UNC path.
        if let Some(rest) = lower.strip_prefix(r"\device\mup\") {
            return (!rest.is_empty()).then(|| format!(r"\\{rest}"));
        }
        for attempt in 0..2 {
            for (dev, letter) in &self.map {
                if let Some(rest) = lower.strip_prefix(dev.as_str()) {
                    if rest.starts_with('\\') {
                        return Some(format!("{letter}{rest}"));
                    }
                }
            }
            if attempt == 0 {
                self.refresh();
            }
        }
        None
    }
}

/// Every volume Windows knows, as (NT device, Win32 path), both lower-case
/// and without trailing backslash. The path is the drive letter or folder
/// the volume is mounted at, or its `\\?\Volume{…}` name if it has neither.
fn mounted_volumes() -> Vec<(String, String)> {
    use windows::Win32::Storage::FileSystem::{
        FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumePathNamesForVolumeNameW,
    };
    let mut out = Vec::new();
    unsafe {
        let mut name = [0u16; 64]; // "\\?\Volume{GUID}\" is 49 characters
        let Ok(find) = FindFirstVolumeW(&mut name) else { return out };
        loop {
            let volume = from_wide(&name);
            // QueryDosDevice wants the name without prefix and trailing backslash.
            if let Some(inner) = volume.strip_prefix(r"\\?\").and_then(|v| v.strip_suffix('\\')) {
                let w = wide(inner);
                let mut dev = [0u16; 512];
                if QueryDosDeviceW(PCWSTR(w.as_ptr()), Some(&mut dev)) > 0 {
                    let wvol = wide(&volume);
                    let mut paths = [0u16; 1024];
                    let mut len = 0u32;
                    // A list of strings; the first is the preferred mount point.
                    let mounted = GetVolumePathNamesForVolumeNameW(PCWSTR(wvol.as_ptr()), Some(&mut paths), &mut len)
                        .map(|()| from_wide(&paths))
                        .unwrap_or_default();
                    let path = if mounted.is_empty() { volume.clone() } else { mounted };
                    out.push((from_wide(&dev).to_lowercase(), path.trim_end_matches('\\').to_lowercase()));
                }
            }
            name = [0u16; 64];
            if FindNextVolumeW(find, &mut name).is_err() {
                break;
            }
        }
        let _ = FindVolumeClose(find);
    }
    out
}

// ---------------------------------------------------------------------------
// WFP net events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NetEvt {
    pub filter_id: u64,
    pub app_id: Vec<u8>,
    pub proto: u8,
    pub remote: Option<IpAddr>,
    pub remote_port: u16,
    pub local_port: u16,
}

/// Context handed to the WFP callback. Leaked on purpose: it must live as long
/// as the subscription, which lives as long as the process.
pub struct NetEventCtx {
    pub tx: Sender<Msg>,
}

pub unsafe extern "system" fn net_event_callback(ctx: *mut core::ffi::c_void, ev: *const FWPM_NET_EVENT1) {
    if ctx.is_null() || ev.is_null() {
        return;
    }
    let ctx = &*(ctx as *const NetEventCtx);
    let ev = &*ev;
    if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return;
    }
    let drop_info = ev.Anonymous.classifyDrop;
    if drop_info.is_null() {
        return;
    }
    let h = &ev.header;
    let app_id = if h.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET != 0 && !h.appId.data.is_null() {
        std::slice::from_raw_parts(h.appId.data, h.appId.size as usize).to_vec()
    } else {
        Vec::new()
    };
    let remote = if h.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET != 0 {
        if h.ipVersion == FWP_IP_VERSION_V4 {
            Some(IpAddr::V4(Ipv4Addr::from(h.Anonymous2.remoteAddrV4)))
        } else {
            Some(IpAddr::V6(Ipv6Addr::from(h.Anonymous2.remoteAddrV6.byteArray16)))
        }
    } else {
        None
    };
    let evt = NetEvt {
        filter_id: (*drop_info).filterId,
        app_id,
        proto: if h.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET != 0 { h.ipProtocol } else { 0 },
        remote,
        remote_port: if h.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET != 0 { h.remotePort } else { 0 },
        local_port: h.localPort,
    };
    let _ = ctx.tx.send(Msg::Net(evt));
}

/// Audit subcategories WFP needs for classify-drop events:
/// Filtering Platform Connection, Filtering Platform Packet Drop.
pub const AUDIT_SUBCATEGORIES: [(&str, u128); 2] = [
    ("{0CCE9226-69AE-11D9-BED3-505054503030}", 0x0CCE9226_69AE_11D9_BED3_505054503030),
    ("{0CCE9225-69AE-11D9-BED3-505054503030}", 0x0CCE9225_69AE_11D9_BED3_505054503030),
];

/// WFP only produces classify-drop events if the corresponding audit
/// subcategories are enabled. Returns the subcategories (GUID strings) that
/// *we* switched on, so uninstall reverts exactly those and leaves alone
/// what the administrator had enabled before.
pub fn ensure_audit_policy() -> Vec<String> {
    let mut enabled_by_us = Vec::new();
    let auditpol = auditpol_exe();
    let privileged = enable_security_privilege();
    for (sc, guid) in AUDIT_SUBCATEGORIES {
        // Ask Windows directly: the answer is a number. Only if that fails,
        // read the words auditpol prints – they depend on the display
        // language, and an unknown language reads as "off". The setting would
        // then be recorded as ours and switched off again on uninstall.
        let enabled = match privileged.then(|| failure_auditing(guid)).flatten() {
            Some(on) => on,
            None => std::process::Command::new(&auditpol)
                .args(["/get", &format!("/subcategory:{sc}"), "/r"])
                .output()
                .map(|o| csv_says_failure(&String::from_utf8_lossy(&o.stdout)))
                .unwrap_or(false),
        };
        if !enabled {
            let ok = std::process::Command::new(&auditpol)
                .args(["/set", &format!("/subcategory:{sc}"), "/failure:enable"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                enabled_by_us.push(sc.to_string());
            }
            log::info!("Audit-Richtlinie {sc} aktiviert: {ok}");
        }
    }
    enabled_by_us
}

/// CSV of `auditpol /get /r`: "...,Inclusion Setting,..." with values like
/// "Failure" / "Success and Failure" – in the display language of Windows.
fn csv_says_failure(stdout: &str) -> bool {
    stdout.to_lowercase().lines().skip(1).any(|l| l.contains("failure") || l.contains("fehler"))
}

/// Is failure auditing on for this subcategory? `None` if Windows does not
/// tell (the call needs the security privilege).
fn failure_auditing(subcategory: u128) -> Option<bool> {
    use windows::Win32::Security::Authentication::Identity::{AuditFree, AuditQuerySystemPolicy, AUDIT_POLICY_INFORMATION};
    const POLICY_AUDIT_EVENT_FAILURE: u32 = 0x2;
    let guids = [windows::core::GUID::from_u128(subcategory)];
    unsafe {
        let mut info: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
        if !AuditQuerySystemPolicy(&guids, &mut info) || info.is_null() {
            return None;
        }
        let on = (*info).AuditingInformation & POLICY_AUDIT_EVENT_FAILURE != 0;
        AuditFree(info as *const _);
        Some(on)
    }
}

/// Reading the audit policy needs SeSecurityPrivilege. SYSTEM and elevated
/// administrators hold it, but switched off.
fn enable_security_privilege() -> bool {
    use windows::Win32::Foundation::{GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let name = wide("SeSecurityPrivilege");
    unsafe {
        let mut luid = LUID::default();
        if LookupPrivilegeValueW(None, PCWSTR(name.as_ptr()), &mut luid).is_err() {
            return false;
        }
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        let adjusted = AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None).is_ok();
        // Success with this code means: the token does not hold the privilege.
        let held = adjusted && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
        let _ = CloseHandle(token);
        held
    }
}

/// Full path of auditpol.exe. A bare name would be looked up next to our own
/// executable first – and the service runs as SYSTEM.
fn auditpol_exe() -> String {
    format!("{}\\system32\\auditpol.exe", crate::trust::windows_dir())
}

/// Switch failure auditing off again for the given subcategories (those
/// [`ensure_audit_policy`] reported). Anything else is ignored.
pub fn revert_audit_policy(subcategories: &[String]) {
    let auditpol = auditpol_exe();
    for (sc, _) in AUDIT_SUBCATEGORIES {
        if !subcategories.iter().any(|s| s.eq_ignore_ascii_case(sc)) {
            continue;
        }
        let _ = std::process::Command::new(&auditpol)
            .args(["/set", &format!("/subcategory:{sc}"), "/failure:disable"])
            .status();
    }
}

// ---------------------------------------------------------------------------
// Network List Manager
// ---------------------------------------------------------------------------

pub struct NetworkWatcher {
    nlm: Option<windows::Win32::Networking::NetworkListManager::INetworkListManager>,
}

impl NetworkWatcher {
    /// Must be called on the thread that will use it.
    pub fn new() -> Self {
        use windows::Win32::Networking::NetworkListManager::{INetworkListManager, NetworkListManager};
        use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED};
        let nlm = unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            CoCreateInstance::<_, INetworkListManager>(&NetworkListManager, None, CLSCTX_ALL).ok()
        };
        if nlm.is_none() {
            log::warn!("NetworkListManager nicht verfügbar");
        }
        Self { nlm }
    }

    /// Connected networks with their Windows category (trust not yet applied).
    pub fn connected(&self) -> Vec<NetworkInfo> {
        use windows::Win32::Networking::NetworkListManager::*;
        let mut out = Vec::new();
        let Some(nlm) = &self.nlm else { return out };
        unsafe {
            let Ok(en) = nlm.GetNetworks(NLM_ENUM_NETWORK_CONNECTED) else { return out };
            loop {
                let mut item = [None];
                let mut fetched = 0u32;
                if en.Next(&mut item, Some(&mut fetched)).is_err() || fetched == 0 {
                    break;
                }
                let Some(net) = item[0].take() else { break };
                let name = net.GetName().map(|b| b.to_string()).unwrap_or_default();
                let id = net.GetNetworkId().map(|g| format!("{g:?}")).unwrap_or_default();
                let cat = net.GetCategory().unwrap_or(NLM_NETWORK_CATEGORY_PUBLIC);
                let windows_category = match cat {
                    NLM_NETWORK_CATEGORY_PRIVATE => NetCategory::Private,
                    NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED => NetCategory::Domain,
                    _ => NetCategory::Public,
                };
                out.push(NetworkInfo {
                    id,
                    name,
                    windows_category,
                    trusted: cat != NLM_NETWORK_CATEGORY_PUBLIC,
                    explicit: false,
                });
            }
        }
        out
    }
}

/// Apply Briqwall's own trust overrides.
pub fn apply_trust(mut nets: Vec<NetworkInfo>, overrides: &std::collections::BTreeMap<String, bool>) -> Vec<NetworkInfo> {
    for n in &mut nets {
        if let Some(t) = overrides.get(&n.id) {
            n.trusted = *t;
            n.explicit = true;
        }
    }
    nets
}

/// Coalesces repeated block events (apps retry aggressively).
#[derive(Default)]
pub struct Coalescer {
    last: HashMap<String, std::time::Instant>,
}

impl Coalescer {
    pub fn should_log(&mut self, key: &str, window: Duration) -> bool {
        let now = std::time::Instant::now();
        if self.last.len() > 4096 {
            self.last.retain(|_, t| now.duration_since(*t) < window);
        }
        match self.last.get(key) {
            Some(t) if now.duration_since(*t) < window => false,
            _ => {
                self.last.insert(key.to_string(), now);
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Security audit 5157: process id of a blocked connection
// ---------------------------------------------------------------------------

/// Fields of a "WFP blocked a connection" audit event.
#[derive(Debug, PartialEq)]
pub struct DropAudit {
    pub pid: u32,
    /// NT device path of the application.
    pub app: String,
    pub filter_id: u64,
}

/// Ids of Briqwall's blocking filters (kept current by the core). Drops by
/// other filters – Windows Firewall, other security software – are ignored
/// before any process is inspected.
fn block_filters() -> &'static std::sync::RwLock<HashSet<u64>> {
    static F: std::sync::OnceLock<std::sync::RwLock<HashSet<u64>>> = std::sync::OnceLock::new();
    F.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

pub fn set_block_filters(ids: impl Iterator<Item = u64>) {
    *block_filters().write().unwrap() = ids.collect();
}

struct AuditCtx {
    tx: Sender<Msg>,
    devmap: std::sync::Mutex<DevMap>,
}

/// Subscribe to event 5157 in the Security log. Windows writes it because the
/// service enables failure auditing for "Filtering Platform Connection".
pub fn subscribe_drop_audit(tx: Sender<Msg>) -> anyhow::Result<()> {
    use windows::Win32::System::EventLog::{EvtSubscribe, EvtSubscribeToFutureEvents};
    let mut devmap = DevMap::default();
    devmap.refresh();
    // Leaked on purpose: lives as long as the subscription (= the process).
    let ctx: &'static AuditCtx = Box::leak(Box::new(AuditCtx { tx, devmap: std::sync::Mutex::new(devmap) }));
    let channel = wide("Security");
    let query = wide("*[System[(EventID=5157)]]");
    unsafe {
        EvtSubscribe(
            None,
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            None,
            Some(ctx as *const AuditCtx as *const core::ffi::c_void),
            Some(audit_callback),
            EvtSubscribeToFutureEvents.0,
        )?;
    }
    Ok(())
}

unsafe extern "system" fn audit_callback(
    action: windows::Win32::System::EventLog::EVT_SUBSCRIBE_NOTIFY_ACTION,
    ctx: *const core::ffi::c_void,
    event: windows::Win32::System::EventLog::EVT_HANDLE,
) -> u32 {
    use windows::Win32::System::EventLog::EvtSubscribeActionDeliver;
    if action != EvtSubscribeActionDeliver || ctx.is_null() {
        return 0;
    }
    let ctx = &*(ctx as *const AuditCtx);
    let Some(xml) = render_xml(event) else {
        log::warn!("Audit 5157: Ereignis nicht darstellbar");
        return 0;
    };
    let Some(audit) = parse_drop_audit(&xml) else {
        // Log the format once so a mismatch can be diagnosed.
        static LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !LOGGED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            log::warn!("Audit 5157 nicht lesbar: {}", xml.chars().take(800).collect::<String>());
        }
        return 0;
    };
    if !block_filters().read().unwrap().contains(&audit.filter_id) {
        return 0; // blocked by someone else
    }
    let path = ctx.devmap.lock().unwrap().to_dos(&audit.app);
    match crate::procinfo::origin(audit.pid, path.as_deref()) {
        Some(origin) => {
            let _ = ctx.tx.send(Msg::Origin { filter_id: audit.filter_id, path, origin });
        }
        None => log::debug!("Herkunft PID {} ({:?}) nicht ermittelbar", audit.pid, path),
    }
    0
}

unsafe fn render_xml(event: windows::Win32::System::EventLog::EVT_HANDLE) -> Option<String> {
    use windows::Win32::System::EventLog::{EvtRender, EvtRenderEventXml};
    let (mut used, mut props) = (0u32, 0u32);
    let _ = EvtRender(None, event, EvtRenderEventXml.0, 0, None, &mut used, &mut props);
    if used == 0 {
        return None;
    }
    let mut buf = vec![0u16; (used as usize).div_ceil(2) + 1];
    EvtRender(
        None,
        event,
        EvtRenderEventXml.0,
        (buf.len() * 2) as u32,
        Some(buf.as_mut_ptr() as *mut _),
        &mut used,
        &mut props,
    )
    .ok()?;
    Some(from_wide(&buf))
}

/// Value of `<Data Name='…'>value</Data>`. EvtRender uses single quotes for
/// attributes; double quotes are accepted as well.
fn xml_data<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let start = ['\'', '"'].iter().find_map(|q| {
        let open = format!("Name={q}{name}{q}>");
        xml.find(&open).map(|i| i + open.len())
    })?;
    let end = xml[start..].find("</Data>")? + start;
    Some(&xml[start..end])
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

pub fn parse_drop_audit(xml: &str) -> Option<DropAudit> {
    Some(DropAudit {
        pid: xml_data(xml, "ProcessID")?.trim().parse().ok()?,
        app: xml_unescape(xml_data(xml, "Application")?.trim()),
        filter_id: xml_data(xml, "FilterRTID")?.trim().parse().ok()?,
    })
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    #[test]
    fn devices_map_to_the_paths_programs_run_from() {
        let mut m = DevMap::default();
        m.refresh();
        let win = crate::trust::windows_dir();
        let letter = &win[..2];
        let dev = m.map.iter().find(|(_, p)| p == letter).map(|(d, _)| d.clone()).expect("system volume is mapped");
        assert_eq!(m.to_dos(&format!(r"{dev}\Windows\X.exe")), Some(format!(r"{letter}\windows\x.exe")));
        assert_eq!(m.to_dos(r"\Device\Mup\Server\Share\x.exe").as_deref(), Some(r"\\server\share\x.exe"));
        assert_eq!(m.to_dos(r"\device\mup\"), None);
        assert_eq!(m.to_dos(r"\device\nosuchvolume99\x.exe"), None);

        // Every volume Windows knows resolves, with or without a drive letter.
        let volumes = mounted_volumes();
        assert!(!volumes.is_empty());
        for (device, path) in volumes {
            println!("{device} -> {path}");
            assert!(!path.is_empty() && !path.ends_with('\\'));
            assert!(m.to_dos(&format!(r"{device}\x.exe")).is_some(), "{device}");
        }
    }

    #[test]
    fn audit_state_does_not_depend_on_the_language_when_windows_answers() {
        // English and German auditpol output is understood …
        let csv = |setting: &str| format!("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\nPC,System,X,{{0CCE9226-69AE-11D9-BED3-505054503030}},{setting},\n");
        assert!(csv_says_failure(&csv("Failure")));
        assert!(csv_says_failure(&csv("Success and Failure")));
        assert!(csv_says_failure(&csv("Fehler")));
        assert!(!csv_says_failure(&csv("No Auditing")));
        // … French is not, which is why the text is only the fallback.
        assert!(!csv_says_failure(&csv("Échec")));

        // Without the privilege (tests run as a normal user) Windows does not
        // answer; with it (CI runs elevated) it answers for both subcategories.
        let privileged = enable_security_privilege();
        for (_, guid) in AUDIT_SUBCATEGORIES {
            let state = failure_auditing(guid);
            println!("privileged={privileged} failure auditing={state:?}");
            if privileged {
                assert!(state.is_some());
            }
        }
    }

    #[test]
    fn only_listed_subcategories_are_known() {
        for (text, guid) in AUDIT_SUBCATEGORIES {
            let hex = format!("{guid:032X}");
            assert_eq!(text.replace(['{', '}', '-'], ""), hex);
        }
    }

    #[test]
    fn parses_5157_event() {
        let bs = std::char::from_u32(0x5c).unwrap();
        let app = format!("{bs}device{bs}harddiskvolume3{bs}windows{bs}system32{bs}rundll32.exe");
        let xml = format!(
            "<Event><System><EventID>5157</EventID></System><EventData>\
             <Data Name=\"ProcessID\">4711</Data>\
             <Data Name=\"Application\">{app}</Data>\
             <Data Name=\"Direction\">%%14593</Data>\
             <Data Name=\"DestAddress\">93.184.216.34</Data>\
             <Data Name=\"DestPort\">443</Data>\
             <Data Name=\"FilterRTID\">123456</Data>\
             </EventData></Event>"
        );
        let a = parse_drop_audit(&xml).expect("parsed");
        assert_eq!(a, DropAudit { pid: 4711, app: app.clone(), filter_id: 123456 });
        assert!(parse_drop_audit("<Event/>").is_none());

        // The format EvtRender actually produces: single-quoted attributes,
        // namespace on <Event>, everything on one line.
        let real = format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5157</EventID></System>\
             <EventData><Data Name='ProcessID'>9412</Data><Data Name='Application'>{app}</Data>\
             <Data Name='Direction'>%%14593</Data><Data Name='FilterRTID'>70321</Data>\
             <Data Name='LayerName'>%%14611</Data><Data Name='LayerRTID'>48</Data></EventData></Event>"
        );
        assert_eq!(parse_drop_audit(&real), Some(DropAudit { pid: 9412, app, filter_id: 70321 }));
    }
}
