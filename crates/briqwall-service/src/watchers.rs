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

/// Polls the process list and reports every newly started process with its
/// image path. This lets Briqwall evaluate (and usually permit) an app *before*
/// its first connection attempt.
pub fn spawn_process_watcher(tx: Sender<Msg>) {
    std::thread::Builder::new()
        .name("procwatch".into())
        .spawn(move || {
            let mut known: HashSet<u32> = HashSet::new();
            loop {
                let mut current = HashSet::with_capacity(known.len() + 16);
                for pid in list_pids() {
                    current.insert(pid);
                    if !known.contains(&pid) {
                        if let Some(path) = process_path(pid) {
                            if tx.send(Msg::Process { path }).is_err() {
                                return;
                            }
                        }
                    }
                }
                known = current;
                std::thread::sleep(Duration::from_millis(250));
            }
        })
        .expect("spawn procwatch");
}

pub fn list_pids() -> Vec<u32> {
    let mut out = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return out };
        let mut pe = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                if pe.th32ProcessID > 4 {
                    out.push(pe.th32ProcessID);
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
    }

    /// `\device\harddiskvolume3\windows\x.exe` -> `c:\windows\x.exe` (lower-case).
    pub fn to_dos(&mut self, dev_path: &str) -> Option<String> {
        let lower = dev_path.to_lowercase();
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

/// WFP only produces classify-drop events if the corresponding audit
/// subcategories are enabled. Uses auditpol with GUIDs (language independent).
/// Returns true if we changed the setting (so uninstall can revert it).
pub fn ensure_audit_policy() -> bool {
    // Filtering Platform Connection, Filtering Platform Packet Drop
    const SUBCATS: [&str; 2] = ["{0CCE9226-69AE-11D9-BED3-505054503030}", "{0CCE9225-69AE-11D9-BED3-505054503030}"];
    let mut changed = false;
    for sc in SUBCATS {
        let cur = std::process::Command::new("auditpol.exe")
            .args(["/get", &format!("/subcategory:{sc}"), "/r"])
            .output();
        let enabled = cur
            .ok()
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout).to_lowercase();
                // CSV: "...,Inclusion Setting,..." values like "Failure" / "Success and Failure"
                s.lines().skip(1).any(|l| l.contains("failure") || l.contains("fehler"))
            })
            .unwrap_or(false);
        if !enabled {
            let ok = std::process::Command::new("auditpol.exe")
                .args(["/set", &format!("/subcategory:{sc}"), "/failure:enable"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            changed |= ok;
            log::info!("Audit-Richtlinie {sc} aktiviert: {ok}");
        }
    }
    changed
}

pub fn revert_audit_policy() {
    for sc in ["{0CCE9226-69AE-11D9-BED3-505054503030}", "{0CCE9225-69AE-11D9-BED3-505054503030}"] {
        let _ = std::process::Command::new("auditpol.exe")
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
