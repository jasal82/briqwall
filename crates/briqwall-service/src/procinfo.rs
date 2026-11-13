//! Process details for blocked connections: command line and parent chain.
//!
//! WFP's own net events carry no process id, but the Security audit event 5157
//! does. For that pid we read the command line and walk up the parents. Short
//! lived processes (rundll32 often exits right after the failed connect) are
//! covered by a cache the process watcher fills when it first sees a process.

use briqwall_common::{now_secs, ParentProcess, ProcessOrigin};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation, ProcessCommandLineInformation};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
};

const MAX_CMDLINE: usize = 2000;
const MAX_PARENTS: usize = 4;
const CACHE_TTL: Duration = Duration::from_secs(600);

#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    /// Executable file name as reported by the process list.
    pub exe: String,
    pub path: Option<String>,
    pub cmdline: Option<String>,
    /// Creation time (FILETIME as u64) – guards against pid reuse.
    pub created: u64,
    /// Account the process runs as.
    pub user_sid: Option<String>,
}

struct Entry {
    info: ProcInfo,
    seen: Instant,
}

fn cache() -> &'static Mutex<HashMap<u32, Entry>> {
    static C: OnceLock<Mutex<HashMap<u32, Entry>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Called by the process watcher for every process it sees for the first
/// time. `listed`: parent id and file name from the process list, asked for
/// only if the process itself cannot be opened.
pub fn remember(pid: u32, listed: impl FnOnce() -> Option<(u32, String)>) {
    let info = match inspect(pid) {
        Some(info) => info,
        None => {
            let (ppid, exe) = listed().unwrap_or_default();
            ProcInfo { pid, ppid, exe, path: None, cmdline: None, created: 0, user_sid: None }
        }
    };
    let mut c = cache().lock().unwrap();
    c.insert(pid, Entry { info, seen: Instant::now() });
}

/// Keep entries of running processes fresh; drop those gone for a while.
pub fn touch_running(pids: &[u32]) {
    let now = Instant::now();
    let mut c = cache().lock().unwrap();
    for pid in pids {
        if let Some(e) = c.get_mut(pid) {
            e.seen = now;
        }
    }
    c.retain(|_, e| now.duration_since(e.seen) < CACHE_TTL);
}

fn cached(pid: u32) -> Option<ProcInfo> {
    cache().lock().unwrap().get(&pid).map(|e| e.info.clone())
}

/// Live details of a running process.
pub fn inspect(pid: u32) -> Option<ProcInfo> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let info = ProcInfo {
            pid,
            ppid: parent_pid(h).unwrap_or(0),
            exe: String::new(),
            path: crate::watchers::process_path(pid),
            cmdline: command_line(h),
            created: creation_time(h).unwrap_or(0),
            user_sid: owner_sid(h),
        };
        let _ = CloseHandle(h);
        let mut info = info;
        info.exe = info.path.as_deref().map(file_name).unwrap_or_default();
        Some(info)
    }
}

fn file_name(path: &str) -> String {
    path.rsplit(['\u{5c}', '/']).next().unwrap_or(path).to_string()
}

unsafe fn parent_pid(h: HANDLE) -> Option<u32> {
    let mut pbi = PROCESS_BASIC_INFORMATION::default();
    let mut len = 0u32;
    let st = NtQueryInformationProcess(
        h,
        ProcessBasicInformation,
        &mut pbi as *mut _ as *mut _,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        &mut len,
    );
    st.is_ok().then_some(pbi.InheritedFromUniqueProcessId as u32)
}

unsafe fn command_line(h: HANDLE) -> Option<String> {
    // Result: UNICODE_STRING header followed by the characters.
    let mut buf = vec![0u8; 4096];
    for _ in 0..2 {
        let mut len = 0u32;
        let st = NtQueryInformationProcess(h, ProcessCommandLineInformation, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut len);
        if st.is_ok() {
            let us = &*(buf.as_ptr() as *const windows::Win32::Foundation::UNICODE_STRING);
            if us.Buffer.is_null() || us.Length == 0 {
                return None;
            }
            let chars = std::slice::from_raw_parts(us.Buffer.0, (us.Length / 2) as usize);
            let mut s = String::from_utf16_lossy(chars).trim().to_string();
            if s.len() > MAX_CMDLINE {
                let cut = (0..=MAX_CMDLINE).rev().find(|i| s.is_char_boundary(*i)).unwrap_or(0);
                s.truncate(cut);
                s.push('…');
            }
            return Some(s);
        }
        if len as usize > buf.len() && len < 1 << 20 {
            buf = vec![0u8; len as usize];
        } else {
            return None;
        }
    }
    None
}

unsafe fn owner_sid(h: HANDLE) -> Option<String> {
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::OpenProcessToken;
    let mut token = HANDLE::default();
    OpenProcessToken(h, TOKEN_QUERY, &mut token).ok()?;
    let sid = crate::trust::token_user_sid(token);
    let _ = CloseHandle(token);
    sid
}

unsafe fn creation_time(h: HANDLE) -> Option<u64> {
    let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u).ok()?;
    Some(((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64)
}

/// Details for `pid`, verified against the expected image path (lower-case
/// DOS path) to rule out pid reuse. Prefers live data, falls back to the cache.
pub fn lookup(pid: u32, expected_path: Option<&str>) -> Option<ProcInfo> {
    let matches = |i: &ProcInfo| match (expected_path, &i.path) {
        (Some(e), Some(p)) => p.eq_ignore_ascii_case(e),
        _ => true,
    };
    let live = inspect(pid).filter(|i| matches(i));
    let mut info = live.or_else(|| cached(pid).filter(|i| matches(i)))?;
    if info.cmdline.is_none() {
        // The cache may know the command line from when the process started.
        if let Some(c) = cached(pid).filter(|c| c.created == info.created || info.created == 0) {
            info.cmdline = c.cmdline;
        }
    }
    Some(info)
}

/// Build the origin for a blocked attempt: command line plus parent chain.
pub fn origin(pid: u32, expected_path: Option<&str>) -> Option<ProcessOrigin> {
    let me = lookup(pid, expected_path)?;
    let mut parents = Vec::new();
    let mut child = me.clone();
    while parents.len() < MAX_PARENTS && child.ppid > 4 {
        let Some(p) = inspect(child.ppid).or_else(|| cached(child.ppid)) else { break };
        // A parent created *after* its child is a reused pid, not the real parent.
        if p.created != 0 && child.created != 0 && p.created > child.created {
            break;
        }
        let name = if p.exe.is_empty() { p.path.as_deref().map(file_name).unwrap_or_default() } else { p.exe.clone() };
        if name.is_empty() {
            break;
        }
        parents.push(ParentProcess { pid: p.pid, name, path: p.path.clone() });
        child = p;
    }
    Some(ProcessOrigin { pid, command_line: me.cmdline, parents, last_seen: now_secs(), count: 1, owner_sid: me.user_sid })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_own_process() {
        let me = std::process::id();
        let info = inspect(me).expect("own process");
        assert!(info.path.as_deref().unwrap_or("").to_lowercase().ends_with(".exe"));
        assert!(info.cmdline.is_some(), "command line of own process");
        assert!(info.ppid > 0);
        assert!(info.created > 0);
        assert!(info.user_sid.as_deref().is_some_and(|s| s.starts_with("S-1-")), "{:?}", info.user_sid);
        assert_eq!(origin(me, None).expect("origin").owner_sid, info.user_sid);
    }

    #[test]
    fn origin_has_parent_chain() {
        let o = origin(std::process::id(), None).expect("origin");
        assert!(!o.parents.is_empty(), "test runner has a parent (cargo)");
        assert!(o.parents.iter().all(|p| !p.name.is_empty()));
    }
}
