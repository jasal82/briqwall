//! Hostnames for blocked connections.
//!
//! An IP address says little ("45.133.1.20:443"), the name the program asked
//! for says a lot ("telemetry.example.com"). Windows' DNS client writes every
//! lookup as an ETW event, so the service listens to that trace and remembers
//! which name resolved to which address. The cache lives in memory only and
//! is read when a blocked attempt is turned into an event.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows::Win32::System::Diagnostics::Etw::*;

/// Microsoft-Windows-DNS-Client.
const DNS_PROVIDER: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
/// "DNS query completed" – carries the queried name and the addresses.
const EVENT_QUERY_COMPLETED: u16 = 3008;
const SESSION: &str = "Briqwall-DNS";
/// What `OpenTraceW` returns on failure (INVALID_PROCESSTRACE_HANDLE).
const INVALID_TRACE: u64 = u64::MAX;
const MAX_ENTRIES: usize = 4096;
const TTL_SECS: u64 = 3 * 3600;

struct Entry {
    host: String,
    seen: u64,
    verified: bool,
}

/// A name for an address, and whether it can be relied on.
///
/// Anyone can write events in the DNS client's name, so a program can claim
/// to have looked up "update.microsoft.com" for the address of its own
/// server. Windows stamps every event with the process that wrote it, and
/// that cannot be faked: a name counts as verified if it was reported by a
/// program only administrators can modify (and that is no scripting tool).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub verified: bool,
}

fn cache() -> &'static RwLock<HashMap<IpAddr, Entry>> {
    static C: std::sync::OnceLock<RwLock<HashMap<IpAddr, Entry>>> = std::sync::OnceLock::new();
    C.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Handle of the running trace session, so it can be stopped on shutdown.
static SESSION_HANDLE: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The name that was looked up for this address, if it is still known.
pub fn lookup(ip: IpAddr) -> Option<Host> {
    let c = cache().read().ok()?;
    let e = c.get(&ip)?;
    (now_secs().saturating_sub(e.seen) <= TTL_SECS).then(|| Host { name: e.host.clone(), verified: e.verified })
}

fn remember(ip: IpAddr, host: &str, verified: bool) {
    let now = now_secs();
    let Ok(mut c) = cache().write() else { return };
    // A claim does not replace what a trustworthy source reported.
    if !verified && c.get(&ip).is_some_and(|e| e.verified && now.saturating_sub(e.seen) <= TTL_SECS) {
        return;
    }
    if c.len() >= MAX_ENTRIES {
        c.retain(|_, e| now.saturating_sub(e.seen) <= TTL_SECS);
        if c.len() >= MAX_ENTRIES {
            c.clear(); // pathological case: start over rather than grow
        }
    }
    c.insert(ip, Entry { host: host.to_string(), seen: now, verified });
}

/// A DNS name as it may be shown: letters, digits, dots, hyphens and
/// underscores (international names arrive in their ASCII form). Anything
/// else (spaces, look-alike characters) is not a name a lookup produces.
fn valid_hostname(name: &str) -> Option<&str> {
    let name = name.trim_end_matches('.');
    let ok = !name.is_empty()
        && name.len() <= 253
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    ok.then_some(name)
}

/// Did a program write this event that only administrators can modify?
/// Remembered per process for a while, lookups come in bursts.
fn emitter_trusted(pid: u32) -> bool {
    const KEEP_SECS: u64 = 60;
    static SEEN: std::sync::OnceLock<std::sync::Mutex<HashMap<u32, (bool, u64)>>> = std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let now = now_secs();
    if let Ok(map) = seen.lock() {
        if let Some((trusted, at)) = map.get(&pid) {
            if now.saturating_sub(*at) <= KEEP_SECS {
                return *trusted;
            }
        }
    }
    let trusted = crate::procinfo::lookup(pid, None).and_then(|i| i.path).is_some_and(|path| {
        let file = path.rsplit('\\').next().unwrap_or_default().to_lowercase();
        !crate::policy::is_lolbin(&file) && crate::trust::is_protected(&path)
    });
    if let Ok(mut map) = seen.lock() {
        if map.len() >= 2048 {
            map.retain(|_, (_, at)| now.saturating_sub(*at) <= KEEP_SECS);
        }
        map.insert(pid, (trusted, now));
    }
    trusted
}

// ---------------------------------------------------------------- parsing

/// UTF-16 string at the start of `data`, plus the offset just behind it.
fn wide_at(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut units = Vec::new();
    let mut i = start;
    while i + 1 < data.len() {
        let u = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;
        if u == 0 {
            return Some((String::from_utf16_lossy(&units), i));
        }
        units.push(u);
    }
    None
}

/// Every NUL-terminated UTF-16 string in the buffer, in order. The numeric
/// fields in between decode as nonsense, which simply yields no addresses –
/// more robust than walking a layout that differs between Windows versions.
fn wide_chunks(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some((text, next)) = wide_at(data, pos) {
        out.push(text);
        pos = next;
    }
    out
}

/// One entry of the `QueryResults` field: either "1.2.3.4" or, for records
/// that are not addresses, something like "type: 5 www.example.com".
fn result_address(item: &str) -> Option<IpAddr> {
    let text = match item.rsplit_once(' ') {
        Some((head, tail)) if head.starts_with("type:") => tail,
        _ => item,
    }
    .trim();
    match text.parse::<IpAddr>().ok()? {
        // The DNS client reports IPv4 answers in the IPv4-mapped IPv6 form.
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))),
        v4 => Some(v4),
    }
}

/// Queried name and the addresses it resolved to, from the user data of
/// event 3008 (QueryName … QueryResults).
fn parse_query_completed(data: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    let chunks = wide_chunks(data);
    let name = chunks.first()?.clone();
    if name.is_empty() {
        return None;
    }
    // QueryResults is the first field after the name that holds addresses.
    let addrs: Vec<IpAddr> = chunks[1..]
        .iter()
        .map(|c| c.split(';').filter_map(result_address).collect::<Vec<_>>())
        .find(|a: &Vec<IpAddr>| !a.is_empty())?;
    Some((name, addrs))
}

// ---------------------------------------------------------------- ETW session

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    let Some(rec) = record.as_ref() else { return };
    if rec.EventHeader.EventDescriptor.Id != EVENT_QUERY_COMPLETED || rec.UserData.is_null() {
        return;
    }
    let data = std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize);
    if let Some((name, addrs)) = parse_query_completed(data) {
        let Some(name) = valid_hostname(&name) else { return };
        let verified = emitter_trusted(rec.EventHeader.ProcessId);
        for ip in addrs {
            remember(ip, name, verified);
        }
    }
}

/// Properties block: the struct followed by the session name.
fn properties(name: &[u16]) -> Vec<u8> {
    let head = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let mut buf = vec![0u8; head + name.len() * 2];
    unsafe {
        let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*p).Wnode.BufferSize = buf.len() as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*p).Wnode.ClientContext = 1; // QPC timestamps
        (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*p).LoggerNameOffset = head as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.as_mut_ptr().add(head) as *mut u16, name.len());
    }
    buf
}

fn stop_session(name: &[u16]) {
    let mut props = properties(name);
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// Start listening. Runs a thread that lives as long as the session; errors
/// are not fatal, the UI then simply shows addresses without names.
pub fn start() -> anyhow::Result<()> {
    let session = SESSION;
    let name = briqwall_common::util::wide(session);
    let mut props = properties(&name);
    let mut handle = CONTROLTRACE_HANDLE::default();

    let mut err = unsafe { StartTraceW(&mut handle, PCWSTR(name.as_ptr()), props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    if err == ERROR_ALREADY_EXISTS {
        // Left over from a crash: stop it and take the name again.
        stop_session(&name);
        props = properties(&name);
        err = unsafe { StartTraceW(&mut handle, PCWSTR(name.as_ptr()), props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    }
    if err != ERROR_SUCCESS {
        anyhow::bail!("StartTrace {session}: {err:?}");
    }
    SESSION_HANDLE.store(handle.Value, Ordering::SeqCst);

    // MatchAnyKeyword = all bits: an event with a keyword is dropped when the
    // mask is 0, and the DNS client tags its events with keywords.
    let err = unsafe { EnableTraceEx2(handle, &DNS_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER.0, 5, u64::MAX, 0, 0, None) };
    if err != ERROR_SUCCESS {
        stop();
        anyhow::bail!("EnableTraceEx2 DNS-Client: {err:?}");
    }

    std::thread::Builder::new().name("dns".into()).spawn(move || consume(name))?;
    Ok(())
}

fn consume(mut name: Vec<u16>) {
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: PWSTR(name.as_mut_ptr()),
        Anonymous1: EVENT_TRACE_LOGFILEW_0 { ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD },
        Anonymous2: EVENT_TRACE_LOGFILEW_1 { EventRecordCallback: Some(on_event) },
        ..Default::default()
    };
    let trace = unsafe { OpenTraceW(&mut logfile) };
    if trace.Value == INVALID_TRACE {
        log::warn!("DNS-Namen: OpenTrace fehlgeschlagen");
        return;
    }
    log::info!("DNS-Namen: Ereignisse werden gelesen");
    // Returns when the session is stopped.
    let err = unsafe { ProcessTrace(&[trace], None, None) };
    if err != ERROR_SUCCESS {
        log::warn!("DNS-Namen: ProcessTrace endete mit {err:?}");
    }
    unsafe { let _ = CloseTrace(trace); }
}

/// Stop the session (otherwise it would outlive the process).
pub fn stop() {
    if SESSION_HANDLE.swap(0, Ordering::SeqCst) != 0 {
        stop_session(&briqwall_common::util::wide(SESSION));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the user data of a 3008 event the way the DNS client writes it:
    /// QueryName, QueryType, QueryOptions, QueryStatus, QueryResults.
    fn event(name: &str, results: &str) -> Vec<u8> {
        let mut b = Vec::new();
        let push = |b: &mut Vec<u8>, s: &str| {
            s.encode_utf16().chain(std::iter::once(0)).for_each(|u| b.extend_from_slice(&u.to_le_bytes()));
        };
        push(&mut b, name);
        b.extend_from_slice(&1u32.to_le_bytes()); // QueryType A
        b.extend_from_slice(&0u64.to_le_bytes()); // QueryOptions
        b.extend_from_slice(&0u32.to_le_bytes()); // QueryStatus
        push(&mut b, results);
        b
    }

    #[test]
    fn reads_name_and_addresses() {
        let data = event("example.com", "::ffff:93.184.216.34;");
        let (name, addrs) = parse_query_completed(&data).expect("parsed");
        assert_eq!(name, "example.com");
        assert_eq!(addrs, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
    }

    /// What Windows 11 really sends: the fixed fields between name and
    /// results decode as junk text, and IPv4 answers are plain addresses.
    #[test]
    fn reads_the_layout_windows_sends() {
        let mut data = Vec::new();
        let push = |b: &mut Vec<u8>, s: &str| {
            s.encode_utf16().chain(std::iter::once(0)).for_each(|u| b.extend_from_slice(&u.to_le_bytes()));
        };
        push(&mut data, "a.nel.cloudflare.com");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&[0x00, 0x40, 0x02, 0x80, 0x00, 0x80, 0x08, 0x0a, 0x00, 0x00]);
        push(&mut data, "type: 5 ads.example.com;35.190.80.1;");
        assert_eq!(
            parse_query_completed(&data),
            Some(("a.nel.cloudflare.com".to_string(), vec!["35.190.80.1".parse().unwrap()]))
        );
    }

    #[test]
    fn skips_records_that_are_not_addresses() {
        let data = event("www.example.net", "type: 5 star.example.net;type: 28 2606:2800:220::1;");
        let (name, addrs) = parse_query_completed(&data).expect("parsed");
        assert_eq!(name, "www.example.net");
        assert_eq!(addrs, vec!["2606:2800:220::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn ignores_lookups_without_answer() {
        assert!(parse_query_completed(&event("nx.example.com", "")).is_none());
        assert!(parse_query_completed(&[]).is_none());
        assert!(parse_query_completed(&[0, 0]).is_none());
    }

    #[test]
    fn cache_returns_what_was_stored() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        remember(ip, "host.example.com", false);
        assert_eq!(lookup(ip), Some(Host { name: "host.example.com".into(), verified: false }));
        assert_eq!(lookup("203.0.113.8".parse().unwrap()), None);
    }

    /// What a program claims never replaces what a trustworthy source said.
    #[test]
    fn a_claim_does_not_replace_a_verified_name() {
        let ip: IpAddr = "203.0.113.20".parse().unwrap();
        remember(ip, "cdn.example.net", true);
        remember(ip, "update.microsoft.com", false);
        assert_eq!(lookup(ip), Some(Host { name: "cdn.example.net".into(), verified: true }));
        // The other way round the better source wins.
        let ip: IpAddr = "203.0.113.21".parse().unwrap();
        remember(ip, "update.microsoft.com", false);
        remember(ip, "c2.example.org", true);
        assert_eq!(lookup(ip), Some(Host { name: "c2.example.org".into(), verified: true }));
    }

    #[test]
    fn only_real_dns_names_are_shown() {
        assert_eq!(valid_hostname("example.com."), Some("example.com"));
        assert_eq!(valid_hostname("xn--mnchen-3ya.de"), Some("xn--mnchen-3ya.de"));
        assert_eq!(valid_hostname("_sip._tcp.example.com"), Some("_sip._tcp.example.com"));
        assert_eq!(valid_hostname("update.microsoft.com (verified)"), None);
        assert_eq!(valid_hostname("micr\u{43e}soft.com"), None); // Cyrillic o
        assert_eq!(valid_hostname(""), None);
        assert_eq!(valid_hostname(&"a".repeat(300)), None);
    }

    /// The test binary lies in a build folder anyone can write to.
    #[test]
    fn events_from_user_writable_programs_are_claims() {
        assert!(!emitter_trusted(std::process::id()));
        assert!(!emitter_trusted(0));
    }
}
