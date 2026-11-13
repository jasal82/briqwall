//! Policy data model. Everything here is serialized to disk (service state) and
//! over the control pipe (UI), so changes must stay backwards compatible
//! (`#[serde(default)]` for new fields).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Global protection level. Ordered from most permissive to most restrictive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Mode {
    /// Briqwall does not install any filters (Windows Firewall still applies).
    Off,
    /// Only clearly suspicious programs are stopped; inbound is left to Windows.
    Relaxed,
    /// Default: system + installed + well-known signed apps are trusted automatically.
    #[default]
    Balanced,
    /// Only Windows components and signed installed software are trusted automatically.
    Strict,
    /// Emergency: everything except loopback/DHCP is blocked.
    Lockdown,
}

impl Mode {
    /// Higher = more restrictive. Used to decide whether a change loosens protection.
    pub fn strictness(self) -> u8 {
        match self {
            Mode::Off => 0,
            Mode::Relaxed => 1,
            Mode::Balanced => 2,
            Mode::Strict => 3,
            Mode::Lockdown => 4,
        }
    }
}

/// Effective access for one direction. Ordered by permissiveness via [`Access::rank`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Access {
    /// Blocked without asking.
    Block,
    /// Blocked until the user decides (shows up in the inbox).
    Ask,
    /// Only local network (private address ranges, link-local, multicast).
    Lan,
    /// Unrestricted.
    Allow,
}

impl Access {
    pub fn rank(self) -> u8 {
        match self {
            Access::Block | Access::Ask => 0,
            Access::Lan => 1,
            Access::Allow => 2,
        }
    }
}

/// What the user explicitly chose for one direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum RuleAccess {
    /// Follow the automatic trust evaluation.
    #[default]
    Auto,
    Block,
    Lan,
    Allow,
}


#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UserRule {
    pub outbound: RuleAccess,
    pub inbound: RuleAccess,
    /// Unix seconds. `None` = permanent.
    pub expires: Option<u64>,
    pub created: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    /// Part of Windows, in a location only TrustedInstaller/Admins can write.
    System,
    /// Windows tool that is frequently abused by attackers ("living off the land").
    Lolbin,
    /// Installed software in an admin-only location.
    Installed,
    /// Somewhere a normal user (or malware without admin rights) could have placed it.
    UserSpace,
    /// Kernel / non-file traffic (e.g. "System").
    Pseudo,
}


#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signature {
    Valid { publisher: String, catalog: bool },
    Unsigned,
    Invalid { code: u32 },
    Unknown,
}

impl Signature {
    pub fn publisher(&self) -> Option<&str> {
        match self {
            Signature::Valid { publisher, .. } => Some(publisher.as_str()),
            _ => None,
        }
    }
    pub fn is_valid(&self) -> bool {
        matches!(self, Signature::Valid { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Risk {
    Low,
    Medium,
    High,
}


/// Why the automatic verdict for an app is what it is. The UI turns this into
/// a sentence in the user's language.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Reason {
    #[default]
    Unknown,
    /// Kernel traffic ("System").
    Kernel,
    /// Part of Windows, only Windows itself can modify it.
    System,
    /// Frequently abused tool (PowerShell, curl, …) – asks before access.
    Tool,
    /// Frequently abused tool, allowed because of relaxed mode.
    ToolRelaxed,
    /// Installed (admin-only location) and signed by this publisher.
    InstalledSigned(String),
    /// Installed (admin-only location), unsigned.
    Installed,
    /// Installed but unsigned – strict mode asks.
    InstalledUnsignedStrict,
    /// Signature present but invalid.
    InvalidSignature,
    /// Publisher the user trusted before.
    LearnedPublisher(String),
    /// Publisher from the built-in list of well-known vendors.
    KnownPublisher(String),
    /// Signed, allowed because of relaxed mode.
    SignedRelaxed(String),
    /// Signed by a publisher Briqwall does not know yet (user-writable location).
    UnknownPublisher(String),
    /// Unsigned in a user-writable location.
    Unsigned,
}

/// Notable location of an executable. Aliases keep state files of older
/// versions readable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Location {
    Downloads,
    #[serde(alias = "Temp-Ordner")]
    Temp,
    Desktop,
    #[serde(alias = "Öffentlicher Ordner")]
    Public,
    AppData,
    #[serde(alias = "Programme")]
    ProgramFiles,
    #[serde(alias = "Benutzerprofil")]
    UserProfile,
    #[serde(alias = "Wechseldatenträger")]
    Removable,
}

impl Location {
    /// Classic malware drop zones.
    pub fn is_risky(self) -> bool {
        matches!(self, Location::Downloads | Location::Temp | Location::Desktop | Location::Public | Location::Removable)
    }
}

/// Network category as reported by Windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetCategory {
    Public,
    Private,
    Domain,
}

/// Machine-readable errors; the UI shows them in the user's language.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    UnknownApp,
    SystemEntry,
    TooManyApprovals,
    ApprovalExpired,
    HelloNotEnrolled,
    NotApprovableWithHello,
    InvalidKey,
    ServiceTimeout,
    BadRequest(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppInfo {
    /// Lower-case Win32 path, or `pseudo:<name>` for non-file traffic.
    pub key: String,
    pub path: String,
    pub name: String,
    pub signature: Signature,
    pub category: Category,
    /// True if only SYSTEM/Administrators/TrustedInstaller could have written the file.
    pub protected: bool,
    /// Human hint about a notable location ("Downloads", "Temp", ...).
    pub location_hint: Option<Location>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub last_blocked: Option<u64>,
    pub blocked_count: u32,
    #[serde(default)]
    pub inbound_blocked_count: u32,
    pub last_remote: Option<String>,
    pub rule: Option<UserRule>,

    pub auto_out: Access,
    pub auto_in: Access,
    /// Why the automatic verdict was reached (translated by the UI).
    #[serde(default)]
    pub reason: Reason,
    pub effective_out: Access,
    pub effective_in: Access,
    pub risk: Risk,

    /// Waiting for a user decision (shown in the inbox).
    pub pending: bool,
    /// "Ignore" was clicked: don't re-raise in the inbox before this time.
    #[serde(default)]
    pub snoozed_until: Option<u64>,
    /// The binary changed identity after the user allowed it; the rule is suspended.
    pub tampered: bool,

    // ---- service-internal bookkeeping (harmless to expose) ----
    /// Identity recorded when the user made a decision: `pub:<publisher>` or `sha256:<hex>`.
    #[serde(default)]
    pub identity: Option<String>,
    /// (size, mtime) of the file when facts were last gathered.
    #[serde(default)]
    pub file_stamp: Option<(u64, u64)>,
    /// Raw WFP app-id blob for pseudo apps.
    #[serde(default)]
    pub raw_app_id: Option<Vec<u8>>,
    /// Which process instances triggered recent blocked attempts (newest
    /// first). Held in memory by the service only, never written to disk.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<ProcessOrigin>,
}

/// One process instance that triggered a blocked connection: its command line
/// and the chain of parent processes. Lets the user tell a legitimate call of a
/// shared tool (rundll32, PowerShell, …) from an abusive one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessOrigin {
    pub pid: u32,
    pub command_line: Option<String>,
    /// Parent first, then grandparent, … (at most a few levels).
    pub parents: Vec<ParentProcess>,
    pub last_seen: u64,
    /// Blocked attempts from this origin (same command line and parents).
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentProcess {
    pub pid: u32,
    /// File name, e.g. "WINWORD.EXE".
    pub name: String,
    pub path: Option<String>,
}

impl AppInfo {
    pub fn has_user_rule(&self) -> bool {
        self.rule.is_some()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub mode: Mode,
    /// Mode to return to when leaving lockdown.
    pub previous_mode: Mode,
    /// Allow inbound LAN traffic for Windows components on trusted networks
    /// (file sharing, casting, discovery).
    pub lan_discovery: bool,
    /// When the user permanently allows a signed app, trust its publisher from then on.
    pub learn_publishers: bool,
    pub learned_publishers: Vec<String>,
    /// Network id -> trusted. Missing entries follow the Windows network category.
    pub network_trust: BTreeMap<String, bool>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Balanced,
            previous_mode: Mode::Balanced,
            lan_discovery: true,
            learn_publishers: true,
            learned_publishers: Vec::new(),
            network_trust: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NetworkInfo {
    pub id: String,
    pub name: String,
    /// "Öffentlich", "Privat", "Domäne".
    pub windows_category: NetCategory,
    pub trusted: bool,
    /// User made an explicit choice in Briqwall.
    pub explicit: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub mode: Mode,
    pub engine_ok: bool,
    pub engine_error: Option<String>,
    /// The calling client may loosen protection (it is elevated).
    pub privileged: bool,
    pub networks: Vec<NetworkInfo>,
    pub network_trusted: bool,
    pub apps_total: usize,
    pub apps_allowed: usize,
    pub apps_blocked: usize,
    pub pending: usize,
    pub blocked_session: u64,
    pub started: u64,
    /// Bumped whenever the app list changes; lets the UI skip refetching.
    pub revision: u64,
    pub settings: Settings,
    /// A Windows Hello key is registered; approvals can be signed instead of UAC.
    #[serde(default)]
    pub hello_enrolled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Out,
    In,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EventKind {
    Blocked {
        key: String,
        name: String,
        remote: String,
        direction: Direction,
        /// true = explicit user rule; false = default policy
        by_rule: bool,
    },
    NewRequest {
        key: String,
        name: String,
        risk: Risk,
    },
    AutoAllowed {
        key: String,
        name: String,
        reason: Reason,
    },
    RuleChanged {
        key: String,
        name: String,
        rule: Option<UserRule>,
    },
    RuleExpired {
        key: String,
        name: String,
    },
    Tampered {
        key: String,
        name: String,
    },
    ModeChanged {
        from: Mode,
        to: Mode,
    },
    NetworkChanged {
        name: String,
        trusted: bool,
    },
    Started {
        version: String,
        mode: Mode,
    },
    PublisherLearned {
        publisher: String,
    },
    HelloEnrolled,
    HelloRemoved,
    /// Applying the rules to WFP failed (technical detail, not translated).
    ApplyFailed {
        detail: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub time: u64,
    pub kind: EventKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    Status,
    Apps,
    Events { after: u64 },
    SetMode(Mode),
    /// `rule: None` resets the app to automatic handling.
    SetRule { key: String, rule: Option<UserRule> },
    /// Hide from inbox for a day, keep blocked.
    Snooze { key: String },
    Forget { key: String },
    /// `trusted: None` = follow Windows network category again.
    SetNetworkTrust { id: String, trusted: Option<bool> },
    SetOptions { lan_discovery: Option<bool>, learn_publishers: Option<bool> },
    RemovePublisher(String),
    /// Several changes at once (one confirmation for all of them).
    Batch(Vec<Request>),
    /// Ask for a single-use nonce to sign with Windows Hello.
    Challenge,
    /// Changes approved by the user with Windows Hello. `payload` is the exact
    /// JSON array of requests that was signed (see [`approval_message`]).
    Approved { nonce: String, payload: String, signature: String },
    /// Register the public key of the user's Windows Hello credential
    /// (hex-encoded X.509 SubjectPublicKeyInfo). Requires an elevated client.
    EnrollHello { public_key: String },
    RemoveHello,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    Status(Box<Status>),
    Apps(Vec<AppInfo>),
    Events(Vec<Event>),
    Ok,
    /// The request would loosen protection and the client is not elevated
    /// (or a Windows Hello approval was invalid).
    Denied,
    Error(ErrorCode),
    /// Nonce for a Windows Hello approval.
    Challenge(String),
}

/// The exact bytes the Windows Hello key signs for an approval. Shared by UI
/// and service so both sides agree byte for byte.
pub fn approval_message(nonce: &str, payload: &str) -> Vec<u8> {
    const LF: u8 = 0x0A;
    let mut m = b"briqwall-approval-v1".to_vec();
    m.push(LF);
    m.extend_from_slice(nonce.as_bytes());
    m.push(LF);
    m.extend_from_slice(payload.as_bytes());
    m
}

/// Well-known ports for human-readable activity (language neutral).
pub fn port_label(proto: u8, port: u16) -> Option<&'static str> {
    Some(match (proto, port) {
        (6, 80) => "HTTP",
        (6, 443) | (17, 443) => "HTTPS",
        (_, 53) => "DNS",
        (6, 853) => "DNS-over-TLS",
        (6, 22) => "SSH",
        (6, 21) => "FTP",
        (6, 25) | (6, 587) | (6, 465) => "SMTP",
        (6, 993) | (6, 143) => "IMAP",
        (6, 995) | (6, 110) => "POP3",
        (6, 445) => "SMB",
        (6, 3389) => "RDP",
        (17, 123) => "NTP",
        (17, 5353) => "mDNS",
        (17, 1900) => "SSDP",
        (17, 5355) => "LLMNR",
        (17, 137) | (17, 138) | (6, 139) => "NetBIOS",
        (17, 67) | (17, 68) => "DHCP",
        _ => return None,
    })
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
