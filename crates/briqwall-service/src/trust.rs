//! Gathers facts about an executable: who could have written it (ACLs),
//! Authenticode signature (embedded or catalog), display name, location.

use crate::policy;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::windows::fs::MetadataExt;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, HWND, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::Cryptography::Catalog::*;
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::*;
use windows::Win32::Security::{
    GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use briqwall_common::util::{from_wide, wide};
use briqwall_common::{Category, Location, Signature};

const TRUST_E_NOSIGNATURE: u32 = 0x800B0100;

#[derive(Debug, Clone)]
pub struct Facts {
    pub exists: bool,
    pub name: String,
    pub signature: Signature,
    pub protected: bool,
    pub category: Category,
    pub location_hint: Option<Location>,
    pub stamp: Option<(u64, u64)>,
}

pub fn windows_dir() -> String {
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemWindowsDirectoryW(Some(&mut buf)) } as usize;
    let s = String::from_utf16_lossy(&buf[..n.min(buf.len())]).to_lowercase();
    if s.is_empty() { r"c:\windows".into() } else { s }
}

pub fn file_stamp(path: &str) -> Option<(u64, u64)> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.len(), m.last_write_time()))
}

pub fn gather(path: &str, win_dir: &str) -> Facts {
    let lower = path.to_lowercase();
    let file_name = lower.rsplit('\\').next().unwrap_or(&lower).to_string();
    let stamp = file_stamp(path);
    let exists = stamp.is_some();
    let version = VersionInfo::load(path);
    let signature = if exists { verify_signature(path) } else { Signature::Unknown };
    let protected = exists && is_protected(path);
    let in_windows = lower.starts_with(&format!("{win_dir}\\"));
    // The description inside a file is written by whoever built it: an
    // unsigned program in a user folder can call itself "Windows Update".
    // It is only shown where someone stands behind it – a signer, or the
    // administrator who installed it. Everything else goes by its file name.
    let name = (protected || signature.is_valid())
        .then(|| version.as_ref().and_then(VersionInfo::display_name))
        .flatten()
        .map(|n| clean_label(&n, 80))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| file_title(path));

    // The name on disk is whatever the person who put the file there chose.
    // The name the tool was built with survives a rename.
    let built_as = version.as_ref().and_then(|v| v.string("OriginalFilename")).map(|n| original_name(&n));
    let lolbin = policy::is_lolbin(&file_name) || built_as.as_deref().is_some_and(policy::is_lolbin);

    // Applies wherever the file lies: a copy in a user folder is the same tool.
    let category = if lolbin {
        Category::Lolbin
    } else if !protected {
        Category::UserSpace
    } else if in_windows {
        Category::System
    } else {
        Category::Installed
    };

    let location_hint = location_hint(&lower).or_else(|| is_removable(&lower).then_some(Location::Removable));
    Facts { exists, name, signature, protected, category, location_hint, stamp }
}

/// File name without ".exe" – the name of a program nobody vouches for.
pub fn file_title(path: &str) -> String {
    let file = path.rsplit('\\').next().unwrap_or(path);
    let title = if file.to_lowercase().ends_with(".exe") { &file[..file.len() - 4] } else { file };
    clean_label(title, 80)
}

/// Text from a file or certificate, made safe to show: one line, no control
/// or direction-changing characters (they can make a name read differently
/// than it is), bounded length.
pub fn clean_label(s: &str, max: usize) -> String {
    let invisible = |c: char| {
        c.is_control()
            || ('\u{200b}'..='\u{200f}').contains(&c)
            || ('\u{2028}'..='\u{202e}').contains(&c)
            || ('\u{2060}'..='\u{2069}').contains(&c)
            || c == '\u{feff}'
    };
    let spaced: String = s.chars().map(|c| if invisible(c) { ' ' } else { c }).collect();
    let mut out = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if out.chars().count() > max {
        out = out.chars().take(max).collect::<String>() + "…";
    }
    out
}

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_CDROM: u32 = 5;
const DRIVE_RAMDISK: u32 = 6;

/// "c:\" for a path that starts with a drive letter.
fn drive_root(path: &str) -> Option<String> {
    let b = path.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\').then(|| format!("{}:\\", b[0] as char))
}

fn drive_type(root: &str) -> u32 {
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    let w = wide(root);
    unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) }
}

fn is_removable(lower: &str) -> bool {
    drive_root(lower).is_some_and(|r| drive_type(&r) == DRIVE_REMOVABLE)
}

/// Is the file on a disk of this computer? Everything else – network shares,
/// drives the service cannot see – is not opened by the service: reading a
/// file on `\\server\share` as SYSTEM logs this computer on to that server,
/// and the server is whatever the path says.
pub fn is_local_path(path: &str) -> bool {
    drive_root(path).is_some_and(|r| matches!(drive_type(&r), DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_CDROM | DRIVE_RAMDISK))
}

/// Facts about a file the service does not open (see [`is_local_path`]).
pub fn unverified(path: &str, stamp: Option<(u64, u64)>) -> Facts {
    Facts {
        exists: stamp.is_some(),
        name: file_title(path),
        signature: Signature::Unknown,
        protected: false,
        category: Category::UserSpace,
        location_hint: Some(Location::Network),
        stamp,
    }
}

/// Can the permissions on this volume be taken at face value? They say who
/// may write *on this computer* only if its administrators control the disk.
/// A USB disk, memory card or disk image arrives with whatever owner and
/// permissions someone else gave it – "administrators only" included.
fn on_trusted_volume(path: &str) -> bool {
    let Some(root) = drive_root(path) else { return false };
    // Windows' own volume, however it is attached (also when booted from a VHD).
    if drive_root(&windows_dir()).is_some_and(|sys| sys.eq_ignore_ascii_case(&root)) {
        return true;
    }
    drive_type(&root) == DRIVE_FIXED && bus_is_internal(&root)
}

/// How the disk behind a volume is attached. `false` if it cannot be told.
fn bus_is_internal(root: &str) -> bool {
    volume_bus(root).is_some_and(|(bus, removable)| {
        // STORAGE_BUS_TYPE: 0 unknown, 4 FireWire, 7 USB, 12 SD, 13 MMC,
        // 15 file-backed virtual disk (mounted VHD/VHDX).
        !removable && !matches!(bus, 0 | 4 | 7 | 12 | 13 | 15)
    })
}

/// (bus type, removable media) of the disk behind "c:\".
fn volume_bus(root: &str) -> Option<(i32, bool)> {
    use windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
    use windows::Win32::System::Ioctl::{
        PropertyStandardQuery, StorageDeviceProperty, IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR,
        STORAGE_PROPERTY_QUERY,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    let device = wide(&format!("\\\\.\\{}", &root[..2]));
    unsafe {
        // No access rights needed to ask what kind of device it is.
        let h = CreateFileW(
            PCWSTR(device.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .ok()?;
        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            ..Default::default()
        };
        let mut out = [0u64; 128]; // aligned for the descriptor
        let mut returned = 0u32;
        let res = DeviceIoControl(
            h,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const _),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(out.as_mut_ptr() as *mut _),
            std::mem::size_of_val(&out) as u32,
            Some(&mut returned),
            None,
        );
        let _ = CloseHandle(h);
        res.ok()?;
        if (returned as usize) < std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            return None;
        }
        let d = &*(out.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR);
        Some((d.BusType.0, d.RemovableMedia))
    }
}

pub fn location_hint(lower: &str) -> Option<Location> {
    let h = if lower.contains(r"\downloads\") {
        Location::Downloads
    } else if lower.contains(r"\appdata\local\temp\") || lower.contains(r"\windows\temp\") || lower.contains(r"\temp\") {
        Location::Temp
    } else if lower.contains(r"\desktop\") {
        Location::Desktop
    } else if lower.starts_with(r"c:\users\public\") {
        Location::Public
    } else if lower.contains(r"\appdata\") {
        Location::AppData
    } else if lower.contains(r"\program files") || lower.contains(r"\windowsapps\") {
        Location::ProgramFiles
    } else if lower.starts_with(r"c:\users\") {
        Location::UserProfile
    } else {
        return None;
    };
    Some(h)
}

pub fn sha256_file(path: &str) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(briqwall_common::util::hex(&h.finalize()))
}

/// Identity used to detect binary replacement: the publisher for signed files,
/// otherwise the content hash.
pub fn identity(path: &str, sig: &Signature) -> Option<String> {
    match sig {
        Signature::Valid { publisher, .. } => Some(format!("pub:{publisher}")),
        _ => sha256_file(path).map(|h| format!("sha256:{h}")),
    }
}

// ---------------------------------------------------------------------------
// Version resource (FileDescription / ProductName)
// ---------------------------------------------------------------------------

/// The version resource of a file and the languages it is available in.
struct VersionInfo {
    data: Vec<u8>,
    langs: Vec<(u16, u16)>,
}

impl VersionInfo {
    fn load(path: &str) -> Option<Self> {
        let w = wide(path);
        unsafe {
            let size = GetFileVersionInfoSizeW(PCWSTR(w.as_ptr()), None);
            if size == 0 {
                return None;
            }
            let mut data = vec![0u8; size as usize];
            GetFileVersionInfoW(PCWSTR(w.as_ptr()), None, size, data.as_mut_ptr() as *mut _).ok()?;

            let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut len = 0u32;
            let q = wide(r"\VarFileInfo\Translation");
            let mut langs: Vec<(u16, u16)> = Vec::new();
            if VerQueryValueW(data.as_ptr() as *const _, PCWSTR(q.as_ptr()), &mut ptr, &mut len).as_bool() && len >= 4 {
                let pairs = std::slice::from_raw_parts(ptr as *const u16, (len / 2) as usize);
                for c in pairs.chunks_exact(2) {
                    langs.push((c[0], c[1]));
                }
            }
            langs.extend([(0x0409, 0x04b0), (0x0409, 0x04e4), (0x0407, 0x04b0), (0x0000, 0x04b0)]);
            Some(Self { data, langs })
        }
    }

    /// A string such as "FileDescription", in the first language that has it.
    fn string(&self, key: &str) -> Option<String> {
        let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        for (lang, cp) in &self.langs {
            let q = wide(&format!(r"\StringFileInfo\{lang:04x}{cp:04x}\{key}"));
            unsafe {
                if VerQueryValueW(self.data.as_ptr() as *const _, PCWSTR(q.as_ptr()), &mut ptr, &mut len).as_bool() && len > 1 {
                    let s = from_wide(std::slice::from_raw_parts(ptr as *const u16, len as usize));
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
            }
        }
        None
    }

    fn display_name(&self) -> Option<String> {
        self.string("FileDescription").or_else(|| self.string("ProductName"))
    }
}

/// "PowerShell.EXE" / "Cmd.Exe.MUI" → the file name the LOLBin list knows.
fn original_name(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    lower.strip_suffix(".mui").unwrap_or(&lower).to_string()
}

// ---------------------------------------------------------------------------
// Authenticode
// ---------------------------------------------------------------------------

pub fn verify_signature(path: &str) -> Signature {
    // A valid signature without a name on the certificate identifies nobody.
    // It must not count as "signed by ''" – that publisher could be learned.
    let named = |publisher: String, catalog: bool| {
        let publisher = clean_label(&publisher, 120);
        if publisher.is_empty() { Signature::Unknown } else { Signature::Valid { publisher, catalog } }
    };
    match verify_embedded(path) {
        Ok(p) => named(p, false),
        Err(code) if code == TRUST_E_NOSIGNATURE => match verify_catalog(path) {
            Some(Ok(p)) => named(p, true),
            Some(Err(code)) => Signature::Invalid { code },
            None => Signature::Unsigned,
        },
        // Other "no signature"-style errors (e.g. subject form unknown).
        Err(0x800B0003) | Err(0x80092009) => Signature::Unsigned,
        Err(code) => Signature::Invalid { code },
    }
}

unsafe fn publisher_from_state(state: HANDLE) -> String {
    let prov = WTHelperProvDataFromStateData(state);
    if prov.is_null() {
        return String::new();
    }
    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
    if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
        return String::new();
    }
    let cert = (*(*sgnr).pasCertChain).pCert;
    if cert.is_null() {
        return String::new();
    }
    let mut buf = [0u16; 512];
    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
    from_wide(&buf[..n as usize])
}

unsafe fn run_wintrust(data: &mut WINTRUST_DATA) -> Result<String, u32> {
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = WinVerifyTrust(HWND(-1isize as _), &mut action, data as *mut _ as *mut _) as u32;
    let publisher = if status == 0 { publisher_from_state(data.hWVTStateData) } else { String::new() };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = WinVerifyTrust(HWND(-1isize as _), &mut action, data as *mut _ as *mut _);
    if status == 0 { Ok(publisher) } else { Err(status) }
}

fn base_trust_data() -> WINTRUST_DATA {
    let mut d: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    d.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    d.dwUIChoice = WTD_UI_NONE;
    d.fdwRevocationChecks = WTD_REVOKE_NONE;
    d.dwStateAction = WTD_STATEACTION_VERIFY;
    // We *are* the firewall: never block on network retrieval during checks.
    d.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    d
}

fn verify_embedded(path: &str) -> Result<String, u32> {
    let w = wide(path);
    let mut fi: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
    fi.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
    fi.pcwszFilePath = PCWSTR(w.as_ptr());
    let mut d = base_trust_data();
    d.dwUnionChoice = WTD_CHOICE_FILE;
    d.Anonymous.pFile = &mut fi;
    unsafe { run_wintrust(&mut d) }
}

/// Many Windows binaries are catalog-signed (signature lives in a .cat file).
/// Returns None if no catalog contains the file.
fn verify_catalog(path: &str) -> Option<Result<String, u32>> {
    let w = wide(path);
    unsafe {
        let file = CreateFileW(
            PCWSTR(w.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .ok()?;
        let mut result = None;
        for alg in ["SHA256", "SHA1"] {
            if let Some(r) = verify_catalog_with(path, file, alg) {
                result = Some(r);
                break;
            }
        }
        let _ = CloseHandle(file);
        result
    }
}

unsafe fn verify_catalog_with(path: &str, file: HANDLE, alg: &str) -> Option<Result<String, u32>> {
    let walg = wide(alg);
    let mut admin: isize = 0;
    CryptCATAdminAcquireContext2(&mut admin, None, PCWSTR(walg.as_ptr()), None, None).ok()?;
    let mut size = 0u32;
    let mut out = None;
    if CryptCATAdminCalcHashFromFileHandle2(admin, file, &mut size, None, None).is_ok() || size > 0 {
        let mut hash = vec![0u8; size as usize];
        if CryptCATAdminCalcHashFromFileHandle2(admin, file, &mut size, Some(hash.as_mut_ptr()), None).is_ok() {
            let catinfo = CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None);
            if catinfo != 0 {
                let mut ci: CATALOG_INFO = std::mem::zeroed();
                ci.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
                if CryptCATCatalogInfoFromContext(catinfo, &mut ci, 0).is_ok() {
                    let tag = wide(&hash.iter().map(|b| format!("{b:02X}")).collect::<String>());
                    let wpath = wide(path);
                    let mut cat: WINTRUST_CATALOG_INFO = std::mem::zeroed();
                    cat.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
                    cat.pcwszCatalogFilePath = PCWSTR(ci.wszCatalogFile.as_ptr());
                    cat.pcwszMemberTag = PCWSTR(tag.as_ptr());
                    cat.pcwszMemberFilePath = PCWSTR(wpath.as_ptr());
                    cat.hMemberFile = file;
                    cat.pbCalculatedFileHash = hash.as_mut_ptr();
                    cat.cbCalculatedFileHash = hash.len() as u32;
                    cat.hCatAdmin = admin;
                    let mut d = base_trust_data();
                    d.dwUnionChoice = WTD_CHOICE_CATALOG;
                    d.Anonymous.pCatalog = &mut cat;
                    out = Some(run_wintrust(&mut d));
                }
                let _ = CryptCATAdminReleaseCatalogContext(admin, catinfo, 0);
            }
        }
    }
    let _ = CryptCATAdminReleaseContext(admin, 0);
    out
}

// ---------------------------------------------------------------------------
// ACL-based provenance
// ---------------------------------------------------------------------------

/// Principals that may legitimately write to installed software.
const TRUSTED_SIDS: &[&str] = &[
    "S-1-5-18",     // SYSTEM
    "S-1-5-32-544", // Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
    "S-1-3-0",      // CREATOR OWNER (only meaningful through inheritance)
    "S-1-5-19",     // LOCAL SERVICE
    "S-1-5-20",     // NETWORK SERVICE
];

const FILE_WRITE_DATA: u32 = 0x0002; // == FILE_ADD_FILE on directories
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_DELETE_CHILD: u32 = 0x0040;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const INHERIT_ONLY_ACE: u8 = 0x08;

/// True if no unprivileged principal can modify the file, replace it, or plant
/// files (e.g. DLLs) next to it – on a disk this computer's administrators
/// control (see [`on_trusted_volume`]).
pub fn is_protected(path: &str) -> bool {
    if !on_trusted_volume(path) {
        return false;
    }
    let file_mask = FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;
    let dir_mask = FILE_WRITE_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;
    let parent = match path.rfind('\\') {
        Some(i) => &path[..i],
        None => return false,
    };
    // A drive root like "C:" needs the trailing backslash.
    let parent = if parent.len() == 2 { format!("{parent}\\") } else { parent.to_string() };
    matches!(only_trusted_can_write(path, file_mask), Some(true))
        && matches!(only_trusted_can_write(&parent, dir_mask), Some(true))
}

pub(crate) fn sid_string(sid: PSID) -> Option<String> {
    unsafe {
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut s).ok()?;
        let r = s.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(s.0 as _)));
        r
    }
}

/// Is the file or folder owned by SYSTEM or the Administrators group? The
/// owner can always rewrite the permissions, whatever they currently say.
/// `false` if the owner cannot be determined.
pub fn owned_by_admins(path: &str) -> bool {
    let w = wide(path);
    unsafe {
        let mut owner = PSID::default();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let r = GetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        );
        if r.0 != 0 {
            return false;
        }
        let ok = sid_string(owner).is_some_and(|s| s == "S-1-5-18" || s == "S-1-5-32-544");
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        ok
    }
}

/// Program folders of this Windows installation, lower-case.
pub fn program_dirs() -> Vec<String> {
    let mut dirs: Vec<String> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|d| d.trim_end_matches('\\').to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Account name for a SID string ("S-1-5-21-…"), e.g. "Kim".
pub fn account_name(sid: &str) -> Option<String> {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};
    let w = wide(sid);
    unsafe {
        let mut psid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(w.as_ptr()), &mut psid).ok()?;
        let mut name = [0u16; 257];
        let mut name_len = name.len() as u32;
        let mut domain = [0u16; 257];
        let mut domain_len = domain.len() as u32;
        let mut kind = SID_NAME_USE::default();
        let res = LookupAccountSidW(
            None,
            psid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        );
        let _ = LocalFree(Some(HLOCAL(psid.0)));
        res.ok()?;
        let name = clean_label(&from_wide(&name), 80);
        (!name.is_empty()).then_some(name)
    }
}

/// SID of the account a token belongs to.
pub(crate) fn token_user_sid(token: HANDLE) -> Option<String> {
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
    unsafe {
        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        if size == 0 {
            return None;
        }
        let mut data = vec![0u64; (size as usize).div_ceil(8)]; // aligned for TOKEN_USER
        GetTokenInformation(token, TokenUser, Some(data.as_mut_ptr() as *mut _), size, &mut size).ok()?;
        sid_string((*(data.as_ptr() as *const TOKEN_USER)).User.Sid)
    }
}

fn is_trusted_sid(sid: PSID) -> bool {
    sid_string(sid).is_some_and(|s| TRUSTED_SIDS.contains(&s.as_str()))
}

fn only_trusted_can_write(path: &str, mask: u32) -> Option<bool> {
    let w = wide(path);
    unsafe {
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let r = GetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        );
        if r.0 != 0 {
            return None;
        }
        let mut ok = is_trusted_sid(owner) && !dacl.is_null();
        if ok {
            for i in 0..(*dacl).AceCount as u32 {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace).is_err() {
                    continue;
                }
                let header = &*(ace as *const ACE_HEADER);
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE || header.AceFlags & INHERIT_ONLY_ACE != 0 {
                    continue;
                }
                let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                if allowed.Mask & mask == 0 {
                    continue;
                }
                let sid = PSID(&allowed.SidStart as *const u32 as *mut _);
                if !is_trusted_sid(sid) {
                    ok = false;
                    break;
                }
            }
        }
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        Some(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints() {
        assert_eq!(location_hint(r"c:\users\a\downloads\x.exe"), Some(Location::Downloads));
        assert_eq!(location_hint(r"c:\users\a\appdata\local\temp\x.exe"), Some(Location::Temp));
        assert_eq!(location_hint(r"c:\users\a\appdata\local\discord\app.exe"), Some(Location::AppData));
        assert_eq!(location_hint(r"c:\program files\x\x.exe"), Some(Location::ProgramFiles));
    }

    #[test]
    fn only_local_disks_are_opened() {
        let win = windows_dir();
        assert!(is_local_path(&format!(r"{win}\system32\notepad.exe")));
        assert!(!is_local_path(r"\\server\share\tool.exe"));
        assert!(!is_local_path(r"\\?\UNC\server\share\tool.exe"));
        assert!(!is_local_path(r"\\.\pipe\x"));
        assert!(!is_local_path(r"tool.exe"));
        assert!(!is_local_path(r"c:tool.exe"));

        let f = unverified(r"\\server\share\Tool.EXE", None);
        assert_eq!((f.name.as_str(), f.protected, f.category), ("Tool", false, Category::UserSpace));
        assert_eq!((f.signature, f.location_hint), (Signature::Unknown, Some(Location::Network)));
        assert!(!is_protected(r"\\server\share\tool.exe"));
    }

    /// Shows how the disks of this machine are attached (`--nocapture`).
    #[test]
    fn system_volume_is_trusted() {
        let win = windows_dir();
        assert!(on_trusted_volume(&format!(r"{win}\system32\notepad.exe")));
        for letter in 'a'..='z' {
            let root = format!(r"{letter}:\");
            let kind = drive_type(&root);
            if kind > 1 {
                println!("{root} type={kind} bus={:?} trusted={}", volume_bus(&root), on_trusted_volume(&root));
            }
        }
    }

    #[test]
    fn well_known_accounts_have_names() {
        assert!(account_name("S-1-5-18").is_some(), "SYSTEM");
        assert!(account_name("not a sid").is_none());
        assert!(account_name("S-1-5-21-1-2-3-99999").is_none(), "no such account");
        assert!(program_dirs().iter().all(|d| !d.ends_with('\\') && *d == d.to_lowercase()));
    }

    #[test]
    fn labels_are_made_safe_to_show() {
        assert_eq!(clean_label("  Windows\u{202e}Update\r\n ", 80), "Windows Update");
        assert_eq!(clean_label(&"x".repeat(200), 10).chars().count(), 11);
        assert_eq!(file_title(r"c:\users\a\downloads\Setup.EXE"), "Setup");
        assert_eq!(file_title(r"c:\tools\noext"), "noext");
    }

    /// An unsigned program in a user folder is shown under its file name,
    /// whatever its version resource claims to be.
    #[test]
    fn unsigned_program_cannot_name_itself() {
        let win = windows_dir();
        // curl.exe carries a description; appending a byte breaks its signature.
        let curl = format!(r"{win}\system32\curl.exe");
        if !std::path::Path::new(&curl).exists() {
            return;
        }
        let copy = std::env::temp_dir().join("briqwall-test-renamed.exe");
        let mut bytes = std::fs::read(&curl).unwrap();
        bytes.push(0);
        std::fs::write(&copy, bytes).unwrap();
        let f = gather(copy.to_str().unwrap(), &win);
        std::fs::remove_file(&copy).ok();
        assert!(!f.signature.is_valid(), "{:?}", f.signature);
        assert_eq!(f.name, "briqwall-test-renamed");
    }

    #[test]
    fn original_names_match_the_lolbin_list() {
        assert_eq!(original_name("PowerShell.EXE"), "powershell.exe");
        assert_eq!(original_name(" Cmd.Exe.MUI "), "cmd.exe");
        assert!(policy::is_lolbin(&original_name("PowerShell.EXE")));
    }

    /// A system tool copied to a user folder under another name must not be
    /// mistaken for an ordinary signed app.
    #[test]
    fn renamed_copy_of_powershell_is_still_a_lolbin() {
        let win = windows_dir();
        let ps = format!(r"{win}\system32\windowspowershell\v1.0\powershell.exe");
        if !std::path::Path::new(&ps).exists() {
            return;
        }
        let copy = std::env::temp_dir().join("briqwall-test-updater.exe");
        std::fs::copy(&ps, &copy).unwrap();
        let f = gather(copy.to_str().unwrap(), &win);
        std::fs::remove_file(&copy).ok();
        assert!(!f.protected);
        assert_eq!(f.category, Category::Lolbin);
    }

    // These touch the real file system of the machine running the tests.
    #[test]
    fn system32_is_protected_and_signed() {
        let win = windows_dir();
        let notepad = format!(r"{win}\system32\notepad.exe");
        if std::path::Path::new(&notepad).exists() {
            let f = gather(&notepad, &win);
            assert!(f.protected, "notepad should be admin-only");
            assert_eq!(f.category, Category::System);
            assert!(f.signature.is_valid(), "notepad should be signed: {:?}", f.signature);
        }
        let ps = format!(r"{win}\system32\windowspowershell\v1.0\powershell.exe");
        if std::path::Path::new(&ps).exists() {
            assert_eq!(gather(&ps, &win).category, Category::Lolbin);
        }
    }

    #[test]
    fn temp_is_userspace() {
        let p = std::env::temp_dir().join("briqwall-test.exe");
        std::fs::write(&p, b"MZ not really").unwrap();
        let f = gather(p.to_str().unwrap(), &windows_dir());
        std::fs::remove_file(&p).ok();
        assert!(!f.protected);
        assert_eq!(f.category, Category::UserSpace);
        assert_eq!(f.signature, Signature::Unsigned);
    }
}
