//! Persistent state (settings + known apps) and the data directory.
//!
//! The data directory gets an explicit, protected DACL: SYSTEM and Administrators
//! may write, everyone else may only read. Otherwise malware running as the user
//! could simply edit the policy file.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use briqwall_common::util::wide;
use briqwall_common::{AppInfo, Settings};

#[derive(Default, Serialize, Deserialize)]
pub struct State {
    pub settings: Settings,
    pub apps: BTreeMap<String, AppInfo>,
    /// We enabled WFP audit events and should turn them off on uninstall.
    #[serde(default)]
    pub audit_enabled_by_us: bool,
    /// Which audit subcategories (GUID strings) we enabled. Empty with the
    /// flag above set: recorded by a version that did not tell them apart.
    #[serde(default)]
    pub audit_enabled: Vec<String>,
    /// Public keys (hex SPKI) of the Windows Hello credentials that may sign
    /// approvals, one per Windows account.
    #[serde(default)]
    pub hello_keys: Vec<HelloKey>,
    /// Single key of versions before per-account enrollment. Read once and
    /// moved into `hello_keys` (see [`State::migrate`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hello_key: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HelloKey {
    /// Empty for a key taken over from before per-account enrollment.
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub name: String,
    pub key: String,
}

impl State {
    /// Audit subcategories to switch off again on uninstall: the ones this
    /// service enabled, not those the administrator had on before.
    pub fn audit_to_revert(&self) -> Vec<String> {
        if !self.audit_enabled.is_empty() {
            self.audit_enabled.clone()
        } else if self.audit_enabled_by_us {
            crate::watchers::AUDIT_SUBCATEGORIES.iter().map(|(sc, _)| sc.to_string()).collect()
        } else {
            Vec::new()
        }
    }

    /// Move a single pre-existing Hello key into the per-account list. It
    /// keeps working; it just has no account attached to it.
    pub fn migrate(&mut self) {
        if let Some(key) = self.hello_key.take() {
            self.hello_keys.push(HelloKey { sid: String::new(), name: String::new(), key });
        }
    }
}

pub fn data_dir(elevated: bool) -> PathBuf {
    if elevated {
        let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| r"C:\ProgramData".into());
        base.join("Briqwall")
    } else {
        // Developer mode (not elevated): keep data in the user profile.
        let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        base.join("Briqwall-dev")
    }
}

/// Briqwall was called "xWall" before. Adopt its rules (state.json) once, so
/// an upgrade keeps user decisions, learned publishers and the Hello key.
pub fn migrate_legacy(dir: &Path, elevated: bool) {
    let new_state = dir.join("state.json");
    if new_state.exists() {
        return;
    }
    let legacy = if elevated {
        std::env::var_os("ProgramData").map(PathBuf::from).map(|b| b.join("xWall"))
    } else {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from).map(|b| b.join("xWall-dev"))
    };
    let Some(old_dir) = legacy else { return };
    let old_state = old_dir.join("state.json");
    if !old_state.exists() {
        return;
    }
    // Any user may create folders in ProgramData. Rules are only adopted from
    // a folder the old service set up itself – otherwise a program could plant
    // a "previous installation" that switches the firewall off.
    if elevated && (is_reparse_point(&old_dir) || is_reparse_point(&old_state) || !crate::trust::is_protected(&old_state.to_string_lossy())) {
        log::warn!("{} ist nicht vor Änderungen durch Benutzer geschützt – Regeln werden nicht übernommen", old_state.display());
        return;
    }
    match std::fs::copy(&old_state, &new_state) {
        Ok(_) => log::info!("Regeln aus {} übernommen", old_state.display()),
        Err(e) => log::warn!("Übernahme von {} fehlgeschlagen: {e}", old_state.display()),
    }
}

/// SYSTEM + Administrators full control, Users read; not inherited from ProgramData.
const DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";

/// Create the data directory, or make sure an existing one can be trusted.
///
/// Any user may create folders in ProgramData, so a folder that is already
/// there proves nothing: whoever created it owns it and can rewrite its
/// permissions at any time, could have filled it with a policy of their own,
/// or made it a link to somewhere else. Such a folder (or file in it) is moved
/// aside and replaced. Returns notes for the log, which is opened afterwards.
pub fn prepare_dir(dir: &Path, protect: bool) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    if !protect {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        return Ok(notes);
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    if create_protected(dir)? {
        return Ok(notes);
    }

    if !dir.is_dir() || !is_trusted(dir) {
        let aside = move_aside(dir)?;
        notes.push(format!(
            "{} gehörte nicht SYSTEM/Administratoren oder war eine Verknüpfung – verschoben nach {}, Ordner neu angelegt",
            dir.display(),
            aside.display()
        ));
        if !create_protected(dir)? {
            anyhow::bail!("{} wurde von einem anderen Prozess erneut angelegt", dir.display());
        }
        return Ok(notes);
    }

    set_sddl(dir, DIR_SDDL)?;
    // Files put there before the folder was protected keep their own owner
    // and permissions; the service must neither read nor write through them.
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))?.flatten() {
        let path = entry.path();
        if entry.file_name().to_string_lossy().contains(ASIDE_MARK) || is_trusted(&path) {
            continue;
        }
        let aside = move_aside(&path)?;
        notes.push(format!(
            "{} gehörte nicht SYSTEM/Administratoren oder war eine Verknüpfung – verschoben nach {}",
            path.display(),
            aside.display()
        ));
    }
    Ok(notes)
}

const ASIDE_MARK: &str = ".untrusted-";

/// Create `dir` with the protected DACL in one step, so there is no moment in
/// which it has the permissive permissions inherited from ProgramData.
/// `Ok(false)` if it already exists.
fn create_protected(dir: &Path) -> Result<bool> {
    use windows::Win32::Foundation::ERROR_ALREADY_EXISTS;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;
    let sddl = wide(DIR_SDDL);
    let path = wide(&dir.to_string_lossy());
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let res = CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&sa));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        match res {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ERROR_ALREADY_EXISTS.to_hresult() => Ok(false),
            Err(e) => Err(e).with_context(|| format!("create {}", dir.display())),
        }
    }
}

fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    // Unreadable counts as "do not follow".
    std::fs::symlink_metadata(path).map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0).unwrap_or(true)
}

/// A real file or folder (no link) that SYSTEM or the Administrators own.
fn is_trusted(path: &Path) -> bool {
    !is_reparse_point(path) && crate::trust::owned_by_admins(&path.to_string_lossy())
}

/// Rename out of the way (nothing is deleted, an administrator can inspect it).
fn move_aside(path: &Path) -> Result<PathBuf> {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!("{ASIDE_MARK}{}", briqwall_common::now_secs()));
    let aside = path.with_file_name(name);
    std::fs::rename(path, &aside).with_context(|| format!("move {} aside", path.display()))?;
    Ok(aside)
}

fn set_sddl(path: &Path, sddl: &str) -> Result<()> {
    let w = wide(sddl);
    let p = wide(&path.to_string_lossy());
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(w.as_ptr()), SDDL_REVISION_1, &mut sd, None)?;
        let ok = SetFileSecurityW(
            PCWSTR(p.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        );
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        if !ok.as_bool() {
            anyhow::bail!("SetFileSecurityW failed: {}", windows::core::Error::from_thread());
        }
    }
    Ok(())
}

pub fn load(dir: &Path) -> State {
    let path = dir.join("state.json");
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<State>(&bytes) {
            Ok(mut s) => {
                s.migrate();
                s
            }
            Err(e) => {
                log::error!("state.json unlesbar ({e}); Sicherung angelegt, starte neu");
                let _ = std::fs::copy(&path, dir.join("state.corrupt.json"));
                State::default()
            }
        },
        Err(_) => State::default(),
    }
}

/// Atomic save (write temp file, then rename).
pub fn save(dir: &Path, state: &State) -> Result<()> {
    let tmp = dir.join("state.json.tmp");
    let data = serde_json::to_vec_pretty(state)?;
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join("state.json"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal file logger
// ---------------------------------------------------------------------------

struct FileLogger {
    file: std::sync::Mutex<Option<std::fs::File>>,
    echo: bool,
}

impl log::Log for FileLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info || m.target().starts_with("briqwall")
    }
    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let line = format!("{} {:5} {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), r.level(), r.args());
        if self.echo {
            eprint!("{line}");
        }
        if let Ok(mut g) = self.file.lock() {
            if let Some(f) = g.as_mut() {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
    fn flush(&self) {}
}

pub fn init_logging(dir: &Path, echo: bool) {
    let path = dir.join("service.log");
    // Simple rotation: keep the previous log when it grows beyond 5 MB.
    if std::fs::metadata(&path).map(|m| m.len() > 5 * 1024 * 1024).unwrap_or(false) {
        let _ = std::fs::rename(&path, dir.join("service.old.log"));
    }
    let file = std::fs::OpenOptions::new().create(true).append(true).open(&path).ok();
    let logger = Box::new(FileLogger { file: std::sync::Mutex::new(file), echo });
    if log::set_boxed_logger(logger).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_reverts_only_the_audit_settings_we_made() {
        let both: Vec<String> = crate::watchers::AUDIT_SUBCATEGORIES.iter().map(|(sc, _)| sc.to_string()).collect();
        let mut s = State::default();
        assert!(s.audit_to_revert().is_empty(), "the administrator's own setting stays");
        // Recorded by an older version: it only knew "something was enabled".
        s.audit_enabled_by_us = true;
        assert_eq!(s.audit_to_revert(), both);
        // One of the two was already on when Briqwall was installed.
        s.audit_enabled = vec![both[1].clone()];
        assert_eq!(s.audit_to_revert(), vec![both[1].clone()]);
        // Older state files without the list still load.
        let old: State = serde_json::from_str(r#"{"settings":{"mode":"Balanced","previous_mode":"Balanced","lan_discovery":true,"learn_publishers":true,"learned_publishers":[],"network_trust":{}},"apps":{},"audit_enabled_by_us":true}"#).unwrap();
        assert_eq!(old.audit_to_revert(), both);
    }

    /// A data folder that someone else created beforehand – with a policy of
    /// their own inside – must not be used as it is.
    #[test]
    fn foreign_data_dir_is_replaced() {
        let base = std::env::temp_dir().join(format!("briqwall-dirtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.join("data");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("state.json"), b"{}").unwrap();
        // Run as a normal user the folder is ours, not the administrators'.
        // Elevated (CI), everything we create belongs to the administrators.
        let foreign = !crate::trust::owned_by_admins(&dir.to_string_lossy());

        let notes = prepare_dir(&dir, true).unwrap();
        let aside = std::fs::read_dir(&base).unwrap().flatten().any(|e| e.file_name().to_string_lossy().contains(ASIDE_MARK));
        if foreign {
            assert_eq!(notes.len(), 1, "{notes:?}");
            assert!(aside, "the foreign folder is kept for inspection");
            assert!(dir.is_dir() && !dir.join("state.json").exists(), "a planted policy must not be read");
        } else {
            assert!(notes.is_empty(), "{notes:?}");
            assert!(!aside && dir.join("state.json").exists());
        }
        // A second start finds the folder as it left it.
        if !foreign {
            assert!(prepare_dir(&dir, true).unwrap().is_empty());
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
