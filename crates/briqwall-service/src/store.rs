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
    /// Public key (hex SPKI) of the Windows Hello credential used to sign approvals.
    #[serde(default)]
    pub hello_key: Option<String>,
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
    let Some(old_state) = legacy.map(|d| d.join("state.json")).filter(|p| p.exists()) else { return };
    match std::fs::copy(&old_state, &new_state) {
        Ok(_) => log::info!("Regeln aus {} übernommen", old_state.display()),
        Err(e) => log::warn!("Übernahme von {} fehlgeschlagen: {e}", old_state.display()),
    }
}

pub fn prepare_dir(dir: &Path, protect: bool) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    if protect {
        // SYSTEM + Administrators full control, Users read; not inherited from ProgramData.
        set_sddl(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")?;
    }
    Ok(())
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
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(s) => s,
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
