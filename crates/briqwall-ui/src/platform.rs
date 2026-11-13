//! Win32 glue: single instance, per-action elevation, toast notifications,
//! autostart, protocol handler.

use anyhow::{anyhow, Result};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_CANCELLED, HANDLE};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{
    CreateEventW, CreateMutexW, GetExitCodeProcess, SetEvent, WaitForSingleObject, INFINITE,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use briqwall_common::util::{hex, wide};
use briqwall_common::Request;
use crate::i18n::t;

pub const AUMID: &str = "Briqwall.Firewall";
const MUTEX_NAME: &str = r"Local\briqwall-ui-instance";
const SHOW_EVENT_NAME: &str = r"Local\briqwall-ui-show";

// ---------------------------------------------------------------------------
// Single instance
// ---------------------------------------------------------------------------

pub enum Instance {
    /// We are the first instance; the event fires when another instance wants us shown.
    Primary { show_event: SendHandle },
    /// Another instance is running and has been asked to show itself.
    Secondary,
}

pub struct SendHandle(pub HANDLE);
unsafe impl Send for SendHandle {}

pub fn acquire_instance() -> Instance {
    unsafe {
        // Low-integrity label + everyone access: a non-elevated second instance
        // (e.g. launched from a toast) must be able to signal an elevated first
        // instance. The event can only ever *show the window*, so this is harmless.
        let sddl = wide("D:(A;;GA;;;WD)S:(ML;;NW;;;LW)");
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let sa = if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .is_ok()
        {
            Some(SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            })
        } else {
            None
        };
        let ev_name = wide(SHOW_EVENT_NAME);
        let event = CreateEventW(sa.as_ref().map(|s| s as *const _), false, false, PCWSTR(ev_name.as_ptr()));

        let m_name = wide(MUTEX_NAME);
        let mutex = CreateMutexW(sa.as_ref().map(|s| s as *const _), true, PCWSTR(m_name.as_ptr()));
        let exists = match &mutex {
            Ok(_) => GetLastError() == ERROR_ALREADY_EXISTS,
            Err(_) => true, // access denied => owned by someone else
        };
        match (exists, event) {
            (true, Ok(ev)) => {
                let _ = SetEvent(ev);
                Instance::Secondary
            }
            (true, Err(_)) => Instance::Secondary,
            (false, Ok(ev)) => {
                // Keep the mutex handle open for the process lifetime.
                std::mem::forget(mutex);
                Instance::Primary { show_event: SendHandle(ev) }
            }
            (false, Err(_)) => Instance::Primary { show_event: SendHandle(HANDLE::default()) },
        }
    }
}

/// Blocks on the show event and calls `f` each time another instance asks.
pub fn spawn_show_listener(ev: SendHandle, f: impl Fn() + Send + 'static) {
    if ev.0.is_invalid() || ev.0 .0.is_null() {
        return;
    }
    std::thread::spawn(move || {
        let ev = ev;
        loop {
            unsafe { WaitForSingleObject(ev.0, INFINITE) };
            f();
        }
    });
}

// ---------------------------------------------------------------------------
// Per-action elevation ("sudo" for a single request)
// ---------------------------------------------------------------------------

pub enum ElevationResult {
    Applied,
    Cancelled,
    Failed(String),
}

/// Run `briqwall.exe --apply <hex>` elevated. UAC appears on the secure desktop,
/// so malware running as the user cannot click "Yes" for us.
pub fn apply_elevated(req: &Request) -> ElevationResult {
    let Ok(json) = serde_json::to_vec(req) else { return ElevationResult::Failed("serialization".into()) };
    let Ok(exe) = std::env::current_exe() else { return ElevationResult::Failed("current_exe".into()) };
    run_elevated(&exe.to_string_lossy(), &format!("--apply {}", hex(&json)))
}

/// ShellExecuteEx("runas") and wait for the process to finish.
pub fn run_elevated(file: &str, params: &str) -> ElevationResult {
    let file = wide(file);
    let params = wide(params);
    let verb = wide("runas");
    unsafe {
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: PCWSTR(verb.as_ptr()),
            lpFile: PCWSTR(file.as_ptr()),
            lpParameters: PCWSTR(params.as_ptr()),
            nShow: SW_HIDE.0,
            ..Default::default()
        };
        if let Err(e) = ShellExecuteExW(&mut info) {
            if e.code() == ERROR_CANCELLED.to_hresult() {
                return ElevationResult::Cancelled;
            }
            return ElevationResult::Failed(e.message().to_string());
        }
        if info.hProcess.is_invalid() {
            return ElevationResult::Failed(t("Der Prozess konnte nicht gestartet werden.", "The process could not be started.").into());
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        let _ = GetExitCodeProcess(info.hProcess, &mut code);
        let _ = CloseHandle(info.hProcess);
        match code {
            0 => ElevationResult::Applied,
            // "No" in the helper's own confirmation dialog.
            4 => ElevationResult::Cancelled,
            3 => ElevationResult::Failed(t("Der Dienst hat die Änderung abgelehnt.", "The service rejected the change.").into()),
            _ => ElevationResult::Failed(t("Der Dienst ist nicht erreichbar.", "The service is not reachable.").into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Registry integration (per-user; no admin needed)
// ---------------------------------------------------------------------------

fn exe_path() -> String {
    std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Remove per-user traces of the old product name "xWall" and carry over the
/// user's UI preferences (notifications, autostart).
pub fn migrate_legacy_user_settings() {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_ALL_ACCESS};
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(old) = hkcu.open_subkey(r"Software\xWall") {
        for name in ["Notifications", "FirstRunDone"] {
            if let (Ok(v), None) = (old.get_value::<u32, _>(name), ui_pref(name)) {
                set_ui_pref(name, v);
            }
        }
        let _ = hkcu.delete_subkey_all(r"Software\xWall");
    }
    if let Ok(run) = hkcu.open_subkey_with_flags(RUN_KEY, KEY_ALL_ACCESS) {
        if run.get_value::<String, _>("xWall").is_ok() {
            let _ = run.delete_value("xWall");
            let _ = set_autostart(true);
        }
    }
    let _ = hkcu.delete_subkey_all(r"Software\Classes\xwall");
    let _ = hkcu.delete_subkey_all(r"Software\Classes\AppUserModelId\xWall.Firewall");
}

/// Register the toast identity and the `briqwall:` protocol (used by toast clicks).
/// The protocol can only *show* the window – it never carries actions, because
/// any website or program could invoke it.
pub fn register_shell_integration() {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((k, _)) = hkcu.create_subkey(format!(r"Software\Classes\AppUserModelId\{AUMID}")) {
        let _ = k.set_value("DisplayName", &"Briqwall Firewall");
    }
    if let Ok((k, _)) = hkcu.create_subkey(r"Software\Classes\briqwall") {
        let _ = k.set_value("", &"URL:Briqwall");
        let _ = k.set_value("URL Protocol", &"");
        if let Ok((c, _)) = k.create_subkey(r"shell\open\command") {
            let _ = c.set_value("", &format!("\"{}\" --show", exe_path()));
        }
    }
}

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

pub fn autostart_enabled() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    winreg::RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .and_then(|k| k.get_value::<String, _>("Briqwall"))
        .is_ok()
}

pub fn set_autostart(on: bool) -> Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    let k = winreg::RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE)?;
    if on {
        k.set_value("Briqwall", &format!("\"{}\" --minimized", exe_path()))?;
    } else {
        let _ = k.delete_value("Briqwall");
    }
    Ok(())
}

/// Small per-user preferences of the UI itself.
pub fn ui_pref(name: &str) -> Option<u32> {
    use winreg::enums::HKEY_CURRENT_USER;
    winreg::RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Briqwall")
        .and_then(|k| k.get_value::<u32, _>(name))
        .ok()
}

pub fn ui_pref_str(name: &str) -> Option<String> {
    use winreg::enums::HKEY_CURRENT_USER;
    winreg::RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Briqwall")
        .and_then(|k| k.get_value::<String, _>(name))
        .ok()
}

pub fn set_ui_pref_str(name: &str, v: &str) {
    use winreg::enums::HKEY_CURRENT_USER;
    if let Ok((k, _)) = winreg::RegKey::predef(HKEY_CURRENT_USER).create_subkey(r"Software\Briqwall") {
        let _ = k.set_value(name, &v);
    }
}

pub fn set_ui_pref(name: &str, v: u32) {
    use winreg::enums::HKEY_CURRENT_USER;
    if let Ok((k, _)) = winreg::RegKey::predef(HKEY_CURRENT_USER).create_subkey(r"Software\Briqwall") {
        let _ = k.set_value(name, &v);
    }
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Show a Windows notification. Clicking it opens Briqwall; `action` adds a
/// labelled button that does the same (only where a button makes sense).
pub fn toast(title: &str, body: &str, action: Option<&str>) -> Result<()> {
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    let actions = action
        .map(|label| {
            format!(
                r#"<actions><action content="{}" activationType="protocol" arguments="briqwall:inbox"/></actions>"#,
                xml_escape(label)
            )
        })
        .unwrap_or_default();
    let xml = format!(
        r#"<toast activationType="protocol" launch="briqwall:inbox">
  <visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual>
  {actions}
</toast>"#,
        xml_escape(title),
        xml_escape(body)
    );
    let doc = XmlDocument::new().map_err(|e| anyhow!("{e}"))?;
    doc.LoadXml(&HSTRING::from(xml)).map_err(|e| anyhow!("{e}"))?;
    let n = ToastNotification::CreateToastNotification(&doc).map_err(|e| anyhow!("{e}"))?;
    let notifier =
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID)).map_err(|e| anyhow!("{e}"))?;
    notifier.Show(&n).map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

/// SID and display name of the account this UI runs as. The SID identifies
/// the Windows Hello key in the service (one key per account).
pub fn current_user() -> (String, String) {
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::WindowsProgramming::GetUserNameW;

    let mut name = String::new();
    let mut buf = [0u16; 257];
    let mut len = buf.len() as u32;
    if unsafe { GetUserNameW(Some(windows::core::PWSTR(buf.as_mut_ptr())), &mut len) }.is_ok() {
        name = briqwall_common::util::from_wide(&buf);
    }

    let mut sid = String::new();
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            let mut size = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
            let mut data = vec![0u8; size as usize];
            if size > 0 && GetTokenInformation(token, TokenUser, Some(data.as_mut_ptr() as *mut _), size, &mut size).is_ok() {
                let user = &*(data.as_ptr() as *const TOKEN_USER);
                let mut text = windows::core::PWSTR::null();
                if ConvertSidToStringSidW(user.User.Sid, &mut text).is_ok() {
                    sid = text.to_string().unwrap_or_default();
                    let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(text.0 as *mut _)));
                }
            }
            let _ = CloseHandle(token);
        }
    }
    (sid, name)
}
