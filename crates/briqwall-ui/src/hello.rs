//! Windows Hello (KeyCredentialManager): a TPM-bound key that only signs
//! after the user confirmed with fingerprint, face or PIN.

use windows::core::{Array, HSTRING};
use windows::Security::Credentials::{KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;

use crate::i18n::t;

const KEY_NAME: &str = "Briqwall-Freigabe";
/// Key name used before the product was renamed from "xWall".
const LEGACY_KEY_NAME: &str = "xWall-Freigabe";

#[derive(Debug)]
pub enum HelloError {
    Cancelled,
    /// No key on this machine/account (e.g. another Windows user).
    NotFound,
    Failed(String),
}

impl From<windows::core::Error> for HelloError {
    fn from(e: windows::core::Error) -> Self {
        HelloError::Failed(e.message().to_string())
    }
}

fn status_err(s: KeyCredentialStatus) -> HelloError {
    match s {
        KeyCredentialStatus::UserCanceled => HelloError::Cancelled,
        KeyCredentialStatus::NotFound => HelloError::NotFound,
        KeyCredentialStatus::SecurityDeviceLocked => HelloError::Failed(t("Das Sicherheitsgerät ist gesperrt.", "The security device is locked.").into()),
        KeyCredentialStatus::UserPrefersPassword => HelloError::Cancelled,
        _ => HelloError::Failed(format!("{} {}", t("Windows Hello meldet Status", "Windows Hello reported status"), s.0)),
    }
}

fn to_vec(buf: &IBuffer) -> windows::core::Result<Vec<u8>> {
    let mut arr = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buf, &mut arr)?;
    Ok(arr.to_vec())
}

/// Is Windows Hello set up for this user (PIN, fingerprint or face)?
pub fn supported() -> bool {
    KeyCredentialManager::IsSupportedAsync().and_then(|op| op.join()).unwrap_or(false)
}

/// Create (or replace) the Briqwall key. Shows the Hello prompt.
/// Returns the public key as X.509 SubjectPublicKeyInfo (DER).
pub fn create_key() -> Result<Vec<u8>, HelloError> {
    let _focus = FocusPrompt::start();
    let r = KeyCredentialManager::RequestCreateAsync(&HSTRING::from(KEY_NAME), KeyCredentialCreationOption::ReplaceExisting)?
        .join()?;
    let st = r.Status()?;
    if st != KeyCredentialStatus::Success {
        return Err(status_err(st));
    }
    Ok(to_vec(&r.Credential()?.RetrievePublicKeyWithDefaultBlobType()?)?)
}

/// Sign `data` with the Briqwall key. Shows the Hello prompt.
pub fn sign(data: &[u8]) -> Result<Vec<u8>, HelloError> {
    let mut opened = KeyCredentialManager::OpenAsync(&HSTRING::from(KEY_NAME))?.join()?;
    if opened.Status()? == KeyCredentialStatus::NotFound {
        opened = KeyCredentialManager::OpenAsync(&HSTRING::from(LEGACY_KEY_NAME))?.join()?;
    }
    let st = opened.Status()?;
    if st != KeyCredentialStatus::Success {
        return Err(status_err(st));
    }
    let cred = opened.Credential()?;
    let _focus = FocusPrompt::start();
    let res = cred.RequestSignAsync(&CryptographicBuffer::CreateFromByteArray(data)?)?.join()?;
    let st = res.Status()?;
    if st != KeyCredentialStatus::Success {
        return Err(status_err(st));
    }
    Ok(to_vec(&res.Result()?)?)
}

pub fn delete_key() {
    for name in [KEY_NAME, LEGACY_KEY_NAME] {
        if let Ok(op) = KeyCredentialManager::DeleteAsync(&HSTRING::from(name)) {
            let _ = op.join();
        }
    }
}

/// From a desktop app the Hello dialog sometimes opens *behind* the active
/// window. While a prompt is pending, bring it to the front.
struct FocusPrompt {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl FocusPrompt {
    fn start() -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        std::thread::spawn(move || {
            let class = briqwall_common::util::wide("Credential Dialog Xaml Host");
            for _ in 0..40 {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(h) = unsafe { FindWindowW(windows::core::PCWSTR(class.as_ptr()), None) } {
                    if !h.is_invalid() {
                        unsafe {
                            let _ = SetForegroundWindow(h);
                        }
                        return;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        Self { stop }
    }
}

impl Drop for FocusPrompt {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
