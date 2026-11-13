//! Language of the native parts (tray, notifications, error messages).
//! The web UI has its own dictionaries; both follow the same preference:
//! "system" (Windows display language), "de" or "en".

use std::sync::atomic::{AtomicBool, Ordering};

static GERMAN: AtomicBool = AtomicBool::new(true);

fn system_is_german() -> bool {
    // LANGID: primary language in the low 10 bits; 0x07 = German.
    let id = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
    id & 0x3ff == 0x07
}

/// The language actually used for a preference value.
pub fn resolve(pref: &str) -> &'static str {
    match pref {
        "de" => "de",
        "en" => "en",
        _ if system_is_german() => "de",
        _ => "en",
    }
}

pub fn system_language() -> &'static str {
    resolve("system")
}

/// Apply a preference ("system", "de", "en").
pub fn set(pref: &str) {
    GERMAN.store(resolve(pref) == "de", Ordering::SeqCst);
}

/// Pick the German or English variant.
pub fn t(de: &'static str, en: &'static str) -> &'static str {
    if GERMAN.load(Ordering::SeqCst) {
        de
    } else {
        en
    }
}

pub fn mode_name(m: briqwall_common::Mode) -> &'static str {
    use briqwall_common::Mode::*;
    match m {
        Off => t("Aus", "Off"),
        Relaxed => t("Entspannt", "Relaxed"),
        Balanced => t("Ausgewogen", "Balanced"),
        Strict => t("Streng", "Strict"),
        Lockdown => t("Notfall-Sperre", "Lockdown"),
    }
}

/// Human-readable text for an error code from the service.
pub fn error_text(e: &briqwall_common::ErrorCode) -> String {
    use briqwall_common::ErrorCode::*;
    match e {
        UnknownApp => t("Diese App ist nicht mehr bekannt.", "This app is no longer known.").into(),
        SystemEntry => t("Systemeinträge können nicht entfernt werden.", "System entries cannot be removed.").into(),
        TooManyApprovals => t("Zu viele offene Bestätigungen.", "Too many pending confirmations.").into(),
        ApprovalExpired => {
            t("Die Bestätigung ist abgelaufen. Bitte erneut versuchen.", "The confirmation expired. Please try again.").into()
        }
        HelloNotEnrolled => t("Windows Hello ist nicht eingerichtet.", "Windows Hello is not set up.").into(),
        NotApprovableWithHello => {
            t("Diese Änderung kann nicht per Windows Hello bestätigt werden.", "This change cannot be confirmed with Windows Hello.")
                .into()
        }
        InvalidKey => t("Ungültiger Schlüssel.", "Invalid key.").into(),
        ServiceTimeout => t("Der Dienst hat nicht rechtzeitig geantwortet.", "The service did not respond in time.").into(),
        BadRequest(detail) => format!("{} ({detail})", t("Ungültige Anfrage", "Invalid request")),
    }
}

pub fn unexpected_response() -> String {
    t("Unerwartete Antwort des Dienstes.", "Unexpected response from the service.").into()
}
