//! Texts of the command-line interface in German and English. The language
//! follows the Windows display language (German → German, otherwise English).
//! The service log stays German-only on purpose (it is a support artefact).

use std::sync::OnceLock;

fn german() -> bool {
    static DE: OnceLock<bool> = OnceLock::new();
    *DE.get_or_init(|| {
        // LANGID: primary language in the low 10 bits; 0x07 = German.
        let id = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
        id & 0x3ff == 0x07
    })
}

/// Pick the German or English variant.
pub fn t(de: &'static str, en: &'static str) -> &'static str {
    if german() {
        de
    } else {
        en
    }
}

pub fn usage(version: &str) -> String {
    if german() {
        format!(
            "Briqwall {version} – Firewall-Dienst\n\n\
             Befehle:\n  install      Dienst installieren und starten (Admin)\n  \
             uninstall    Dienst entfernen und alle Filter löschen (Admin) [--purge: auch Daten]\n  \
             reset        Notfall: alle Briqwall-Filter sofort entfernen (Admin)\n  \
             console      im Vordergrund ausführen (Fehlersuche)\n  \
             check <exe>  zeigen, wie Briqwall eine Datei einstuft"
        )
    } else {
        format!(
            "Briqwall {version} – firewall service\n\n\
             Commands:\n  install      install and start the service (admin)\n  \
             uninstall    remove the service and all filters (admin) [--purge: also data]\n  \
             reset        emergency: remove all Briqwall filters immediately (admin)\n  \
             console      run in the foreground (troubleshooting)\n  \
             check <exe>  show how Briqwall classifies a file"
        )
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
