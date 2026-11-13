//! What the elevated helper (`briqwall.exe --apply`) shows before it changes
//! anything.
//!
//! The UAC prompt only says "Briqwall wants to make changes" – not which
//! ones. Any program can start the helper with a request of its own choosing
//! and hope the user approves the familiar name. So the helper spells the
//! change out and asks again. It runs elevated, which keeps other programs of
//! the same user from pressing its buttons.

use crate::i18n::{self, t};
use briqwall_common::{now_secs, AppInfo, Request, Response, RuleAccess, Status, UserRule};

/// Longest list shown in the dialog; the rest is summarized.
const MAX_LINES: usize = 12;
const MAX_TEXT: usize = 160;

/// The single changes of a request. `None` if it contains something the
/// helper never applies: read-only requests, challenges, signed approvals or
/// batches inside batches. None of them needs elevation, so their presence
/// means the caller is not the Briqwall interface.
pub fn changes(req: &Request) -> Option<Vec<&Request>> {
    fn single(r: &Request) -> bool {
        matches!(
            r,
            Request::SetMode(_)
                | Request::SetRule { .. }
                | Request::Snooze { .. }
                | Request::Forget { .. }
                | Request::SetNetworkTrust { .. }
                | Request::SetOptions { .. }
                | Request::RemovePublisher(_)
                | Request::TrustFolder { .. }
                | Request::UntrustFolder(_)
                | Request::EnrollHello { .. }
                | Request::RemoveHello { .. }
        )
    }
    let list: Vec<&Request> = match req {
        Request::Batch(reqs) => reqs.iter().collect(),
        one => vec![one],
    };
    (!list.is_empty() && list.iter().all(|r| single(r))).then_some(list)
}

/// Names for the keys and ids in a request, as far as the service knows them.
#[derive(Default)]
pub struct Names {
    pub apps: Vec<AppInfo>,
    pub status: Option<Status>,
}

impl Names {
    /// Best effort: the dialog works without the service, it just shows keys.
    pub fn fetch() -> Self {
        let apps = match briqwall_common::ipc::call(&Request::Apps) {
            Ok(Response::Apps(a)) => a,
            _ => Vec::new(),
        };
        let status = match briqwall_common::ipc::call(&Request::Status) {
            Ok(Response::Status(s)) => Some(*s),
            _ => None,
        };
        Self { apps, status }
    }

    /// The path of the program. Deliberately not its display name: that comes
    /// from the file itself and says whatever its author wants it to say.
    fn app(&self, key: &str) -> String {
        clean(self.apps.iter().find(|a| a.key == key).map_or(key, |a| a.path.as_str()))
    }

    /// The program folder the app belongs to (its path if the service does
    /// not name one – the request will then be turned down anyway).
    fn folder(&self, key: &str) -> String {
        let app = self.apps.iter().find(|a| a.key == key);
        clean(app.and_then(|a| a.install_folder.as_deref()).or(app.map(|a| a.path.as_str())).unwrap_or(key))
    }

    fn network(&self, id: &str) -> String {
        let name = self.status.as_ref().and_then(|s| s.networks.iter().find(|n| n.id == id)).map(|n| n.name.as_str());
        clean(name.filter(|n| !n.is_empty()).unwrap_or(id))
    }
}

/// One line, no control or direction-changing characters, bounded length.
fn clean(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() || ('\u{2028}'..='\u{202e}').contains(&c) || ('\u{2066}'..='\u{2069}').contains(&c) { ' ' } else { c })
        .collect();
    if out.chars().count() > MAX_TEXT {
        out = out.chars().take(MAX_TEXT).collect::<String>() + "…";
    }
    out
}

fn access(a: RuleAccess) -> &'static str {
    match a {
        RuleAccess::Auto => t("automatisch", "automatic"),
        RuleAccess::Allow => t("erlauben", "allow"),
        RuleAccess::Lan => t("nur lokales Netzwerk", "local network only"),
        RuleAccess::Block => t("blockieren", "block"),
    }
}

fn rule_text(r: &UserRule) -> String {
    let duration = match r.expires {
        None => t("dauerhaft", "permanently").to_string(),
        Some(end) => {
            let minutes = end.saturating_sub(now_secs()).div_ceil(60);
            format!("{} {minutes} {}", t("für", "for"), t("Minuten", "minutes"))
        }
    };
    format!(
        "{} {}, {} {} ({duration})",
        t("Internet:", "internet:"),
        access(r.outbound),
        t("eingehend:", "inbound:"),
        access(r.inbound)
    )
}

fn on_off(v: bool) -> &'static str {
    if v {
        t("einschalten", "turn on")
    } else {
        t("ausschalten", "turn off")
    }
}

/// One line per change, in the user's language.
pub fn describe(req: &Request, names: &Names) -> Vec<String> {
    match req {
        Request::SetMode(m) => vec![format!("{} {}", t("Schutzstufe ändern auf:", "Change protection level to:"), i18n::mode_name(*m))],
        Request::SetRule { key, rule: Some(r) } => vec![format!("{} – {}", names.app(key), rule_text(r))],
        Request::SetRule { key, rule: None } => {
            vec![format!("{} – {}", names.app(key), t("eigene Regel entfernen (wieder automatisch)", "remove custom rule (back to automatic)"))]
        }
        Request::Snooze { key } => vec![format!("{} – {}", names.app(key), t("Anfrage für einen Tag ausblenden", "hide request for a day"))],
        Request::Forget { key } => {
            vec![format!("{} – {}", names.app(key), t("aus der Liste entfernen, samt Regel", "remove from the list, including its rule"))]
        }
        Request::SetNetworkTrust { id, trusted } => {
            let what = match trusted {
                Some(true) => t("als Heimnetzwerk einstufen (vertrauenswürdig)", "treat as home network (trusted)"),
                Some(false) => t("als öffentliches Netzwerk einstufen", "treat as public network"),
                None => t("wieder wie Windows einstufen", "classify like Windows again"),
            };
            vec![format!("{} {} – {what}", t("Netzwerk", "Network"), names.network(id))]
        }
        Request::SetOptions { lan_discovery, learn_publishers } => {
            let mut v = Vec::new();
            if let Some(on) = lan_discovery {
                v.push(format!("{} {}", t("Windows-Dienste im Heimnetzwerk:", "Windows services on the home network:"), on_off(*on)));
            }
            if let Some(on) = learn_publishers {
                v.push(format!("{} {}", t("Herausgeber merken:", "Remember publishers:"), on_off(*on)));
            }
            v
        }
        Request::RemovePublisher(p) => vec![format!("{} {}", t("Herausgeber nicht mehr vertrauen:", "Stop trusting publisher:"), clean(p))],
        Request::TrustFolder { key } => vec![format!(
            "{} {} – {}",
            t("Programmordner vertrauen:", "Trust program folder:"),
            names.folder(key),
            t(
                "alle dort installierten Programme dürfen ins Internet, auch ohne Signatur",
                "every program installed there may go online, signed or not"
            )
        )],
        Request::UntrustFolder(folder) => {
            vec![format!("{} {}", t("Programmordner nicht mehr vertrauen:", "Stop trusting program folder:"), clean(folder))]
        }
        Request::EnrollHello { name, sid, .. } => vec![format!(
            "{} {} ({}) – {}",
            t("Windows Hello einrichten für Konto", "Set up Windows Hello for account"),
            clean(name),
            clean(sid),
            t(
                "dieses Konto kann Freigaben danach ohne diese Abfrage bestätigen",
                "this account can then confirm permissions without this prompt"
            )
        )],
        Request::RemoveHello { sid } => {
            vec![format!("{} {}", t("Windows Hello entfernen für Konto", "Remove Windows Hello for account"), clean(sid))]
        }
        // Not applied by the helper (see `changes`).
        Request::Batch(_)
        | Request::Status
        | Request::Apps
        | Request::Events { .. }
        | Request::AddApp { .. }
        | Request::Challenge
        | Request::Approved { .. } => Vec::new(),
    }
}

/// The text of the confirmation dialog.
pub fn message(list: &[&Request], names: &Names) -> String {
    let lines: Vec<String> = list.iter().flat_map(|r| describe(r, names)).collect();
    let mut text = String::from(t(
        "Briqwall soll folgende Änderung vornehmen:",
        "Briqwall is about to make the following change:",
    ));
    text.push_str("\n\n");
    for line in lines.iter().take(MAX_LINES) {
        text.push_str("•  ");
        text.push_str(line);
        text.push('\n');
    }
    if lines.len() > MAX_LINES {
        text.push_str(&format!("… {} {}\n", lines.len() - MAX_LINES, t("weitere", "more")));
    }
    text.push('\n');
    text.push_str(t(
        "Haben Sie das gerade selbst in Briqwall ausgelöst? Wenn nicht, wählen Sie „Nein“.",
        "Did you just ask for this in Briqwall yourself? If not, choose “No”.",
    ));
    text
}

/// Ask the user. "No" is the default button.
pub fn ask(text: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO,
    };
    let text = briqwall_common::util::wide(text);
    let title = briqwall_common::util::wide(t("Briqwall – Änderung bestätigen", "Briqwall – confirm change"));
    let style = MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST;
    unsafe { MessageBoxW(None, PCWSTR(text.as_ptr()), PCWSTR(title.as_ptr()), style) == IDYES }
}

#[cfg(test)]
mod tests {
    use super::*;
    use briqwall_common::Mode;

    fn allow(key: &str) -> Request {
        Request::SetRule {
            key: key.into(),
            rule: Some(UserRule { outbound: RuleAccess::Allow, inbound: RuleAccess::Auto, expires: None, created: 1 }),
        }
    }

    #[test]
    fn only_plain_changes_are_applied() {
        assert_eq!(changes(&Request::SetMode(Mode::Off)).map(|l| l.len()), Some(1));
        assert_eq!(changes(&Request::Batch(vec![allow("a"), allow("b")])).map(|l| l.len()), Some(2));
        assert!(changes(&Request::Batch(vec![])).is_none());
        assert!(changes(&Request::Batch(vec![allow("a"), Request::Batch(vec![allow("b")])])).is_none());
        assert!(changes(&Request::Challenge).is_none());
        assert!(changes(&Request::Apps).is_none());
        let signed = Request::Approved { nonce: "n".into(), payload: "[]".into(), signature: "s".into() };
        assert!(changes(&Request::Batch(vec![allow("a"), signed])).is_none());
    }

    #[test]
    fn every_applied_change_is_described() {
        i18n::set("en");
        let names = Names::default();
        let enroll = Request::EnrollHello { public_key: "00".into(), sid: "S-1-5-21-1".into(), name: "Kim".into() };
        let all = [
            Request::SetMode(Mode::Off),
            allow("c:\\x\\a.exe"),
            Request::SetRule { key: "k".into(), rule: None },
            Request::Snooze { key: "k".into() },
            Request::Forget { key: "k".into() },
            Request::SetNetworkTrust { id: "{id}".into(), trusted: Some(true) },
            Request::SetOptions { lan_discovery: Some(true), learn_publishers: None },
            Request::RemovePublisher("P".into()),
            Request::TrustFolder { key: "k".into() },
            Request::UntrustFolder("C:\\Program Files\\X".into()),
            enroll,
            Request::RemoveHello { sid: "S-1-5-21-1".into() },
        ];
        for r in &all {
            assert!(changes(r).is_some(), "{r:?}");
            assert!(!describe(r, &names).is_empty(), "{r:?}");
        }
        let text = message(&[&all[0], &all[1]], &names);
        assert!(text.contains("Off") && text.contains("c:\\x\\a.exe") && text.contains("allow") && text.contains("permanently"));
    }

    #[test]
    fn long_lists_and_odd_characters_stay_readable() {
        i18n::set("en");
        let reqs: Vec<Request> = (0..30).map(|i| allow(&format!("c:\\app{i}.exe"))).collect();
        let list: Vec<&Request> = reqs.iter().collect();
        let text = message(&list, &Names::default());
        assert!(text.contains("app11.exe") && !text.contains("app12.exe") && text.contains("18 more"));
        assert_eq!(clean("a\nb\u{202e}c"), "a b c");
        assert!(clean(&"x".repeat(500)).chars().count() <= MAX_TEXT + 1);
    }
}
