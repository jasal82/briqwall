//! The automatic trust decision: the heart of "easy but safe".
//!
//! Instead of asking the user about ports and protocols, Briqwall asks one question
//! about every executable: *could an unprivileged process have put this file here?*
//! Software that only an administrator could have installed is treated very
//! differently from a binary that appeared in Downloads or AppData. Code signing,
//! known publishers and a list of frequently abused Windows tools refine this.

use briqwall_common::{Access, AppInfo, Category, Mode, Reason, Risk, RuleAccess, Signature};

/// Windows binaries that are signed by Microsoft but routinely abused to download
/// or run malicious payloads ("living off the land"). Never trusted automatically
/// in balanced/strict mode.
pub const LOLBINS: &[&str] = &[
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "certreq.exe",
    "bitsadmin.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "cmstp.exe",
    "wmic.exe",
    "msiexec.exe",
    "hh.exe",
    "curl.exe",
    "ftp.exe",
    "tftp.exe",
    "finger.exe",
    "msxsl.exe",
    "odbcconf.exe",
    "ieexec.exe",
    "presentationhost.exe",
    "desktopimgdownldr.exe",
    "msdt.exe",
    "xwizard.exe",
    "cmd.exe",
];

/// Publishers whose signed apps are commonly installed per-user (in AppData) and
/// are trusted automatically in balanced mode. Matched case-insensitively as prefix.
pub const KNOWN_PUBLISHERS: &[&str] = &[
    "Microsoft Corporation",
    "Microsoft Windows",
    "Google LLC",
    "Mozilla Corporation",
    "Apple Inc.",
    "Discord Inc.",
    "Spotify AB",
    "Zoom Video Communications",
    "Zoom Communications",
    "Slack Technologies",
    "Valve",
    "Epic Games",
    "Brave Software",
    "Opera Norway",
    "Dropbox, Inc",
    "JetBrains s.r.o.",
    "GitHub, Inc.",
    "Docker Inc",
    "Python Software Foundation",
    "Signal Messenger",
    "Telegram FZ-LLC",
    "WhatsApp",
    "Meta Platforms",
    "Notion Labs",
    "Figma, Inc.",
    "Postman, Inc.",
    "Proton AG",
    "Mozilla Foundation",
    "Adobe Inc.",
    "Adobe Systems",
    "NVIDIA Corporation",
    "Intel Corporation",
    "Advanced Micro Devices",
    "Logitech",
    "Electronic Arts",
    "Riot Games",
    "Blizzard Entertainment",
    "Ubisoft",
    "Cisco Systems",
    "Citrix Systems",
    "Oracle America",
    "Node.js Foundation",
    "OpenJS Foundation",
    "Anthropic",
    "OpenAI",
    "Obsidian",
    "Element",
    "1Password",
    "Bitwarden",
    "AgileBits",
    "TeamViewer",
    "Rustlang",
];

pub fn is_lolbin(file_name_lower: &str) -> bool {
    LOLBINS.contains(&file_name_lower)
}

pub fn is_known_publisher(p: &str) -> bool {
    let p = p.to_lowercase();
    KNOWN_PUBLISHERS.iter().any(|k| p.starts_with(&k.to_lowercase()))
}

pub fn is_learned_publisher(p: &str, learned: &[String]) -> bool {
    learned.iter().any(|l| l.eq_ignore_ascii_case(p))
}


#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub out: Access,
    pub inn: Access,
    pub reason: Reason,
}

pub struct Inputs<'a> {
    pub category: Category,
    pub signature: &'a Signature,
    pub mode: Mode,
    pub learned: &'a [String],
    pub lan_discovery: bool,
}

pub fn auto_verdict(i: &Inputs) -> Verdict {
    let publisher = i.signature.publisher();
    let learned = publisher.is_some_and(|p| is_learned_publisher(p, i.learned));
    let builtin = publisher.is_some_and(is_known_publisher);
    let relaxed = i.mode == Mode::Relaxed;
    let strict = i.mode == Mode::Strict;

    let (out, reason): (Access, Reason) = match i.category {
        Category::Pseudo => (Access::Allow, Reason::Kernel),
        Category::System => (Access::Allow, Reason::System),
        Category::Lolbin if relaxed => (Access::Allow, Reason::ToolRelaxed),
        Category::Lolbin => (Access::Ask, Reason::Tool),
        Category::Installed => match publisher {
            Some(p) => (Access::Allow, Reason::InstalledSigned(p.to_string())),
            None if strict => (Access::Ask, Reason::InstalledUnsignedStrict),
            None => (Access::Allow, Reason::Installed),
        },
        Category::UserSpace => match i.signature {
            Signature::Invalid { .. } => (Access::Ask, Reason::InvalidSignature),
            Signature::Valid { publisher, .. } if learned => (Access::Allow, Reason::LearnedPublisher(publisher.clone())),
            Signature::Valid { publisher, .. } if builtin && !strict => {
                (Access::Allow, Reason::KnownPublisher(publisher.clone()))
            }
            Signature::Valid { publisher, .. } if relaxed => (Access::Allow, Reason::SignedRelaxed(publisher.clone())),
            Signature::Valid { publisher, .. } => (Access::Ask, Reason::UnknownPublisher(publisher.clone())),
            Signature::Unsigned | Signature::Unknown => (Access::Ask, Reason::Unsigned),
        },
    };

    let inn = if relaxed {
        Access::Allow // = "Windows Firewall decides"; Briqwall installs no inbound default block
    } else if matches!(i.category, Category::System | Category::Pseudo)
        && i.lan_discovery
        && i.mode == Mode::Balanced
    {
        Access::Lan
    } else {
        Access::Block
    };

    Verdict { out, inn, reason }
}

pub fn risk(app: &AppInfo, learned: &[String]) -> Risk {
    if app.tampered || matches!(app.signature, Signature::Invalid { .. }) {
        return Risk::High;
    }
    match app.category {
        Category::System | Category::Pseudo | Category::Installed => Risk::Low,
        Category::Lolbin => Risk::Medium,
        Category::UserSpace => match app.signature.publisher() {
            Some(p) if is_learned_publisher(p, learned) || is_known_publisher(p) => Risk::Low,
            Some(_) => Risk::Medium,
            None if app.location_hint.is_some_and(|l| l.is_risky()) => Risk::High,
            None => Risk::Medium,
        },
    }
}

fn apply(rule: RuleAccess, auto: Access) -> Access {
    match rule {
        RuleAccess::Auto => auto,
        RuleAccess::Block => Access::Block,
        RuleAccess::Lan => Access::Lan,
        RuleAccess::Allow => Access::Allow,
    }
}

/// Combine automatic verdict with the user's rule. A tampered binary loses its
/// user rule until the user decides again.
pub fn effective(app: &AppInfo) -> (Access, Access) {
    match (&app.rule, app.tampered) {
        (Some(r), false) => (apply(r.outbound, app.auto_out), apply(r.inbound, app.auto_in)),
        (Some(r), true) => {
            // Keep explicit *blocks*, drop explicit permits.
            let keep = |ra: RuleAccess, auto: Access| if ra == RuleAccess::Block { Access::Block } else { auto };
            let out = keep(r.outbound, app.auto_out);
            let out = if out == Access::Block { out } else { Access::Ask };
            (out, keep(r.inbound, Access::Block))
        }
        (None, _) => (app.auto_out, app.auto_in),
    }
}

/// Is the explicit rule (not the auto verdict) responsible for this direction?
pub fn explicit(app: &AppInfo, outbound: bool) -> bool {
    app.rule.as_ref().is_some_and(|r| {
        let ra = if outbound { r.outbound } else { r.inbound };
        ra != RuleAccess::Auto && (!app.tampered || ra == RuleAccess::Block)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(cat: Category, sig: &'a Signature, mode: Mode) -> Inputs<'a> {
        Inputs { category: cat, signature: sig, mode, learned: &[], lan_discovery: true }
    }
    fn signed(p: &str) -> Signature {
        Signature::Valid { publisher: p.into(), catalog: false }
    }

    #[test]
    fn system_always_allowed() {
        for m in [Mode::Relaxed, Mode::Balanced, Mode::Strict] {
            assert_eq!(auto_verdict(&inputs(Category::System, &Signature::Unknown, m)).out, Access::Allow);
        }
    }

    #[test]
    fn lolbins_ask_unless_relaxed() {
        let s = signed("Microsoft Windows");
        assert_eq!(auto_verdict(&inputs(Category::Lolbin, &s, Mode::Balanced)).out, Access::Ask);
        assert_eq!(auto_verdict(&inputs(Category::Lolbin, &s, Mode::Strict)).out, Access::Ask);
        assert_eq!(auto_verdict(&inputs(Category::Lolbin, &s, Mode::Relaxed)).out, Access::Allow);
        assert!(is_lolbin("powershell.exe"));
    }

    #[test]
    fn unsigned_userspace_always_asks() {
        for m in [Mode::Relaxed, Mode::Balanced, Mode::Strict] {
            assert_eq!(auto_verdict(&inputs(Category::UserSpace, &Signature::Unsigned, m)).out, Access::Ask);
        }
    }

    #[test]
    fn known_publisher_in_appdata() {
        let s = signed("Discord Inc.");
        assert_eq!(auto_verdict(&inputs(Category::UserSpace, &s, Mode::Balanced)).out, Access::Allow);
        assert_eq!(auto_verdict(&inputs(Category::UserSpace, &s, Mode::Strict)).out, Access::Ask);
        let u = signed("Totally Legit Software Ltd");
        assert_eq!(auto_verdict(&inputs(Category::UserSpace, &u, Mode::Balanced)).out, Access::Ask);
        assert_eq!(auto_verdict(&inputs(Category::UserSpace, &u, Mode::Relaxed)).out, Access::Allow);
    }

    #[test]
    fn learned_publisher_is_trusted_even_in_strict() {
        let s = signed("Tiny Indie Dev");
        let learned = vec!["tiny indie dev".to_string()];
        let i = Inputs { category: Category::UserSpace, signature: &s, mode: Mode::Strict, learned: &learned, lan_discovery: true };
        assert_eq!(auto_verdict(&i).out, Access::Allow);
    }

    #[test]
    fn installed_unsigned_only_asks_in_strict() {
        let s = Signature::Unsigned;
        assert_eq!(auto_verdict(&inputs(Category::Installed, &s, Mode::Balanced)).out, Access::Allow);
        assert_eq!(auto_verdict(&inputs(Category::Installed, &s, Mode::Strict)).out, Access::Ask);
    }

    #[test]
    fn inbound_defaults() {
        let s = Signature::Unknown;
        assert_eq!(auto_verdict(&inputs(Category::System, &s, Mode::Balanced)).inn, Access::Lan);
        assert_eq!(auto_verdict(&inputs(Category::System, &s, Mode::Strict)).inn, Access::Block);
        assert_eq!(auto_verdict(&inputs(Category::Installed, &s, Mode::Balanced)).inn, Access::Block);
    }

    #[test]
    fn invalid_signature_is_high_risk() {
        let s = Signature::Invalid { code: 0x80096010 };
        assert_eq!(auto_verdict(&inputs(Category::UserSpace, &s, Mode::Relaxed)).out, Access::Ask);
    }
}
