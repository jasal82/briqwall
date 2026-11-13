//! The automatic trust decision: the heart of "easy but safe".
//!
//! Instead of asking the user about ports and protocols, Briqwall asks one question
//! about every executable: *could an unprivileged process have put this file here?*
//! Software that only an administrator could have installed is treated very
//! differently from a binary that appeared in Downloads or AppData. Code signing,
//! known publishers and a list of frequently abused Windows tools refine this.

use briqwall_common::{Access, AppInfo, Category, Location, Mode, Reason, Risk, RuleAccess, Signature, UserRule};

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
/// are trusted automatically in balanced mode. An entry matches the whole
/// name on the certificate, optionally followed by a legal form ("Valve" also
/// covers "Valve Corp."), see [`is_known_publisher`].
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
    "GitHub",
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
    "OpenAI OpCo",
    "Obsidian",
    "Element",
    "1Password",
    "Bitwarden",
    "AgileBits",
    "TeamViewer Germany",
    "Rustlang",
];

/// Legal forms that may follow a publisher name (dots and commas removed).
const LEGAL_FORMS: &[&str] = &[
    "inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation", "co", "co ltd", "gmbh", "ag", "ab", "as", "sa",
    "bv", "nv", "oy", "sro", "srl", "sas", "se", "aps", "kg", "plc", "pbc", "lp", "llp", "pty ltd", "kk",
];

/// Lower case, without dots and commas, single spaces.
fn normalize_publisher(p: &str) -> String {
    let lower = p.to_lowercase().replace(['.', ','], "");
    lower.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn is_lolbin(file_name_lower: &str) -> bool {
    LOLBINS.contains(&file_name_lower)
}

/// Is this certificate name on the built-in list? The name must be the entry
/// itself, give or take a legal form. A mere common beginning does not count:
/// "Valve" must not vouch for "Valve Industries Ltd" or "Valvexyz".
pub fn is_known_publisher(p: &str) -> bool {
    let p = normalize_publisher(p);
    if p.is_empty() {
        return false;
    }
    KNOWN_PUBLISHERS.iter().any(|k| match p.strip_prefix(&normalize_publisher(k)) {
        Some("") => true,
        Some(rest) => rest.strip_prefix(' ').is_some_and(|form| LEGAL_FORMS.contains(&form)),
        None => false,
    })
}

/// A valid signature whose certificate carries no name identifies nobody; an
/// empty entry must never match (or be learned).
pub fn is_learned_publisher(p: &str, learned: &[String]) -> bool {
    !p.trim().is_empty() && learned.iter().any(|l| l.eq_ignore_ascii_case(p))
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
    /// Only SYSTEM/Administrators can modify the file or its folder.
    pub protected: bool,
    pub location: Option<Location>,
}

pub fn auto_verdict(i: &Inputs) -> Verdict {
    let publisher = i.signature.publisher();
    let learned = publisher.is_some_and(|p| is_learned_publisher(p, i.learned));
    let builtin = publisher.is_some_and(is_known_publisher);
    let relaxed = i.mode == Mode::Relaxed;
    let strict = i.mode == Mode::Strict;
    let drop_zone = i.location.is_some_and(Location::is_risky);

    let (out, reason): (Access, Reason) = match i.category {
        Category::Pseudo => (Access::Allow, Reason::Kernel),
        Category::System => (Access::Allow, Reason::System),
        // A copy of such a tool in a user folder is never waved through: the
        // name on disk is the attacker's choice and a DLL can sit next to it.
        Category::Lolbin if relaxed && i.protected => (Access::Allow, Reason::ToolRelaxed),
        Category::Lolbin => (Access::Ask, Reason::Tool),
        Category::Installed => match publisher {
            Some(p) => (Access::Allow, Reason::InstalledSigned(p.to_string())),
            None if strict => (Access::Ask, Reason::InstalledUnsignedStrict),
            None => (Access::Allow, Reason::Installed),
        },
        Category::UserSpace => match i.signature {
            Signature::Invalid { .. } => (Access::Ask, Reason::InvalidSignature),
            // A catalog signature says "this file belongs to Windows". Outside
            // a protected folder that is a copied system file, whatever it is
            // called now – no publisher list makes it trustworthy.
            Signature::Valid { catalog: true, .. } => (Access::Ask, Reason::MisplacedSystemFile),
            Signature::Valid { publisher, .. } if learned => (Access::Allow, Reason::LearnedPublisher(publisher.clone())),
            Signature::Valid { publisher, .. } if builtin && !strict && (relaxed || !drop_zone) => {
                (Access::Allow, Reason::KnownPublisher(publisher.clone()))
            }
            Signature::Valid { publisher, .. } if relaxed => (Access::Allow, Reason::SignedRelaxed(publisher.clone())),
            Signature::Valid { publisher, .. } if builtin && drop_zone && !strict => {
                (Access::Ask, Reason::RiskyLocation(publisher.clone()))
            }
            Signature::Valid { publisher, .. } => (Access::Ask, Reason::UnknownPublisher(publisher.clone())),
            // Not opened at all (network share): "unsigned" would be a guess.
            _ if i.location == Some(Location::Network) => (Access::Ask, Reason::Unverified),
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
        Category::Lolbin if app.protected => Risk::Medium,
        Category::Lolbin => Risk::High,
        Category::UserSpace => {
            let drop_zone = app.location_hint.is_some_and(|l| l.is_risky());
            match &app.signature {
                Signature::Valid { catalog: true, .. } => Risk::High,
                Signature::Valid { publisher, .. } if is_learned_publisher(publisher, learned) => Risk::Low,
                Signature::Valid { publisher, .. } if is_known_publisher(publisher) && !drop_zone => Risk::Low,
                Signature::Valid { .. } => Risk::Medium,
                _ if drop_zone => Risk::High,
                _ => Risk::Medium,
            }
        }
    }
}

/// Does the rule give the app access in either direction?
pub fn grants(rule: Option<&UserRule>) -> bool {
    rule.is_some_and(|r| grant_rank(r.outbound) > 0 || grant_rank(r.inbound) > 0)
}

/// How much an explicit rule grants on its own (ignoring the automatic verdict).
fn grant_rank(r: RuleAccess) -> u8 {
    match r {
        RuleAccess::Allow => 2,
        RuleAccess::Lan => 1,
        RuleAccess::Auto | RuleAccess::Block => 0,
    }
}

/// Does going from `current` to `cand` (same app, new rule, both evaluated)
/// give the app more than it has now? Such a change needs proof that a human
/// agreed. Comparing what is effectively allowed is not enough:
///
/// * a temporary permission made permanent allows nothing new *today*,
/// * neither does an explicit "allow" on top of an automatic one – but it
///   would outlive a stricter mode or a removed publisher.
pub fn loosens(current: &AppInfo, cand: &AppInfo) -> bool {
    if cand.effective_out.rank() > current.effective_out.rank()
        || cand.effective_in.rank() > current.effective_in.rank()
        || (current.tampered && cand.effective_out.rank() > 0)
    {
        return true;
    }
    let grants = |r: Option<&UserRule>| r.map_or((0, 0), |r| (grant_rank(r.outbound), grant_rank(r.inbound)));
    let (old_out, old_in) = grants(current.rule.as_ref());
    let (new_out, new_in) = grants(cand.rule.as_ref());
    if new_out > old_out || new_in > old_in {
        return true;
    }
    if new_out > 0 || new_in > 0 {
        let old_expiry = current.rule.as_ref().and_then(|r| r.expires);
        let new_expiry = cand.rule.as_ref().and_then(|r| r.expires);
        match (old_expiry, new_expiry) {
            (Some(_), None) => return true,
            (Some(old), Some(new)) if new > old => return true,
            _ => {}
        }
    }
    false
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
        let protected = cat != Category::UserSpace;
        Inputs { category: cat, signature: sig, mode, learned: &[], lan_discovery: true, protected, location: None }
    }

    /// An app as the core would hold it: facts, rule, evaluated verdict.
    fn app(cat: Category, sig: Signature, auto_out: Access, rule: Option<UserRule>) -> AppInfo {
        let mut a = AppInfo {
            key: "k".into(),
            path: "k".into(),
            name: "n".into(),
            signature: sig,
            category: cat,
            protected: cat != Category::UserSpace,
            location_hint: None,
            first_seen: 0,
            last_seen: 0,
            last_blocked: None,
            blocked_count: 0,
            inbound_blocked_count: 0,
            last_remote: None,
            rule,
            auto_out,
            auto_in: Access::Block,
            reason: Reason::Unknown,
            effective_out: Access::Ask,
            effective_in: Access::Block,
            risk: Risk::Medium,
            pending: false,
            snoozed_until: None,
            tampered: false,
            identity: None,
            file_stamp: None,
            raw_app_id: None,
            origins: Vec::new(),
            last_host: None,
            last_host_verified: false,
        };
        (a.effective_out, a.effective_in) = effective(&a);
        a
    }
    fn rule(outbound: RuleAccess, inbound: RuleAccess, expires: Option<u64>) -> Option<UserRule> {
        Some(UserRule { outbound, inbound, expires, created: 1 })
    }
    /// Does replacing the rule of `from` by `to` count as loosening?
    fn change(auto_out: Access, from: Option<UserRule>, to: Option<UserRule>) -> bool {
        let current = app(Category::UserSpace, Signature::Unsigned, auto_out, from);
        let cand = app(Category::UserSpace, Signature::Unsigned, auto_out, to);
        loosens(&current, &cand)
    }

    #[test]
    fn publishers_match_by_whole_name_not_by_beginning() {
        // Names as they appear on real certificates.
        for real in [
            "Microsoft Corporation",
            "Google LLC",
            "Valve",
            "Valve Corp.",
            "Epic Games Inc.",
            "Anthropic, PBC",
            "OpenAI OpCo, LLC",
            "TeamViewer Germany GmbH",
            "Logitech Inc",
            "Adobe Systems, Incorporated",
            "Adobe Systems Incorporated",
            "Advanced Micro Devices",
            "GitHub",
            "GitHub, Inc.",
            "OpenJS Foundation",
            "mozilla corporation",
        ] {
            assert!(is_known_publisher(real), "{real}");
        }
        // Somebody else whose name merely starts the same way.
        for other in [
            "Valvexyz Ltd",
            "Valve Industries Ltd",
            "Elemental Software Ltd",
            "Obsidian Entertainment, Inc.",
            "OpenAI Tools LLC",
            "Microsoft Corporation Support Services",
            "Microsoft Windows Publisher",
            "Signal Messenger Tools",
            "",
            "Inc.",
        ] {
            assert!(!is_known_publisher(other), "{other}");
        }
    }

    /// A program on a network share is never opened, so nothing about it is
    /// known – it asks in every mode and says why.
    #[test]
    fn programs_on_network_shares_always_ask() {
        for mode in [Mode::Relaxed, Mode::Balanced, Mode::Strict] {
            let mut i = inputs(Category::UserSpace, &Signature::Unknown, mode);
            i.location = Some(Location::Network);
            let v = auto_verdict(&i);
            assert_eq!((v.out, v.reason), (Access::Ask, Reason::Unverified), "{mode:?}");
        }
    }

    #[test]
    fn a_nameless_certificate_is_nobody() {
        let learned = vec![String::new(), "Tiny Indie Dev".to_string()];
        assert!(!is_learned_publisher("", &learned));
        assert!(!is_learned_publisher("  ", &learned));
        assert!(is_learned_publisher("tiny indie dev", &learned));
    }

    #[test]
    fn extending_a_temporary_permission_loosens() {
        use RuleAccess::*;
        let hour = rule(Allow, Auto, Some(1000));
        assert!(change(Access::Ask, hour.clone(), rule(Allow, Auto, None)), "1 hour → permanent");
        assert!(change(Access::Ask, hour.clone(), rule(Allow, Auto, Some(2000))), "later expiry");
        assert!(change(Access::Ask, hour.clone(), rule(Lan, Auto, None)), "less access, but for longer");
        assert!(!change(Access::Ask, hour.clone(), rule(Allow, Auto, Some(1000))), "same rule again");
        assert!(!change(Access::Ask, hour.clone(), rule(Allow, Auto, Some(500))), "shorter");
        assert!(!change(Access::Ask, hour, rule(Lan, Auto, Some(1000))), "less access, same time");
        assert!(!change(Access::Ask, rule(Allow, Auto, None), rule(Allow, Auto, Some(1000))), "permanent → temporary");
    }

    #[test]
    fn pinning_an_automatic_permission_loosens() {
        use RuleAccess::*;
        // Allowed automatically today; an explicit rule would survive a stricter mode.
        assert!(change(Access::Allow, None, rule(Allow, Auto, None)));
        assert!(change(Access::Allow, None, rule(Auto, Lan, None)));
        assert!(change(Access::Allow, rule(Block, Auto, None), rule(Allow, Auto, None)));
        assert!(change(Access::Allow, rule(Lan, Auto, None), rule(Allow, Auto, None)));
    }

    #[test]
    fn tightening_never_needs_confirmation() {
        use RuleAccess::*;
        assert!(!change(Access::Allow, None, rule(Block, Auto, None)));
        assert!(!change(Access::Ask, None, rule(Block, Block, None)));
        assert!(!change(Access::Ask, rule(Allow, Lan, None), rule(Allow, Block, None)));
        assert!(!change(Access::Ask, rule(Allow, Auto, None), rule(Lan, Auto, None)));
        assert!(!change(Access::Ask, rule(Allow, Auto, None), None), "remove a permission");
        // A block with an end date may be made permanent.
        assert!(!change(Access::Ask, rule(Block, Auto, Some(1000)), rule(Block, Auto, None)));
        // Removing a block hands the app back to the automatic verdict.
        assert!(change(Access::Allow, rule(Block, Auto, None), None));
        assert!(!change(Access::Ask, rule(Block, Auto, None), None));
    }

    #[test]
    fn a_tampered_app_needs_a_fresh_confirmation() {
        use RuleAccess::*;
        let mut current = app(Category::UserSpace, Signature::Unsigned, Access::Ask, rule(Allow, Auto, None));
        current.tampered = true;
        (current.effective_out, current.effective_in) = effective(&current);
        let cand = app(Category::UserSpace, Signature::Unsigned, Access::Ask, rule(Allow, Auto, None));
        assert!(loosens(&current, &cand));
    }

    #[test]
    fn copied_system_files_are_never_trusted_by_publisher() {
        // powershell.exe copied to a user folder keeps its catalog signature.
        let s = Signature::Valid { publisher: "Microsoft Windows".into(), catalog: true };
        let learned = vec!["Microsoft Windows".to_string()];
        for mode in [Mode::Relaxed, Mode::Balanced, Mode::Strict] {
            let i = Inputs {
                category: Category::UserSpace,
                signature: &s,
                mode,
                learned: &learned,
                lan_discovery: true,
                protected: false,
                location: Some(Location::AppData),
            };
            let v = auto_verdict(&i);
            assert_eq!((v.out, v.reason), (Access::Ask, Reason::MisplacedSystemFile), "{mode:?}");
        }
        let a = app(Category::UserSpace, s, Access::Ask, None);
        assert_eq!(risk(&a, &learned), Risk::High);
    }

    #[test]
    fn lolbin_copy_in_user_folder_always_asks() {
        let s = signed("Microsoft Corporation");
        let mut i = inputs(Category::Lolbin, &s, Mode::Relaxed);
        assert_eq!(auto_verdict(&i).out, Access::Allow, "the real tool is allowed in relaxed mode");
        i.protected = false;
        assert_eq!(auto_verdict(&i).out, Access::Ask);
        let mut a = app(Category::Lolbin, s, Access::Ask, None);
        assert_eq!(risk(&a, &[]), Risk::Medium);
        a.protected = false;
        assert_eq!(risk(&a, &[]), Risk::High);
    }

    #[test]
    fn known_publisher_in_a_drop_zone_asks() {
        let s = signed("Discord Inc.");
        let at = |location, mode| {
            let mut i = inputs(Category::UserSpace, &s, mode);
            i.location = Some(location);
            auto_verdict(&i)
        };
        assert_eq!(at(Location::AppData, Mode::Balanced).out, Access::Allow);
        for zone in [Location::Downloads, Location::Temp, Location::Desktop, Location::Public, Location::Removable] {
            let v = at(zone, Mode::Balanced);
            assert_eq!((v.out, v.reason), (Access::Ask, Reason::RiskyLocation("Discord Inc.".into())), "{zone:?}");
        }
        // Relaxed allows every valid signature, strict none from the built-in list.
        assert_eq!(at(Location::Downloads, Mode::Relaxed).out, Access::Allow);
        assert_eq!(at(Location::Downloads, Mode::Strict).reason, Reason::UnknownPublisher("Discord Inc.".into()));
        // A publisher the user trusted stays trusted wherever the file is.
        let learned = vec!["Discord Inc.".to_string()];
        let mut i = inputs(Category::UserSpace, &s, Mode::Balanced);
        i.location = Some(Location::Downloads);
        i.learned = &learned;
        assert_eq!(auto_verdict(&i).out, Access::Allow);

        let mut a = app(Category::UserSpace, s, Access::Ask, None);
        assert_eq!(risk(&a, &[]), Risk::Low);
        a.location_hint = Some(Location::Downloads);
        assert_eq!(risk(&a, &[]), Risk::Medium);
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
        let i = Inputs {
            category: Category::UserSpace,
            signature: &s,
            mode: Mode::Strict,
            learned: &learned,
            lan_discovery: true,
            protected: false,
            location: None,
        };
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
