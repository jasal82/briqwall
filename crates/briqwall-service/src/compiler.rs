//! Translates the high-level policy into concrete WFP filters.
//!
//! Weight layout inside the Briqwall sublayer (highest wins):
//!   15  loopback + DHCP (always permitted, even in lockdown)
//!   14  lockdown block-all
//!   13  essential ICMP (path MTU discovery, IPv6 neighbor discovery)
//!   12  explicit per-app block
//!   10  per-app permit
//!    0  default block ("ask" apps fall through to here)
//!
//! A block in *any* WFP sublayer wins over permits in other sublayers, so Briqwall
//! adds protection on top of the Windows Firewall but can never weaken it.

use crate::wfp::{Cond, FilterSpec, LAYER_IN_V4, LAYER_IN_V6, LAYER_OUT_V4, LAYER_OUT_V6};
use windows::core::GUID;
use briqwall_common::{Access, Direction, Mode};

const W_ALWAYS: u64 = 15;
const W_LOCKDOWN: u64 = 14;
const W_ESSENTIAL: u64 = 13;
const W_APP_BLOCK: u64 = 12;
const W_APP_PERMIT: u64 = 10;
const W_DEFAULT: u64 = 0;

/// Network category Windows assigned to the interface a connection uses
/// (NL_INTERFACE_NETWORK_CATEGORY_STATE): 1 public, 2 private, 3 domain.
const PROFILE_PRIVATE: u32 = 2;
const PROFILE_DOMAIN: u32 = 3;

const PROTO_ICMP: u8 = 1;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

#[derive(Clone, Debug, PartialEq)]
pub enum Purpose {
    DefaultBlock(Direction),
    Lockdown(Direction),
    AppBlock(String, Direction),
    Other,
}

pub type Compiled = Vec<(FilterSpec, Purpose)>;

fn spec(name: &str, layer: GUID, weight: u64, permit: bool, conds: Vec<Cond>) -> FilterSpec {
    FilterSpec { name: format!("Briqwall: {name}"), layer, weight, permit, conds }
}

/// Private / link-local / multicast ranges considered "local network".
pub fn lan_v4() -> Vec<Cond> {
    let r = |a: [u8; 4], bits: u32| Cond::RemoteV4 {
        addr: u32::from_be_bytes(a),
        mask: if bits == 0 { 0 } else { u32::MAX << (32 - bits) },
    };
    vec![
        r([10, 0, 0, 0], 8),
        r([172, 16, 0, 0], 12),
        r([192, 168, 0, 0], 16),
        r([169, 254, 0, 0], 16),
        r([224, 0, 0, 0], 4),
        r([255, 255, 255, 255], 32),
    ]
}

pub fn lan_v6() -> Vec<Cond> {
    let mut fe80 = [0u8; 16];
    fe80[0] = 0xfe;
    fe80[1] = 0x80;
    let mut fc00 = [0u8; 16];
    fc00[0] = 0xfc;
    let mut ff00 = [0u8; 16];
    ff00[0] = 0xff;
    vec![
        Cond::RemoteV6 { addr: fe80, prefix: 10 },
        Cond::RemoteV6 { addr: fc00, prefix: 7 },
        Cond::RemoteV6 { addr: ff00, prefix: 8 },
    ]
}

/// Filters that do not depend on individual apps. `dhcp_client` is the app id
/// of the process hosting the Windows DHCP client (svchost.exe); without it
/// the DHCP permits are bound to the client ports only.
pub fn base_filters(mode: Mode, dhcp_client: Option<&[u8]>) -> Compiled {
    let mut out = Vec::new();
    if mode == Mode::Off {
        return out;
    }
    let o = Purpose::Other;
    // These permits outrank everything, lockdown included, so they must match
    // the DHCP client and nothing else: its own ports on both ends (the same
    // shape as Windows' built-in DHCP rules). "Any program to port 67" would
    // be a way out for every blocked app.
    let dhcp = |local: u16, remote: u16| {
        let mut c = vec![Cond::Protocol(PROTO_UDP), Cond::LocalPort(local), Cond::RemotePort(remote)];
        c.extend(dhcp_client.map(|id| Cond::AppId(id.to_vec())));
        c
    };

    // Loopback is never filtered.
    for (layer, n) in [
        (LAYER_OUT_V4, "Loopback aus v4"),
        (LAYER_OUT_V6, "Loopback aus v6"),
        (LAYER_IN_V4, "Loopback ein v4"),
        (LAYER_IN_V6, "Loopback ein v6"),
    ] {
        out.push((spec(n, layer, W_ALWAYS, true, vec![Cond::Loopback]), o.clone()));
    }

    // DHCP so the machine keeps its address even in lockdown.
    out.push((spec("DHCP aus v4", LAYER_OUT_V4, W_ALWAYS, true, dhcp(68, 67)), o.clone()));
    out.push((spec("DHCP ein v4", LAYER_IN_V4, W_ALWAYS, true, dhcp(68, 67)), o.clone()));
    out.push((spec("DHCPv6 aus", LAYER_OUT_V6, W_ALWAYS, true, dhcp(546, 547)), o.clone()));
    out.push((spec("DHCPv6 ein", LAYER_IN_V6, W_ALWAYS, true, dhcp(546, 547)), o.clone()));

    if mode == Mode::Lockdown {
        for (layer, dir, n) in [
            (LAYER_OUT_V4, Direction::Out, "Sperre aus v4"),
            (LAYER_OUT_V6, Direction::Out, "Sperre aus v6"),
            (LAYER_IN_V4, Direction::In, "Sperre ein v4"),
            (LAYER_IN_V6, Direction::In, "Sperre ein v6"),
        ] {
            out.push((spec(n, layer, W_LOCKDOWN, false, vec![]), Purpose::Lockdown(dir)));
        }
        return out;
    }

    // Essential inbound ICMP: echo reply, unreachable / packet-too-big, time exceeded.
    // Echo *requests* stay blocked (stealth).
    for icmp_type in [0u16, 3, 11] {
        out.push((
            spec(&format!("ICMP Typ {icmp_type}"), LAYER_IN_V4, W_ESSENTIAL, true, vec![
                Cond::Protocol(PROTO_ICMP),
                Cond::LocalPort(icmp_type),
            ]),
            o.clone(),
        ));
    }
    // ICMPv6 carries neighbor discovery / router advertisements: IPv6 breaks without it.
    for icmp_type in [1u16, 2, 3, 4, 129, 133, 134, 135, 136] {
        out.push((
            spec(&format!("ICMPv6 Typ {icmp_type}"), LAYER_IN_V6, W_ESSENTIAL, true, vec![
                Cond::Protocol(PROTO_ICMPV6),
                Cond::LocalPort(icmp_type),
            ]),
            o.clone(),
        ));
    }

    // Default deny. Outbound always; inbound only where Briqwall owns inbound policy.
    out.push((
        spec("Standard: aus v4 blockieren", LAYER_OUT_V4, W_DEFAULT, false, vec![]),
        Purpose::DefaultBlock(Direction::Out),
    ));
    out.push((
        spec("Standard: aus v6 blockieren", LAYER_OUT_V6, W_DEFAULT, false, vec![]),
        Purpose::DefaultBlock(Direction::Out),
    ));
    if mode != Mode::Relaxed {
        out.push((
            spec("Standard: ein v4 blockieren", LAYER_IN_V4, W_DEFAULT, false, vec![]),
            Purpose::DefaultBlock(Direction::In),
        ));
        out.push((
            spec("Standard: ein v6 blockieren", LAYER_IN_V6, W_DEFAULT, false, vec![]),
            Purpose::DefaultBlock(Direction::In),
        ));
    }
    out
}

/// Per-direction input for [`app_filters`].
#[derive(Clone, Copy, Debug)]
pub struct DirPolicy {
    pub access: Access,
    /// Comes from an explicit user rule (only then do blocks get their own
    /// filter; automatic blocks simply fall through to the default block).
    pub explicit: bool,
}

/// Filters for one app.
pub fn app_filters(
    key: &str,
    name: &str,
    app_id: &[u8],
    out_policy: DirPolicy,
    in_policy: DirPolicy,
    mode: Mode,
    network_trusted: bool,
    bind_profile: bool,
) -> Compiled {
    let mut v = Vec::new();
    if matches!(mode, Mode::Off | Mode::Lockdown) {
        return v;
    }
    let app = || Cond::AppId(app_id.to_vec());

    let mut emit = |dir: Direction, p: DirPolicy| {
        let access = p.access;
        let (l4, l6) = match dir {
            Direction::Out => (LAYER_OUT_V4, LAYER_OUT_V6),
            Direction::In => (LAYER_IN_V4, LAYER_IN_V6),
        };
        let d = if dir == Direction::Out { "aus" } else { "ein" };
        match access {
            Access::Allow => {
                v.push((spec(&format!("{name} {d} v4"), l4, W_APP_PERMIT, true, vec![app()]), Purpose::Other));
                v.push((spec(&format!("{name} {d} v6"), l6, W_APP_PERMIT, true, vec![app()]), Purpose::Other));
            }
            Access::Lan => {
                // Inbound LAN access is only granted on trusted networks
                // (public hotspot = nobody gets in).
                if dir == Direction::In && !network_trusted {
                    return;
                }
                let mut c4 = vec![app()];
                c4.extend(lan_v4());
                let mut c6 = vec![app()];
                c6.extend(lan_v6());
                // Filters outlive the service (crash, stop, the minutes
                // before it starts after boot). A permit for the home network
                // must not still be open when the laptop wakes up in a café:
                // it only matches while Windows itself has the connection
                // down as private or domain.
                if dir == Direction::In && bind_profile {
                    for c in [&mut c4, &mut c6] {
                        c.push(Cond::Profile(PROFILE_PRIVATE));
                        c.push(Cond::Profile(PROFILE_DOMAIN));
                    }
                }
                v.push((spec(&format!("{name} {d} LAN v4"), l4, W_APP_PERMIT, true, c4), Purpose::Other));
                v.push((spec(&format!("{name} {d} LAN v6"), l6, W_APP_PERMIT, true, c6), Purpose::Other));
            }
            Access::Block => {
                if !p.explicit {
                    return;
                }
                let p = Purpose::AppBlock(key.to_string(), dir);
                v.push((spec(&format!("{name} {d} blockiert v4"), l4, W_APP_BLOCK, false, vec![app()]), p.clone()));
                v.push((spec(&format!("{name} {d} blockiert v6"), l6, W_APP_BLOCK, false, vec![app()]), p));
            }
            // Falls through to the default block and generates an inbox entry.
            Access::Ask => {}
        }
    };
    emit(Direction::Out, out_policy);
    // In relaxed mode inbound is left to the Windows Firewall unless the user
    // set an explicit inbound rule.
    if mode != Mode::Relaxed || in_policy.explicit {
        emit(Direction::In, in_policy);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auto(a: Access) -> DirPolicy {
        DirPolicy { access: a, explicit: false }
    }
    fn rule(a: Access) -> DirPolicy {
        DirPolicy { access: a, explicit: true }
    }

    #[test]
    fn off_has_no_filters() {
        assert!(base_filters(Mode::Off, None).is_empty());
        assert!(app_filters("k", "n", &[1, 2], rule(Access::Allow), rule(Access::Allow), Mode::Off, true, false).is_empty());
    }

    #[test]
    fn lockdown_blocks_everything_but_keeps_loopback() {
        let f = base_filters(Mode::Lockdown, None);
        assert_eq!(f.iter().filter(|(_, p)| matches!(p, Purpose::Lockdown(_))).count(), 4);
        assert!(f.iter().any(|(s, _)| s.permit && matches!(s.conds[..], [Cond::Loopback])));
        assert!(!f.iter().any(|(_, p)| matches!(p, Purpose::DefaultBlock(_))));
    }

    /// The DHCP permits outrank lockdown. They must not double as a way out
    /// for other programs ("UDP to port 67 on any host").
    #[test]
    fn dhcp_permits_match_only_the_dhcp_client() {
        let has = |s: &FilterSpec, want: fn(&Cond) -> bool| s.conds.iter().any(want);
        for mode in [Mode::Relaxed, Mode::Balanced, Mode::Strict, Mode::Lockdown] {
            let f = base_filters(mode, Some(&[7, 7]));
            let dhcp: Vec<&FilterSpec> = f.iter().map(|(s, _)| s).filter(|s| s.name.contains("DHCP")).collect();
            assert_eq!(dhcp.len(), 4, "{mode:?}");
            for s in dhcp {
                assert!(s.permit && s.weight == W_ALWAYS);
                assert!(has(s, |c| matches!(c, Cond::Protocol(PROTO_UDP))), "{}", s.name);
                assert!(has(s, |c| matches!(c, Cond::LocalPort(68 | 546))), "{} needs the client port", s.name);
                assert!(has(s, |c| matches!(c, Cond::RemotePort(67 | 547))), "{}", s.name);
                assert!(has(s, |c| matches!(c, Cond::AppId(id) if id == &[7, 7])), "{} needs the app", s.name);
            }
            // Every permit above the lockdown block is narrowed by a condition.
            assert!(f.iter().all(|(s, _)| !s.permit || !s.conds.is_empty()));
        }
        // Without a resolvable svchost the ports still narrow the permit.
        let f = base_filters(Mode::Lockdown, None);
        assert!(f.iter().filter(|(s, _)| s.name.contains("DHCP")).all(|(s, _)| s.conds.len() == 3));
    }

    #[test]
    fn relaxed_leaves_inbound_to_windows() {
        let f = base_filters(Mode::Relaxed, None);
        assert!(!f.iter().any(|(_, p)| *p == Purpose::DefaultBlock(Direction::In)));
        let b = base_filters(Mode::Balanced, None);
        assert!(b.iter().any(|(_, p)| *p == Purpose::DefaultBlock(Direction::In)));
    }

    #[test]
    fn inbound_lan_only_on_trusted_network() {
        let trusted = app_filters("k", "n", &[1], auto(Access::Ask), auto(Access::Lan), Mode::Balanced, true, false);
        let public = app_filters("k", "n", &[1], auto(Access::Ask), auto(Access::Lan), Mode::Balanced, false, false);
        assert_eq!(trusted.len(), 2);
        assert!(public.is_empty());
    }

    /// Inbound LAN permits can be tied to what Windows says about the network,
    /// so they close by themselves when the service is not there to do it.
    #[test]
    fn inbound_lan_can_follow_the_windows_profile() {
        let profiles = |f: &Compiled| -> Vec<Vec<u32>> {
            f.iter().map(|(s, _)| s.conds.iter().filter_map(|c| if let Cond::Profile(p) = c { Some(*p) } else { None }).collect()).collect()
        };
        let bound = app_filters("k", "n", &[1], auto(Access::Ask), auto(Access::Lan), Mode::Balanced, true, true);
        assert_eq!(profiles(&bound), vec![vec![2, 3], vec![2, 3]], "private or domain, v4 and v6");
        let unbound = app_filters("k", "n", &[1], auto(Access::Ask), auto(Access::Lan), Mode::Balanced, true, false);
        assert_eq!(profiles(&unbound), vec![Vec::<u32>::new(), Vec::new()]);
        // Outbound LAN access and full inbound access are not affected.
        let out = app_filters("k", "n", &[1], rule(Access::Lan), rule(Access::Allow), Mode::Balanced, true, true);
        assert!(profiles(&out).iter().all(|p| p.is_empty()));
        // Still nothing at all on a network Briqwall does not trust.
        assert!(app_filters("k", "n", &[1], auto(Access::Ask), auto(Access::Lan), Mode::Balanced, false, true).is_empty());
    }

    #[test]
    fn ask_produces_no_permit() {
        let f = app_filters("k", "n", &[1], auto(Access::Ask), auto(Access::Block), Mode::Strict, true, false);
        assert!(f.is_empty(), "automatic decisions rely on the default block");
        let f = app_filters("k", "n", &[1], rule(Access::Block), auto(Access::Block), Mode::Strict, true, false);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|(s, p)| !s.permit && matches!(p, Purpose::AppBlock(_, Direction::Out))));
    }

    #[test]
    fn lan_masks() {
        let v4 = lan_v4();
        assert!(matches!(v4[1], Cond::RemoteV4 { addr: 0xAC10_0000, mask: 0xFFF0_0000 }));
        assert!(matches!(v4[5], Cond::RemoteV4 { addr: 0xFFFF_FFFF, mask: 0xFFFF_FFFF }));
    }
}
