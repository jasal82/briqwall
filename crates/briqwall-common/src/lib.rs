//! Shared data model and IPC protocol between the Briqwall service and the UI.

pub mod ipc;
pub mod model;
pub mod util;

pub use model::*;

/// Two backslashes, dot, backslash, "pipe", backslash, name. Written with hex
/// escapes so the leading double backslash cannot get lost.
pub const PIPE_NAME: &str = "\x5c\x5c.\x5cpipe\x5cbriqwall-control";
pub const SERVICE_NAME: &str = "briqwall";
pub const SERVICE_DISPLAY_NAME: &str = "Briqwall Firewall";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn pipe_name_has_unc_prefix() {
        assert!(super::PIPE_NAME.starts_with(&"\x5c".repeat(2)));
        assert!(super::PIPE_NAME.ends_with("pipe\x5cbriqwall-control"));
    }

    /// State files of older versions stored German location names.
    #[test]
    fn legacy_location_names_still_parse() {
        use super::Location;
        for (old, new) in [
            ("\"Temp-Ordner\"", Location::Temp),
            ("\"Programme\"", Location::ProgramFiles),
            ("\"Öffentlicher Ordner\"", Location::Public),
            ("\"Benutzerprofil\"", Location::UserProfile),
            ("\"Wechseldatenträger\"", Location::Removable),
            ("\"Downloads\"", Location::Downloads),
        ] {
            assert_eq!(serde_json::from_str::<Location>(old).unwrap(), new);
        }
        // New format round-trips.
        assert_eq!(serde_json::to_string(&Location::Temp).unwrap(), "\"Temp\"");
    }
}
