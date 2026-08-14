//! PGP identity management (v7.6 — Phase 2.1)
//!
//! Uses Ed25519 keys (from identity.rs) for trust chain operations.
//! The "PGP" naming is kept for the user-facing command interface,
//! but internally trust is built on Ed25519 signatures — simpler,
//! already audited, and zero additional dependencies.
//!
//! Full OpenPGP support can be added later as a feature flag.

pub mod web_of_trust;

use crate::identity::Identity;
use serde::{Deserialize, Serialize};

/// Public identity that can be shared and signed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpIdentity {
    /// User ID / nickname
    pub user_id: String,
    /// Ed25519 public key hex (32 bytes = 64 hex chars)
    pub public_key_hex: String,
    /// SHA-256 fingerprint of the public key (formatted)
    pub fingerprint: String,
    /// Creation timestamp (Unix epoch seconds)
    pub created: u64,
}

impl PgpIdentity {
    /// Create from an existing Identity
    pub fn from_identity(id: &Identity) -> Self {
        Self::from_parts(
            if id.uid.is_empty() {
                "anonymous"
            } else {
                &id.uid
            },
            id.public_hex(),
        )
    }

    /// Create from a (user_id, public_key_hex) pair — the import path for
    /// friends' keys (we never hold their secret keys).
    pub fn from_parts(user_id: &str, public_key_hex: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            public_key_hex: public_key_hex.to_string(),
            fingerprint: crate::identity::fingerprint_of_public_hex(public_key_hex),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Format fingerprint for human display: "A1B2 C3D4 E5F6 ..."
    pub fn formatted_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    /// Short fingerprint: first 8 ... last 8
    pub fn fingerprint_short(&self) -> String {
        if self.public_key_hex.len() <= 16 {
            self.public_key_hex.clone()
        } else {
            format!(
                "{}...{}",
                &self.public_key_hex[..8],
                &self.public_key_hex[self.public_key_hex.len() - 8..]
            )
        }
    }

    /// Export as a shareable string (JSON with key material)
    pub fn export(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Import from a shareable string
    pub fn import(data: &str) -> Result<Self, String> {
        serde_json::from_str(data).map_err(|e| format!("Invalid identity data: {}", e))
    }
}

/// Trust level in the Web of Trust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    Never = -1,
    Unknown = 0,
    Marginal = 1,
    Full = 2,
    Ultimate = 3,
}

impl TrustLevel {
    pub fn from_i32(v: i32) -> Self {
        match v {
            -1 => TrustLevel::Never,
            0 => TrustLevel::Unknown,
            1 => TrustLevel::Marginal,
            2 => TrustLevel::Full,
            3 => TrustLevel::Ultimate,
            _ => TrustLevel::Unknown,
        }
    }

    pub fn to_i32(self) -> i32 {
        self as i32
    }

    /// Map to DC-Net permission level:
    ///   Never/Unknown = 0 (cannot participate)
    ///   Marginal = 1 (can speak)
    ///   Full = 2 (speak + relay)
    ///   Ultimate = 3 (admin/leader)
    pub fn to_dcnet_trust(self) -> u8 {
        match self {
            TrustLevel::Never | TrustLevel::Unknown => 0,
            TrustLevel::Marginal => 1,
            TrustLevel::Full => 2,
            TrustLevel::Ultimate => 3,
        }
    }

    /// Can this trust level participate in DC-Net rounds?
    pub fn can_speak(self) -> bool {
        self >= TrustLevel::Marginal
    }

    /// Can this trust level be a network admin?
    pub fn can_admin(self) -> bool {
        self >= TrustLevel::Ultimate
    }

    /// Can this trust level relay messages?
    pub fn can_relay(self) -> bool {
        self >= TrustLevel::Full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Ultimate > TrustLevel::Full);
        assert!(TrustLevel::Full > TrustLevel::Marginal);
        assert!(TrustLevel::Marginal > TrustLevel::Unknown);
        assert!(TrustLevel::Unknown > TrustLevel::Never);
    }

    #[test]
    fn test_trust_to_dcnet() {
        assert_eq!(TrustLevel::Never.to_dcnet_trust(), 0);
        assert_eq!(TrustLevel::Unknown.to_dcnet_trust(), 0);
        assert_eq!(TrustLevel::Marginal.to_dcnet_trust(), 1);
        assert_eq!(TrustLevel::Full.to_dcnet_trust(), 2);
        assert_eq!(TrustLevel::Ultimate.to_dcnet_trust(), 3);
    }

    #[test]
    fn test_can_speak() {
        assert!(!TrustLevel::Never.can_speak());
        assert!(!TrustLevel::Unknown.can_speak());
        assert!(TrustLevel::Marginal.can_speak());
        assert!(TrustLevel::Full.can_speak());
        assert!(TrustLevel::Ultimate.can_speak());
    }

    #[test]
    fn test_can_admin() {
        assert!(!TrustLevel::Full.can_admin());
        assert!(TrustLevel::Ultimate.can_admin());
    }

    #[test]
    fn test_identity_export_import() {
        let id = Identity::generate("alice");
        let pgi = PgpIdentity::from_identity(&id);
        let exported = pgi.export();
        let imported = PgpIdentity::import(&exported).unwrap();
        assert_eq!(pgi.public_key_hex, imported.public_key_hex);
        assert_eq!(pgi.fingerprint, imported.fingerprint);
    }

    #[test]
    fn test_fingerprint_display() {
        let id = Identity::generate("bob");
        let pgi = PgpIdentity::from_identity(&id);
        assert!(!pgi.formatted_fingerprint().is_empty());
        assert!(pgi.fingerprint_short().contains("...") || pgi.public_key_hex.len() <= 16);
    }

    #[test]
    fn test_from_parts_matches_identity() {
        // Import path (public key only) must produce the same fingerprint
        // as the full Identity does.
        let id = Identity::generate("carol");
        let from_id = PgpIdentity::from_identity(&id);
        let from_parts = PgpIdentity::from_parts("carol", id.public_hex());
        assert_eq!(from_id.fingerprint, from_parts.fingerprint);
        assert_eq!(from_id.public_key_hex, from_parts.public_key_hex);
        assert_eq!(from_parts.user_id, "carol");
    }
}
