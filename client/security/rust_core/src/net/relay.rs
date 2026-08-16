//! Multi-path relay routing (v7.2 M5, P4 security rewrite)
//!
//! If Alice can't reach Bob directly, Alice can send through Carol (mutual friend).
//! Carol relays AES-encrypted frames but cannot decrypt the content.
//! End-to-end encryption is preserved through the relay.
//!
//! P4 hardening:
//!   - every relay message is Ed25519-signed by its originator
//!     (from, to, nonce, timestamp, payload);
//!   - per-sender monotonic nonces defeat replay;
//!   - a timestamp window defeats expired-message injection;
//!   - a per-sender rate limit defeats amplification;
//!   - hops_left (not covered by the signature) defeats routing loops.

use crate::identity::hex_decode;
use crate::net::tcp::PeerMessage;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;

/// Domain separator for relay signatures.
const RELAY_SIG_DOMAIN: &[u8] = b"chrono-relay-v1";

/// Maximum relay hops (loop prevention bound).
pub const RELAY_MAX_HOPS: u8 = 8;

/// Accepted clock skew / freshness window in seconds.
pub const RELAY_MAX_AGE_SECS: u64 = 60;

/// Rate limit: max requests per sender per window.
pub const RELAY_RATE_WINDOW_SECS: u64 = 60;
pub const RELAY_MAX_PER_WINDOW: u32 = 60;

/// Anti-memory-DoS bounds for the relay verifier's tables. When a table
/// reaches this many entries it is cleared wholesale (coarse-grained
/// eviction) rather than letting a flood of fake identities grow it without
/// bound. `last_nonce` and `rate` are keyed by the verified identity key,
/// so they share MAX_RELAY_TRACKED; `key_pins` uses MAX_RELAY_PINS.
pub const MAX_RELAY_TRACKED: usize = 4096;
pub const MAX_RELAY_PINS: usize = 4096;

/// The exact bytes a relay signature covers. hops_left is deliberately
/// excluded so relays can decrement it without invalidating the signature.
pub fn relay_signature_message(
    from_uid: &str,
    to_uid: &str,
    nonce: u64,
    timestamp: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64 + from_uid.len() + to_uid.len() + payload.len() + 16);
    msg.extend_from_slice(RELAY_SIG_DOMAIN);
    msg.extend_from_slice(&(from_uid.len() as u32).to_be_bytes());
    msg.extend_from_slice(from_uid.as_bytes());
    msg.extend_from_slice(&(to_uid.len() as u32).to_be_bytes());
    msg.extend_from_slice(to_uid.as_bytes());
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    msg.extend_from_slice(payload);
    msg
}

/// Sign a relay message with the originator's identity key.
pub fn sign_relay(
    signing_key: &SigningKey,
    from_uid: &str,
    to_uid: &str,
    nonce: u64,
    timestamp: u64,
    payload: &[u8],
) -> Vec<u8> {
    signing_key
        .sign(&relay_signature_message(
            from_uid, to_uid, nonce, timestamp, payload,
        ))
        .to_vec()
}

/// Verify a relay signature (false on any parse failure).
pub fn verify_relay(
    vk: &VerifyingKey,
    from_uid: &str,
    to_uid: &str,
    nonce: u64,
    timestamp: u64,
    payload: &[u8],
    signature: &[u8],
) -> bool {
    match Signature::from_slice(signature) {
        Ok(sig) => vk
            .verify(
                &relay_signature_message(from_uid, to_uid, nonce, timestamp, payload),
                &sig,
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// Parse an identity public key hex into a VerifyingKey.
pub fn parse_verifying_key(key_hex: &str) -> Option<VerifyingKey> {
    let bytes = hex_decode(key_hex)?;
    let arr = <[u8; 32]>::try_from(bytes).ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Inbound hops guard: a relayed message must never present a `hops_left`
/// greater than the protocol maximum. Relays only decrement it, so a larger
/// value means the field was crafted (loop / sybil hardening).
pub fn valid_inbound_hops(hops_left: u8) -> bool {
    hops_left <= RELAY_MAX_HOPS
}

/// Relay path: source → relay → destination
#[derive(Debug, Clone)]
pub struct RelayPath {
    pub relay_uid: String,  // the mutual friend who relays
    pub target_uid: String, // the final destination
    pub active: bool,
    pub bytes_relayed: u64,
}

/// Relay routing table
pub struct RelayRouter {
    paths: HashMap<String, Vec<RelayPath>>, // target_uid → possible relay paths
}

impl Default for RelayRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayRouter {
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
        }
    }

    /// Register a relay path: I can reach `target` through `relay`
    pub fn add_path(&mut self, target_uid: &str, relay_uid: &str) {
        let path = RelayPath {
            relay_uid: relay_uid.to_string(),
            target_uid: target_uid.to_string(),
            active: true,
            bytes_relayed: 0,
        };
        self.paths
            .entry(target_uid.to_string())
            .or_default()
            .push(path);
    }

    /// Remove relay paths for a target
    pub fn remove_target(&mut self, target_uid: &str) {
        self.paths.remove(target_uid);
    }

    /// Get available relay paths to a target
    pub fn get_paths(&self, target_uid: &str) -> Vec<&RelayPath> {
        self.paths
            .get(target_uid)
            .map(|v| v.iter().filter(|p| p.active).collect())
            .unwrap_or_default()
    }

    /// Check if we have any relay path to a target
    pub fn has_path(&self, target_uid: &str) -> bool {
        self.paths
            .get(target_uid)
            .map(|v| v.iter().any(|p| p.active))
            .unwrap_or(false)
    }

    /// The first active relay hop toward a target (P4: used for forwarding).
    pub fn next_hop(&self, target_uid: &str) -> Option<String> {
        self.get_paths(target_uid)
            .first()
            .map(|p| p.relay_uid.clone())
    }

    /// List all relay paths
    pub fn list_all(&self) -> Vec<&RelayPath> {
        self.paths.values().flat_map(|v| v.iter()).collect()
    }
}

/// Per-sender relay admission control: replay, expiry and rate limits,
/// plus TOFU identity-key pinning for relayed senders.
pub struct RelayVerifier {
    /// sender uid → highest accepted nonce.
    last_nonce: HashMap<String, u64>,
    /// sender uid → (window start unix secs, accepted count).
    rate: HashMap<String, (u64, u32)>,
    /// sender uid → pinned identity key hex (TOFU for relayed senders).
    key_pins: HashMap<String, String>,
}

impl Default for RelayVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayVerifier {
    pub fn new() -> Self {
        Self {
            last_nonce: HashMap::new(),
            rate: HashMap::new(),
            key_pins: HashMap::new(),
        }
    }

    /// TOFU-pin (or check) a sender's identity key.
    /// Ok when the key is new or unchanged; Err when a DIFFERENT key was
    /// pinned before (possible impersonation).
    pub fn pin_key(&mut self, sender: &str, key_hex: &str) -> Result<(), String> {
        match self.key_pins.get(sender) {
            None => {
                // Coarse anti-memory-DoS eviction before inserting a new pin.
                if self.key_pins.len() >= MAX_RELAY_PINS {
                    self.key_pins.clear();
                    log::warn!("Relay key-pin table full; cleared (anti-memory-DoS)");
                }
                self.key_pins
                    .insert(sender.to_string(), key_hex.to_string());
                Ok(())
            }
            Some(prev) if prev == key_hex => Ok(()),
            Some(_) => Err(format!("identity key changed for {}", sender)),
        }
    }

    /// Admit or reject one relay message, keyed by the originator's verified
    /// identity public key (`key_hex`) rather than the spoofable `from_uid`.
    /// This makes the nonce/rate quotas sybil-resistant: many fake uids
    /// behind one identity key share a single quota. `now` is the current
    /// unix time in seconds (injectable for tests).
    pub fn check(
        &mut self,
        key_hex: &str,
        nonce: u64,
        timestamp: u64,
        now: u64,
    ) -> Result<(), String> {
        // 1. Replay: nonces must be strictly increasing per identity key.
        if let Some(&last) = self.last_nonce.get(key_hex) {
            if nonce <= last {
                return Err(format!("replayed nonce {} (last {})", nonce, last));
            }
        }

        // 2. Freshness window.
        if now.abs_diff(timestamp) > RELAY_MAX_AGE_SECS {
            return Err(format!("timestamp {} outside freshness window", timestamp));
        }

        // 3. Rate limit per window, per identity key.
        //    Coarse anti-memory-DoS eviction before inserting a new key.
        if self.rate.len() >= MAX_RELAY_TRACKED {
            self.rate.clear();
            log::warn!("Relay rate table full; cleared (anti-memory-DoS)");
        }
        let (window_start, count) = self.rate.entry(key_hex.to_string()).or_insert((now, 0));
        if now.abs_diff(*window_start) >= RELAY_RATE_WINDOW_SECS {
            *window_start = now;
            *count = 0;
        }
        if *count >= RELAY_MAX_PER_WINDOW {
            return Err(format!("rate limit exceeded for identity key {}", key_hex));
        }
        *count += 1;

        if self.last_nonce.len() >= MAX_RELAY_TRACKED {
            self.last_nonce.clear();
            log::warn!("Relay nonce table full; cleared (anti-memory-DoS)");
        }
        self.last_nonce.insert(key_hex.to_string(), nonce);
        Ok(())
    }
}

/// Fields common to a relay message being originated.
pub struct RelayOrigin<'a> {
    pub signing_key: &'a SigningKey,
    /// The originator's Ed25519 identity public key (hex) — lets recipients
    /// verify without prior knowledge (TOFU-pinned per sender).
    pub origin_key_hex: &'a str,
    pub from_uid: &'a str,
    pub to_uid: &'a str,
    pub nonce: u64,
    pub timestamp: u64,
    pub hops_left: u8,
}

/// Build a relay request message (payload already encrypted end-to-end).
pub fn build_relay_request(origin: RelayOrigin, encrypted: Vec<u8>) -> PeerMessage {
    let signature = sign_relay(
        origin.signing_key,
        origin.from_uid,
        origin.to_uid,
        origin.nonce,
        origin.timestamp,
        &encrypted,
    );
    PeerMessage::RelayRequest {
        from_uid: origin.from_uid.to_string(),
        to_uid: origin.to_uid.to_string(),
        origin_key_hex: origin.origin_key_hex.to_string(),
        nonce: origin.nonce,
        timestamp: origin.timestamp,
        hops_left: origin.hops_left.min(RELAY_MAX_HOPS),
        signature,
        encrypted_payload: encrypted,
    }
}

/// Build a relay response message.
pub fn build_relay_response(origin: RelayOrigin, encrypted: Vec<u8>) -> PeerMessage {
    let signature = sign_relay(
        origin.signing_key,
        origin.from_uid,
        origin.to_uid,
        origin.nonce,
        origin.timestamp,
        &encrypted,
    );
    PeerMessage::RelayResponse {
        from_uid: origin.from_uid.to_string(),
        to_uid: origin.to_uid.to_string(),
        origin_key_hex: origin.origin_key_hex.to_string(),
        nonce: origin.nonce,
        timestamp: origin.timestamp,
        hops_left: origin.hops_left.min(RELAY_MAX_HOPS),
        signature,
        encrypted_payload: encrypted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn ids() -> (Identity, Identity) {
        (Identity::generate("alice"), Identity::generate("bob"))
    }

    #[test]
    fn test_relay_path_add_and_get() {
        let mut r = RelayRouter::new();
        r.add_path("bob", "carol");
        let paths = r.get_paths("bob");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].relay_uid, "carol");
        assert_eq!(r.next_hop("bob").as_deref(), Some("carol"));
    }

    #[test]
    fn test_relay_unknown_target() {
        let r = RelayRouter::new();
        assert!(r.get_paths("nobody").is_empty());
        assert!(!r.has_path("nobody"));
        assert!(r.next_hop("nobody").is_none());
    }

    #[test]
    fn test_relay_signature_roundtrip_and_tamper() {
        let (alice, bob) = ids();
        let sk = alice.signing_key().unwrap();
        let vk = alice.public_key().unwrap();
        let payload = vec![1u8, 2, 3];
        let sig = sign_relay(&sk, "alice", "bob", 7, 1000, &payload);
        assert!(verify_relay(&vk, "alice", "bob", 7, 1000, &payload, &sig));
        // Tampered payload / nonce / recipient all fail.
        assert!(!verify_relay(&vk, "alice", "bob", 7, 1000, &[9u8], &sig));
        assert!(!verify_relay(&vk, "alice", "bob", 8, 1000, &payload, &sig));
        assert!(!verify_relay(
            &vk, "alice", "carol", 7, 1000, &payload, &sig
        ));
        // Wrong signer's key fails.
        let bob_vk = bob.public_key().unwrap();
        assert!(!verify_relay(
            &bob_vk, "alice", "bob", 7, 1000, &payload, &sig
        ));
        // Garbage signature bytes: false, no panic.
        assert!(!verify_relay(
            &vk, "alice", "bob", 7, 1000, &payload, &[0u8; 3]
        ));
    }

    #[test]
    fn test_relay_verifier_rejects_replay() {
        let mut v = RelayVerifier::new();
        assert!(v.check("alice", 5, 1000, 1000).is_ok());
        assert!(v.check("alice", 6, 1000, 1000).is_ok());
        // Same nonce again → replay.
        assert!(v.check("alice", 6, 1000, 1000).is_err());
        // Older nonce → replay.
        assert!(v.check("alice", 5, 1000, 1000).is_err());
    }

    #[test]
    fn test_relay_verifier_rejects_expired() {
        let mut v = RelayVerifier::new();
        assert!(v.check("alice", 1, 1000, 1030).is_ok());
        assert!(v.check("alice", 2, 1000, 1100).is_err()); // 100s old
        assert!(v.check("alice", 2, 2000, 1000).is_err()); // from the future
    }

    #[test]
    fn test_relay_verifier_rate_limit() {
        let mut v = RelayVerifier::new();
        for i in 0..RELAY_MAX_PER_WINDOW {
            assert!(v.check("alice", i as u64 + 1, 1000, 1000).is_ok());
        }
        assert!(v.check("alice", 1000, 1000, 1000).is_err()); // over limit
                                                              // A different sender is not affected.
        assert!(v.check("bob", 1, 1000, 1000).is_ok());
        // Window slides after RELAY_RATE_WINDOW_SECS.
        assert!(v.check("alice", 1001, 1061, 1061).is_ok());
    }

    #[test]
    fn test_build_relay_request() {
        let (alice, _) = ids();
        let sk = alice.signing_key().unwrap();
        let key_hex = alice.public_hex().to_string();
        let msg = build_relay_request(
            RelayOrigin {
                signing_key: &sk,
                origin_key_hex: &key_hex,
                from_uid: "alice",
                to_uid: "bob",
                nonce: 1,
                timestamp: 1000,
                hops_left: RELAY_MAX_HOPS,
            },
            vec![1, 2, 3],
        );
        let json = msg.to_json();
        assert!(json.contains("relay_request"));
        assert!(json.contains("alice"));
        assert!(json.contains("bob"));
    }

    #[test]
    fn test_verifier_pins_keys() {
        let mut v = RelayVerifier::new();
        assert!(v.pin_key("alice", "k1").is_ok());
        assert!(v.pin_key("alice", "k1").is_ok()); // same key fine
        assert!(v.pin_key("alice", "k2").is_err()); // key change rejected
        assert!(v.pin_key("bob", "k2").is_ok()); // different sender fine
    }

    #[test]
    fn test_relay_verifier_sybil_quota_shared_per_key() {
        // Anti-sybil: many uids behind one identity key share one quota.
        let mut v = RelayVerifier::new();
        let key = "one_identity_key_hex";
        for i in 0..RELAY_MAX_PER_WINDOW {
            assert!(v.check(key, i as u64 + 1, 1000, 1000).is_ok());
        }
        // A 61st message under the same key is rejected — regardless of uid.
        assert!(v.check(key, 1000, 1000, 1000).is_err());
        // A different identity key has its own independent quota.
        assert!(v.check("other_identity_key_hex", 1, 1000, 1000).is_ok());
    }

    #[test]
    fn test_inbound_hops_guard() {
        assert!(valid_inbound_hops(0));
        assert!(valid_inbound_hops(RELAY_MAX_HOPS));
        assert!(!valid_inbound_hops(RELAY_MAX_HOPS + 1));
    }
}
