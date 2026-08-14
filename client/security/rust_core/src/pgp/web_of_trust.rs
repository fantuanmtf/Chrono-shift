//! Web of Trust (v7.6 — Phase 2.2, P0 security rewrite)
//!
//! Directed graph of Ed25519 key signatures. Trust is calculated via a
//! worklist fixpoint over the signature graph (order-independent).
//!
//! Trust levels:
//!   Ultimate  — Our own key, or manually marked
//!   Full      — signed by 1 signer whose effective level >= Full,
//!               OR signed by 2+ signers with effective level >= Marginal
//!   Marginal  — signed by 1 signer with effective level >= Marginal
//!   Unknown   — No signatures from anyone we trust
//!   Never     — Explicitly distrusted
//!
//! effective level of one signature = min(signer's trust, signature's
//! trust_level) — a Full introducer granting only Marginal still yields
//! Marginal for the subject.
//!
//! SECURITY (P0 fix): every signature is Ed25519-verified against the
//! signer's public key both on insert and again during trust computation
//! (so a tampered on-disk WoT file cannot grant trust).

use super::PgpIdentity;
use super::TrustLevel;
use crate::identity::hex_decode;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Domain-separated, length-prefixed message that a trust signature covers:
///   "chrono-wot-sign-v1" || len(subject_fp) || subject_fp || trust_level || timestamp
pub fn signature_message(subject_fp: &str, trust_level: u8, timestamp: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(24 + subject_fp.len() + 9);
    msg.extend_from_slice(b"chrono-wot-sign-v1");
    msg.extend_from_slice(&(subject_fp.len() as u32).to_be_bytes());
    msg.extend_from_slice(subject_fp.as_bytes());
    msg.push(trust_level);
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg
}

/// A trust signature from one key to another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSignature {
    /// Who signed (fingerprint)
    pub signer_fingerprint: String,
    /// Whose key was signed (fingerprint)
    pub subject_fingerprint: String,
    /// Trust level assigned by the signer
    pub trust_level: u8,
    /// When the signature was created
    pub timestamp: u64,
    /// Ed25519 signature over signature_message(subject, trust, timestamp)
    pub signature_data: Vec<u8>,
}

impl TrustSignature {
    /// Create a properly-signed trust signature.
    pub fn create(
        signing_key: &SigningKey,
        signer_fingerprint: &str,
        subject_fingerprint: &str,
        trust_level: u8,
        timestamp: u64,
    ) -> Self {
        let msg = signature_message(subject_fingerprint, trust_level, timestamp);
        Self {
            signer_fingerprint: signer_fingerprint.to_string(),
            subject_fingerprint: subject_fingerprint.to_string(),
            trust_level,
            timestamp,
            signature_data: signing_key.sign(&msg).to_vec(),
        }
    }
}

/// Web of Trust: tracks who signed whose keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebOfTrust {
    /// All known identities (by fingerprint)
    pub keys: HashMap<String, PgpIdentity>,
    /// All trust signatures
    pub signatures: Vec<TrustSignature>,
    /// Our own fingerprints (Ultimate trust)
    pub own_fingerprints: HashSet<String>,
    /// Keys we trust as introducers
    pub trusted_introducers: HashSet<String>,
    /// Manual trust overrides (bypasses computation)
    pub manual_overrides: HashMap<String, TrustLevel>,

    /// Cache: fingerprint → TrustLevel
    #[serde(skip)]
    trust_cache: HashMap<String, TrustLevel>,
    /// Cache validity flag
    #[serde(skip)]
    cache_valid: bool,
}

impl Default for WebOfTrust {
    fn default() -> Self {
        Self::new()
    }
}

impl WebOfTrust {
    /// Create a new, empty Web of Trust
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            signatures: Vec::new(),
            own_fingerprints: HashSet::new(),
            trusted_introducers: HashSet::new(),
            manual_overrides: HashMap::new(),
            trust_cache: HashMap::new(),
            cache_valid: false,
        }
    }

    /// Add our own key (Ultimate trust)
    pub fn add_own_key(&mut self, identity: &PgpIdentity) {
        self.own_fingerprints.insert(identity.fingerprint.clone());
        self.keys
            .insert(identity.fingerprint.clone(), identity.clone());
        self.invalidate_cache();
    }

    /// Add a key to the WoT
    pub fn add_key(&mut self, identity: PgpIdentity) {
        self.keys.insert(identity.fingerprint.clone(), identity);
        self.invalidate_cache();
    }

    /// Check if we have a key
    pub fn has_key(&self, fingerprint: &str) -> bool {
        self.keys.contains_key(fingerprint)
    }

    /// Get a key by fingerprint
    pub fn get_key(&self, fingerprint: &str) -> Option<&PgpIdentity> {
        self.keys.get(fingerprint)
    }

    /// Cryptographically verify a signature against the signer's stored key.
    fn signature_is_valid(&self, sig: &TrustSignature) -> bool {
        let Some(signer) = self.keys.get(&sig.signer_fingerprint) else {
            return false;
        };
        let Some(bytes) = hex_decode(&signer.public_key_hex) else {
            return false;
        };
        let Ok(arr) = <[u8; 32]>::try_from(bytes) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&arr) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&sig.signature_data) else {
            return false;
        };
        vk.verify(
            &signature_message(&sig.subject_fingerprint, sig.trust_level, sig.timestamp),
            &signature,
        )
        .is_ok()
    }

    /// Record that signer signed subject's key at a given trust level.
    ///
    /// P0 fix: the signature is Ed25519-verified against the signer's
    /// public key; forged or tampered signatures are rejected.
    /// Returns true when the signature was accepted.
    pub fn add_signature(&mut self, sig: TrustSignature) -> bool {
        // Ensure both keys are known
        if !self.keys.contains_key(&sig.signer_fingerprint)
            || !self.keys.contains_key(&sig.subject_fingerprint)
        {
            return false;
        }
        // Avoid duplicate
        if self.signatures.iter().any(|s| {
            s.signer_fingerprint == sig.signer_fingerprint
                && s.subject_fingerprint == sig.subject_fingerprint
        }) {
            return false;
        }
        // P0: reject unverifiable signatures
        if !self.signature_is_valid(&sig) {
            return false;
        }
        self.signatures.push(sig);
        self.invalidate_cache();
        true
    }

    /// Remove all signatures from a signer to a subject
    pub fn remove_signature(&mut self, signer_fp: &str, subject_fp: &str) {
        self.signatures.retain(|s| {
            !(s.signer_fingerprint == signer_fp && s.subject_fingerprint == subject_fp)
        });
        self.invalidate_cache();
    }

    /// Manually override a trust level
    pub fn set_manual_trust(&mut self, fingerprint: &str, level: TrustLevel) {
        self.manual_overrides.insert(fingerprint.to_string(), level);
        self.invalidate_cache();
    }

    /// Calculate trust level for a fingerprint.
    pub fn calculate_trust(&mut self, fingerprint: &str) -> TrustLevel {
        // Check manual override
        if let Some(level) = self.manual_overrides.get(fingerprint) {
            return *level;
        }

        // Our own key = Ultimate
        if self.own_fingerprints.contains(fingerprint) {
            return TrustLevel::Ultimate;
        }

        if !self.cache_valid {
            self.trust_cache = self.compute_trust_map();
            self.cache_valid = true;
        }
        self.trust_cache
            .get(fingerprint)
            .copied()
            .unwrap_or(TrustLevel::Unknown)
    }

    /// Worklist fixpoint over the signature graph.
    ///
    /// P0 fix: replaces the old pseudo-BFS whose result depended on query
    /// order (it looked up signer trust via a one-level quick check). This
    /// version computes levels for ALL keys simultaneously and iterates
    /// until stable, so query order is irrelevant and cycles terminate at
    /// Unknown for keys unreachable from own keys.
    fn compute_trust_map(&self) -> HashMap<String, TrustLevel> {
        let mut trust: HashMap<String, TrustLevel> = HashMap::new();
        for fp in &self.own_fingerprints {
            trust.insert(fp.clone(), TrustLevel::Ultimate);
        }
        for (fp, lv) in &self.manual_overrides {
            trust.insert(fp.clone(), *lv);
        }

        // Only signatures that verify participate (protects against a
        // tampered persisted WoT file).
        let valid_sigs: Vec<&TrustSignature> = self
            .signatures
            .iter()
            .filter(|s| self.signature_is_valid(s))
            .collect();

        // Levels only grow (contribution = min(signer, sig_level), and
        // signer levels only grow), so the fixpoint terminates in at most
        // 4 * N iterations.
        loop {
            let mut changed = false;
            for fp in self.keys.keys() {
                if self.own_fingerprints.contains(fp) || self.manual_overrides.contains_key(fp) {
                    continue;
                }
                let mut full = 0usize;
                let mut marginal = 0usize;
                for sig in &valid_sigs {
                    if &sig.subject_fingerprint != fp {
                        continue;
                    }
                    let signer_trust = trust
                        .get(&sig.signer_fingerprint)
                        .copied()
                        .unwrap_or(TrustLevel::Unknown);
                    let sig_level = TrustLevel::from_i32(sig.trust_level as i32);
                    let contribution = signer_trust.min(sig_level);
                    if contribution >= TrustLevel::Full {
                        full += 1;
                    } else if contribution >= TrustLevel::Marginal {
                        marginal += 1;
                    }
                }
                let new_level = if full >= 1 || marginal >= 2 {
                    TrustLevel::Full
                } else if marginal >= 1 {
                    TrustLevel::Marginal
                } else {
                    TrustLevel::Unknown
                };
                let cur = trust.get(fp).copied().unwrap_or(TrustLevel::Unknown);
                if new_level != cur {
                    trust.insert(fp.clone(), new_level);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        trust
    }

    /// Find the trust path from our keys to a target (BFS over verified sigs)
    pub fn trust_path(&self, fingerprint: &str) -> Vec<String> {
        if self.own_fingerprints.contains(fingerprint) {
            return vec![format!("(you) == {}", fingerprint_short(fingerprint))];
        }

        // BFS to find shortest path
        let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();

        for own_fp in &self.own_fingerprints {
            queue.push_back((own_fp.clone(), vec![own_fp.clone()]));
            visited.insert(own_fp.clone());
        }

        while let Some((current, path)) = queue.pop_front() {
            if current == fingerprint {
                return path.into_iter().map(|fp| fingerprint_short(&fp)).collect();
            }

            // Find all keys signed by current (only verified signatures)
            for sig in &self.signatures {
                if sig.signer_fingerprint == current
                    && !visited.contains(&sig.subject_fingerprint)
                    && self.signature_is_valid(sig)
                {
                    let mut new_path = path.clone();
                    new_path.push(sig.subject_fingerprint.clone());
                    visited.insert(sig.subject_fingerprint.clone());
                    queue.push_back((sig.subject_fingerprint.clone(), new_path));
                }
            }
        }

        vec!["(no trust path found)".to_string()]
    }

    /// Find all keys at or above a trust level
    pub fn keys_at_level(&mut self, min: TrustLevel) -> Vec<PgpIdentity> {
        let mut result = Vec::new();
        let fingerprints: Vec<String> = self.keys.keys().cloned().collect();
        for fp in fingerprints {
            let trust = self.calculate_trust(&fp);
            if trust >= min {
                if let Some(key) = self.keys.get(&fp) {
                    result.push(key.clone());
                }
            }
        }
        result
    }

    /// Number of known keys
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Number of signatures
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Invalidate the trust cache.
    ///
    /// P0 fix: the map is cleared, not just flagged — stale entries can
    /// never be served again.
    fn invalidate_cache(&mut self) {
        self.cache_valid = false;
        self.trust_cache.clear();
    }
}

fn fingerprint_short(fp: &str) -> String {
    if fp.len() <= 12 {
        fp.to_string()
    } else {
        format!("{}..{}", &fp[..6], &fp[fp.len() - 6..])
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn make_id(uid: &str) -> (Identity, PgpIdentity) {
        let id = Identity::generate(uid);
        let pgp = PgpIdentity::from_identity(&id);
        (id, pgp)
    }

    fn make_sig(
        signer_id: &Identity,
        signer: &PgpIdentity,
        subject: &PgpIdentity,
        level: u8,
        ts: u64,
    ) -> TrustSignature {
        TrustSignature::create(
            &signer_id.signing_key().expect("signing key"),
            &signer.fingerprint,
            &subject.fingerprint,
            level,
            ts,
        )
    }

    #[test]
    fn test_own_key_is_ultimate() {
        let (_, alice) = make_id("alice");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        assert_eq!(
            wot.calculate_trust(&alice.fingerprint),
            TrustLevel::Ultimate
        );
    }

    #[test]
    fn test_direct_signature_is_full() {
        let (alice_id, alice) = make_id("alice");
        let (_, bob) = make_id("bob");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(bob.clone());
        assert!(wot.add_signature(make_sig(&alice_id, &alice, &bob, 2, 1000)));
        assert_eq!(wot.calculate_trust(&bob.fingerprint), TrustLevel::Full);
    }

    #[test]
    fn test_chain_alice_bob_carol() {
        let (alice_id, alice) = make_id("alice");
        let (bob_id, bob) = make_id("bob");
        let (_, carol) = make_id("carol");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(bob.clone());
        wot.add_key(carol.clone());
        wot.add_signature(make_sig(&alice_id, &alice, &bob, 2, 1000));
        wot.add_signature(make_sig(&bob_id, &bob, &carol, 2, 2000));
        assert_eq!(wot.calculate_trust(&bob.fingerprint), TrustLevel::Full);
        assert_eq!(wot.calculate_trust(&carol.fingerprint), TrustLevel::Full);
    }

    #[test]
    fn test_trust_result_is_order_independent() {
        // P0 fix regression: the old pseudo-BFS returned Carol=Unknown when
        // queried before Bob, and Full when queried after.
        let (alice_id, alice) = make_id("alice");
        let (bob_id, bob) = make_id("bob");
        let (_, carol) = make_id("carol");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(bob.clone());
        wot.add_key(carol.clone());
        wot.add_signature(make_sig(&alice_id, &alice, &bob, 2, 1000));
        wot.add_signature(make_sig(&bob_id, &bob, &carol, 2, 2000));
        // Query Carol FIRST (the order the old code failed on).
        assert_eq!(wot.calculate_trust(&carol.fingerprint), TrustLevel::Full);
        assert_eq!(wot.calculate_trust(&bob.fingerprint), TrustLevel::Full);
    }

    #[test]
    fn test_two_marginal_makes_full() {
        let (alice_id, alice) = make_id("alice");
        let (bob_id, bob) = make_id("bob");
        let (carol_id, carol) = make_id("carol");
        let (_, target) = make_id("target");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(bob.clone());
        wot.add_key(carol.clone());
        wot.add_key(target.clone());
        wot.add_signature(make_sig(&alice_id, &alice, &bob, 2, 1000));
        wot.add_signature(make_sig(&alice_id, &alice, &carol, 2, 1000));
        wot.add_signature(make_sig(&bob_id, &bob, &target, 1, 2000));
        wot.add_signature(make_sig(&carol_id, &carol, &target, 1, 2000));
        assert_eq!(wot.calculate_trust(&target.fingerprint), TrustLevel::Full);
    }

    #[test]
    fn test_signature_level_caps_signer_trust() {
        // A Full-trusted introducer granting only Marginal level
        // yields Marginal, not Full.
        let (alice_id, alice) = make_id("alice");
        let (bob_id, bob) = make_id("bob");
        let (_, carol) = make_id("carol");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(bob.clone());
        wot.add_key(carol.clone());
        wot.add_signature(make_sig(&alice_id, &alice, &bob, 2, 1000));
        wot.add_signature(make_sig(&bob_id, &bob, &carol, 1, 2000));
        assert_eq!(
            wot.calculate_trust(&carol.fingerprint),
            TrustLevel::Marginal
        );
    }

    #[test]
    fn test_forged_signature_rejected() {
        // P0 fix: a signature that does not verify against the signer's
        // key must never grant trust.
        let (alice_id, alice) = make_id("alice");
        let (_, mallory) = make_id("mallory");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(mallory.clone());

        let mut forged = make_sig(&alice_id, &alice, &mallory, 2, 1000);
        forged.signature_data = vec![9u8; 64]; // garbage bytes
        assert!(!wot.add_signature(forged));
        assert_eq!(
            wot.calculate_trust(&mallory.fingerprint),
            TrustLevel::Unknown
        );
    }

    #[test]
    fn test_signature_from_wrong_signer_rejected() {
        // The signature must verify against signer_fingerprint's key.
        let (_, alice) = make_id("alice");
        let (bob_id, bob) = make_id("bob");
        let (_, eve) = make_id("eve");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(bob.clone());
        wot.add_key(eve.clone());
        let mut sig = make_sig(&bob_id, &bob, &eve, 2, 1000);
        // ...but the record claims alice made it.
        sig.signer_fingerprint = alice.fingerprint.clone();
        assert!(!wot.add_signature(sig));
    }

    #[test]
    fn test_mutual_signing_without_own_path_is_unknown() {
        let (a_id, a) = make_id("a");
        let (b_id, b) = make_id("b");
        let (_, me) = make_id("me");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&me);
        wot.add_key(a.clone());
        wot.add_key(b.clone());
        wot.add_signature(make_sig(&a_id, &a, &b, 2, 1000));
        wot.add_signature(make_sig(&b_id, &b, &a, 2, 2000));
        assert_eq!(wot.calculate_trust(&a.fingerprint), TrustLevel::Unknown);
        assert_eq!(wot.calculate_trust(&b.fingerprint), TrustLevel::Unknown);
    }

    #[test]
    fn test_unknown_key() {
        let (_, alice) = make_id("alice");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        let (_, stranger) = make_id("stranger");
        assert_eq!(
            wot.calculate_trust(&stranger.fingerprint),
            TrustLevel::Unknown
        );
    }

    #[test]
    fn test_manual_override() {
        let (_, alice) = make_id("alice");
        let (_, eve) = make_id("eve");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(eve.clone());
        assert_eq!(wot.calculate_trust(&eve.fingerprint), TrustLevel::Unknown);
        wot.set_manual_trust(&eve.fingerprint, TrustLevel::Never);
        assert_eq!(wot.calculate_trust(&eve.fingerprint), TrustLevel::Never);
    }

    #[test]
    fn test_trust_path() {
        let (alice_id, alice) = make_id("alice");
        let (_, bob) = make_id("bob");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(bob.clone());
        wot.add_signature(make_sig(&alice_id, &alice, &bob, 2, 1000));
        let path = wot.trust_path(&bob.fingerprint);
        assert_eq!(path.len(), 2);
    }

    #[test]
    fn test_cache_invalidation() {
        let (alice_id, alice) = make_id("alice");
        let (_, bob) = make_id("bob");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(bob.clone());
        assert_eq!(wot.calculate_trust(&bob.fingerprint), TrustLevel::Unknown);
        assert!(wot.add_signature(make_sig(&alice_id, &alice, &bob, 2, 1000)));
        assert_eq!(wot.calculate_trust(&bob.fingerprint), TrustLevel::Full);
    }

    #[test]
    fn test_remove_signature_drops_trust() {
        // P0 fix regression: stale cache entries used to survive
        // invalidation.
        let (alice_id, alice) = make_id("alice");
        let (_, bob) = make_id("bob");
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&alice);
        wot.add_key(bob.clone());
        wot.add_signature(make_sig(&alice_id, &alice, &bob, 2, 1000));
        assert_eq!(wot.calculate_trust(&bob.fingerprint), TrustLevel::Full);
        wot.remove_signature(&alice.fingerprint, &bob.fingerprint);
        assert_eq!(wot.calculate_trust(&bob.fingerprint), TrustLevel::Unknown);
    }
}
