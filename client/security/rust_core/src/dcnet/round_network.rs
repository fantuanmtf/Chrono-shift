//! Distributed DC-Net Round Coordination (v7.6 — Phase 4, P2 security rewrite)
//!
//! Protocol flow:
//!   Phase 1: Leader sends DcRoundStart to all members
//!   Phase 2: Each participant computes their XOR share locally
//!   Phase 3: Each participant sends DcRoundShare to leader
//!   Phase 4: Leader computes global XOR, extracts message
//!   Phase 5: Leader sends DcRoundResult to all members
//!
//! P2 hardening:
//!   - shares are derived from offline friend-edge PSKs (derive_pair_share),
//!     never from public data — the old SHA-256(uid, round) shares were
//!     publicly computable;
//!   - submit_share rejects non-participants and duplicate submissions;
//!   - a single monotonic round counter replaces the divergent
//!     last_seen_round_id/current_round_id pair (split-brain injection fix);
//!   - messages carry a 4-byte length prefix inside the fixed payload, so
//!     trailing zero bytes are never stripped;
//!   - DcRoundShare carries an Ed25519 signature over (channel, round_id,
//!     share) for per-share authentication.

use crate::dcnet::xor_bytes;
use crate::net::tcp::PeerMessage;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Default payload length (matches PADDED_SIZE from net/tcp)
pub const DEFAULT_PAYLOAD_LEN: usize = 1024;

/// Maximum round deadline in seconds
pub const MAX_ROUND_DEADLINE_SECS: u64 = 30;

/// Domain separator for share signatures.
const SHARE_SIG_DOMAIN: &[u8] = b"chrono-dcnet-share-v1";

/// Derive the 32-byte peer id for a uid (same construction as f2f.rs).
pub fn peer_id_of(uid: &str) -> [u8; 32] {
    Sha256::digest(uid.as_bytes()).into()
}

/// Collects XOR shares from participants for one round
pub struct RoundCollector {
    pub channel: String,
    pub round_id: u64,
    pub participants: HashSet<String>,
    /// Collected shares: participant_uid → XOR output
    pub shares_received: HashMap<String, Vec<u8>>,
    pub deadline: Instant,
    pub payload_len: usize,
    /// The message we want to send (only if we're the sender)
    pub my_message: Option<Vec<u8>>,
    /// Whether we've submitted our own share
    pub my_share_submitted: bool,
}

impl RoundCollector {
    /// Create a new round collector (called by the leader)
    pub fn new(
        channel: &str,
        round_id: u64,
        participants: &[String],
        deadline_secs: u64,
        payload_len: usize,
    ) -> Self {
        Self {
            channel: channel.to_string(),
            round_id,
            participants: participants.iter().cloned().collect(),
            shares_received: HashMap::new(),
            deadline: Instant::now()
                + std::time::Duration::from_secs(deadline_secs.min(MAX_ROUND_DEADLINE_SECS)),
            // Honor the announced payload length (sanity-clamped).
            // P2 fix: the old .max(DEFAULT_PAYLOAD_LEN) silently forced
            // every round to >= 1024 bytes regardless of announcement.
            payload_len: payload_len.clamp(4, 65536),
            my_message: None,
            my_share_submitted: false,
        }
    }

    /// Check if the round deadline has passed
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Check if all participants have submitted shares
    pub fn is_complete(&self) -> bool {
        self.shares_received.len() >= self.participants.len()
    }

    /// Submit a share from a participant.
    ///
    /// P2 fix: rejects shares from non-participants and duplicate
    /// submissions (the old code accepted both — anyone could impersonate
    /// another member or force the round to "complete" with junk).
    pub fn submit_share(&mut self, peer_uid: &str, xored: &[u8]) -> Result<(), String> {
        if !self.participants.contains(peer_uid) {
            return Err(format!("{} is not a participant of this round", peer_uid));
        }
        if self.shares_received.contains_key(peer_uid) {
            return Err(format!("duplicate share from {}", peer_uid));
        }
        if xored.len() != self.payload_len {
            return Err(format!(
                "Share length mismatch: got {}, expected {}",
                xored.len(),
                self.payload_len
            ));
        }
        self.shares_received
            .insert(peer_uid.to_string(), xored.to_vec());
        Ok(())
    }

    /// Get the list of participants who haven't submitted yet
    pub fn missing_participants(&self) -> Vec<String> {
        self.participants
            .iter()
            .filter(|p| !self.shares_received.contains_key(*p))
            .cloned()
            .collect()
    }

    /// Compute the global XOR of all received shares to extract the message
    pub fn extract_message(&self) -> Option<Vec<u8>> {
        if self.shares_received.is_empty() {
            return None;
        }
        let mut result = vec![0u8; self.payload_len];
        for share in self.shares_received.values() {
            let xored = xor_bytes(&result, share);
            result[..xored.len()].copy_from_slice(&xored);
        }
        Some(result)
    }
}

/// Computes a participant's XOR share for a DC-Net round using offline
/// friend-edge PSKs. This is the production share construction:
///
///   share = XOR over friends of derive_pair_share(edge_key, round_id, me, them)
///           (+ padded message if we are the sender)
///
/// Returns None when we cannot participate securely: we are not in the
/// participant list, the group is too small, a message does not fit, or an
/// edge key for some participant is missing (refuse rather than fall back
/// to publicly-computable shares).
pub fn compute_xor_share_secure(
    round_id: u64,
    my_uid: &str,
    participants: &[String],
    message: Option<&[u8]>,
    payload_len: usize,
    edge_keys: &HashMap<String, [u8; 32]>,
) -> Option<Vec<u8>> {
    if participants.len() < 2 || !participants.iter().any(|u| u == my_uid) {
        return None;
    }
    let my_peer = peer_id_of(my_uid);
    let mut output = vec![0u8; payload_len];

    for other in participants {
        if other == my_uid {
            continue;
        }
        // Refuse to participate without a secret edge key.
        let key = edge_keys.get(other)?;
        let share = crate::dcnet::derive_pair_share(
            key,
            round_id,
            &my_peer,
            &peer_id_of(other),
            payload_len,
        );
        output = xor_bytes(&output, &share);
    }

    if let Some(msg) = message {
        let padded = pad_message(msg, payload_len)?;
        output = xor_bytes(&output, &padded);
    }
    Some(output)
}

/// DETERMINISTIC simulation helper (kept for tests and demos only).
/// Its keys are publicly computable — it provides NO anonymity and NO
/// confidentiality. Production code must use compute_xor_share_secure.
pub fn compute_xor_share_simulation(
    round_id: u64,
    my_uid: &str,
    participants: &[String],
    message: Option<&[u8]>,
    payload_len: usize,
) -> Option<Vec<u8>> {
    let mut output = vec![0u8; payload_len];

    for other in participants {
        if other == my_uid {
            continue;
        }
        let share = pairwise_share_simulation(round_id, my_uid, other, payload_len);
        output = xor_bytes(&output, &share);
    }

    if let Some(msg) = message {
        let padded = pad_message(msg, payload_len)?;
        output = xor_bytes(&output, &padded);
    }
    Some(output)
}

fn pairwise_share_simulation(
    round_id: u64,
    peer_a: &str,
    peer_b: &str,
    output_len: usize,
) -> Vec<u8> {
    let (p1, p2) = if peer_a < peer_b {
        (peer_a, peer_b)
    } else {
        (peer_b, peer_a)
    };

    let mut hasher = Sha256::new();
    hasher.update(b"chrono-dcnet-pairwise-sim-v1");
    hasher.update((p1.len() as u32).to_be_bytes());
    hasher.update(p1.as_bytes());
    hasher.update((p2.len() as u32).to_be_bytes());
    hasher.update(p2.as_bytes());
    hasher.update(round_id.to_be_bytes());
    let hash = hasher.finalize();

    let mut result = Vec::with_capacity(output_len);
    while result.len() < output_len {
        result.extend_from_slice(&hash);
    }
    result.truncate(output_len);
    result
}

/// Frame a message inside the fixed payload:
/// [4-byte BE length][32-byte SHA-256 of message][message][zero pad].
///
/// P2 fix: the old zero-pad + trim-trailing-zeros scheme silently truncated
/// messages ending in 0x00 and leaked unmasked tails. Length prefixing makes
/// extraction exact for arbitrary binary content; the SHA-256 checksum lets
/// us DETECT corrupted extractions (e.g. two senders colliding in one round)
/// instead of emitting garbage text.
pub fn pad_message(msg: &[u8], payload_len: usize) -> Option<Vec<u8>> {
    let frame_len = 36 + msg.len();
    if payload_len < frame_len {
        return None;
    }
    let mut padded = vec![0u8; payload_len];
    padded[..4].copy_from_slice(&(msg.len() as u32).to_be_bytes());
    padded[4..36].copy_from_slice(&Sha256::digest(msg));
    padded[36..36 + msg.len()].copy_from_slice(msg);
    Some(padded)
}

/// Extract the original message from a length-prefixed padded payload,
/// verifying the embedded checksum. Returns None on any corruption.
pub fn unpad_message(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 36 {
        return None;
    }
    let len = u32::from_be_bytes(padded[..4].try_into().ok()?) as usize;
    if len > padded.len() - 36 {
        return None;
    }
    let msg = &padded[36..36 + len];
    if Sha256::digest(msg).as_slice() != &padded[4..36] {
        return None; // corrupted XOR result (collision or tampering)
    }
    Some(msg.to_vec())
}

/// The exact bytes a DcRoundShare signature covers.
pub fn share_signature_message(channel: &str, round_id: u64, share: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SHARE_SIG_DOMAIN.len() + 4 + channel.len() + 8 + share.len());
    msg.extend_from_slice(SHARE_SIG_DOMAIN);
    msg.extend_from_slice(&(channel.len() as u32).to_be_bytes());
    msg.extend_from_slice(channel.as_bytes());
    msg.extend_from_slice(&round_id.to_be_bytes());
    msg.extend_from_slice(share);
    msg
}

/// Sign a round share with our identity key.
pub fn sign_share(signing_key: &SigningKey, channel: &str, round_id: u64, share: &[u8]) -> Vec<u8> {
    signing_key
        .sign(&share_signature_message(channel, round_id, share))
        .to_vec()
}

/// Verify a round share signature (false on any parse failure).
pub fn verify_share_signature(
    vk: &VerifyingKey,
    channel: &str,
    round_id: u64,
    share: &[u8],
    signature: &[u8],
) -> bool {
    match Signature::from_slice(signature) {
        Ok(sig) => vk
            .verify(&share_signature_message(channel, round_id, share), &sig)
            .is_ok(),
        Err(_) => false,
    }
}

/// Build a DcRoundStart message
pub fn build_round_start(
    channel: &str,
    round_id: u64,
    leader_id: &str,
    participants: &[String],
    deadline_secs: u64,
    payload_len: usize,
) -> PeerMessage {
    PeerMessage::DcRoundStart {
        channel: channel.to_string(),
        round_id,
        leader_id: leader_id.to_string(),
        participants: participants.to_vec(),
        deadline_secs,
        payload_len,
    }
}

/// Build a DcRoundShare message (signature over channel || round_id || share)
pub fn build_round_share(
    channel: &str,
    round_id: u64,
    peer_uid: &str,
    xored_payload: Vec<u8>,
    signature: Vec<u8>,
) -> PeerMessage {
    PeerMessage::DcRoundShare {
        channel: channel.to_string(),
        round_id,
        peer_uid: peer_uid.to_string(),
        xored_payload,
        signature,
    }
}

/// Track round state for a network with a SINGLE monotonic counter.
///
/// P2 fix (split-brain): the old design kept two counters
/// (current_round_id / last_seen_round_id) with different update rules —
/// observing one far-future round id could permanently reject all later
/// legitimate rounds. Now there is exactly one counter and round ids may
/// only advance by exactly +1.
pub struct RoundTracker {
    current_round_id: u64,
    /// Active round collector (if we're the leader)
    pub active_round: Option<RoundCollector>,
    /// Pending message queue: text → submit in next round
    pub message_queue: Vec<String>,
    /// Leader heartbeat tracking
    pub last_leader_seen: Instant,
}

impl Default for RoundTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundTracker {
    pub fn new() -> Self {
        Self {
            current_round_id: 0,
            active_round: None,
            message_queue: Vec::new(),
            last_leader_seen: Instant::now(),
        }
    }

    /// The current round id.
    pub fn current_round_id(&self) -> u64 {
        self.current_round_id
    }

    /// Advance to the next round id (leader side).
    pub fn next_round(&mut self) -> u64 {
        self.current_round_id += 1;
        self.current_round_id
    }

    /// Accept a round id observed from the network. Only exactly the next
    /// round (+1) is accepted — far-future ids are rejected instead of
    /// adopted (the old split-brain bug). Returns false when rejected.
    pub fn mark_seen(&mut self, round_id: u64) -> bool {
        if round_id == self.current_round_id + 1 {
            self.current_round_id = round_id;
            true
        } else {
            false
        }
    }

    /// True when the round id has already passed.
    pub fn is_stale(&self, round_id: u64) -> bool {
        round_id <= self.current_round_id
    }

    /// A round id is valid to act on when it is the current or the next one.
    pub fn verify_round_id(&self, round_id: u64) -> bool {
        round_id == self.current_round_id || round_id == self.current_round_id + 1
    }

    /// Queue a message for the next round
    pub fn queue_message(&mut self, text: &str) {
        self.message_queue.push(text.to_string());
    }

    /// Dequeue the next message (if any)
    pub fn dequeue_message(&mut self) -> Option<String> {
        if self.message_queue.is_empty() {
            None
        } else {
            Some(self.message_queue.remove(0))
        }
    }

    /// v8.1 port: build a RoundSyncResponse for a reconnecting node.
    /// Only includes commitments (SHA-256 hashes of shares), never raw
    /// shares — prevents downgrade attacks without leaking anything.
    pub fn build_sync_response(
        &self,
        leader_uid: &str,
        channel: &str,
        collector: &RoundCollector,
    ) -> crate::net::tcp::PeerMessage {
        let commitments: Vec<(String, String)> = collector
            .shares_received
            .iter()
            .map(|(uid, share)| {
                let hash = sha2::Sha256::digest(share);
                (uid.clone(), format!("{:x}", hash))
            })
            .collect();

        crate::net::tcp::PeerMessage::RoundSyncResponse {
            leader_uid: leader_uid.to_string(),
            channel: channel.to_string(),
            round_id: self.current_round_id(),
            payload_len: collector.payload_len,
            share_commitments: commitments,
        }
    }

    /// v8.1 port: verify that a share matches its previously-received
    /// RoundSync commitment.
    pub fn verify_share_commitment(uid: &str, share: &[u8], commitment: &str) -> bool {
        let _ = uid;
        let actual = format!("{:x}", sha2::Sha256::digest(share));
        actual == commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use std::collections::HashMap;

    /// Build one participant's edge-key map: friend uid → per-pair PSK.
    /// Each pair of friends has its OWN key (offline exchange), so every
    /// participant carries a distinct key per friend.
    fn keymap(pairs: &[(&str, [u8; 32])]) -> HashMap<String, [u8; 32]> {
        pairs.iter().map(|(u, k)| (u.to_string(), *k)).collect()
    }

    #[test]
    fn test_secure_share_cancellation_extracts_message() {
        let participants = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
        let (k_ab, k_ac, k_bc) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let alice_keys = keymap(&[("bob", k_ab), ("carol", k_ac)]);
        let bob_keys = keymap(&[("alice", k_ab), ("carol", k_bc)]);
        let carol_keys = keymap(&[("alice", k_ac), ("bob", k_bc)]);

        let msg = b"secret message from the sender";
        let alice =
            compute_xor_share_secure(7, "alice", &participants, Some(msg), 256, &alice_keys)
                .expect("alice share");
        let bob = compute_xor_share_secure(7, "bob", &participants, None, 256, &bob_keys)
            .expect("bob share");
        let carol = compute_xor_share_secure(7, "carol", &participants, None, 256, &carol_keys)
            .expect("carol share");

        let mut global = vec![0u8; 256];
        for s in [&alice, &bob, &carol] {
            global = xor_bytes(&global, s);
        }
        assert_eq!(unpad_message(&global).as_deref(), Some(&msg[..]));
    }

    #[test]
    fn test_secure_share_refuses_missing_edge_key() {
        // Without a secret edge key for every peer, participation must be
        // refused (no silent fallback to publicly-computable shares).
        let participants = vec!["alice".to_string(), "bob".to_string()];
        let keys = keymap(&[("carol", [1u8; 32])]); // bob missing
        assert!(compute_xor_share_secure(1, "alice", &participants, None, 256, &keys).is_none());
        // Also refuse when we're not even in the participant list.
        assert!(compute_xor_share_secure(1, "eve", &participants, None, 256, &keys).is_none());
    }

    #[test]
    fn test_observer_with_wrong_key_cannot_recover_message() {
        // Attack test: an observer with a DIFFERENT edge key cannot derive
        // the real shares, so the global XOR does not yield the message.
        let participants = vec!["alice".to_string(), "bob".to_string()];
        let alice_keys = keymap(&[("bob", [1u8; 32])]);
        let observer_keys = keymap(&[("alice", [9u8; 32])]); // wrong key

        let msg = b"attack target";
        let alice =
            compute_xor_share_secure(3, "alice", &participants, Some(msg), 256, &alice_keys)
                .expect("alice");
        let bob_forged =
            compute_xor_share_secure(3, "bob", &participants, None, 256, &observer_keys)
                .expect("observer computed something");

        let mut global = vec![0u8; 256];
        for s in [&alice, &bob_forged] {
            global = xor_bytes(&global, s);
        }
        assert_ne!(unpad_message(&global).as_deref(), Some(&msg[..]));
    }

    #[test]
    fn test_round_collector_rejects_outsiders_and_duplicates() {
        let participants = vec!["alice".to_string(), "bob".to_string()];
        let mut rc = RoundCollector::new("#test", 1, &participants, 10, 256);

        // Outsider impersonation is rejected.
        let err = rc.submit_share("mallory", &vec![0u8; 256]).unwrap_err();
        assert!(err.contains("not a participant"));

        rc.submit_share("alice", &vec![1u8; 256]).unwrap();
        // Duplicate submission is rejected (no overwrite).
        let err = rc.submit_share("alice", &vec![2u8; 256]).unwrap_err();
        assert!(err.contains("duplicate"));
        assert_eq!(rc.shares_received["alice"], vec![1u8; 256]);

        // Length mismatch still rejected.
        assert!(rc.submit_share("bob", &vec![0u8; 128]).is_err());
        rc.submit_share("bob", &vec![3u8; 256]).unwrap();
        assert!(rc.is_complete());
    }

    #[test]
    fn test_round_tracker_single_monotonic_counter() {
        // P2 split-brain fix: only exactly +1 advances the counter.
        let mut rt = RoundTracker::new();
        assert_eq!(rt.current_round_id(), 0);

        assert!(rt.mark_seen(1));
        assert_eq!(rt.current_round_id(), 1);

        // Far-future ids are REJECTED, not adopted (the old bug let one
        // malicious far-future id permanently reject all legit rounds).
        assert!(!rt.mark_seen(100));
        assert_eq!(rt.current_round_id(), 1);

        assert!(rt.is_stale(1));
        assert!(!rt.is_stale(2));
        assert!(rt.verify_round_id(1)); // current
        assert!(rt.verify_round_id(2)); // next
        assert!(!rt.verify_round_id(3)); // too far
        assert!(!rt.verify_round_id(0)); // stale

        assert_eq!(rt.next_round(), 2);
        assert!(rt.mark_seen(3));
    }

    #[test]
    fn test_pad_unpad_preserves_trailing_zeros() {
        // P2 fix regression: the old trailing-zero-trim scheme destroyed
        // binary messages ending in 0x00.
        let msg = [1u8, 2, 3, 0, 0, 0];
        let padded = pad_message(&msg, 256).expect("fits");
        assert_eq!(padded.len(), 256);
        assert_eq!(unpad_message(&padded).unwrap(), msg);
    }

    #[test]
    fn test_pad_rejects_oversized_message() {
        assert!(pad_message(&[0u8; 300], 256).is_none());
        assert!(unpad_message(&[0u8; 2]).is_none());
    }

    #[test]
    fn test_share_signature_binds_content() {
        let id = Identity::generate("alice");
        let sk = id.signing_key().expect("sk");
        let vk = id.public_key().expect("vk");

        let share = vec![7u8; 256];
        let sig = sign_share(&sk, "#general", 4, &share);
        assert!(verify_share_signature(&vk, "#general", 4, &share, &sig));

        // Tampered share / channel / round → verification fails.
        assert!(!verify_share_signature(
            &vk,
            "#general",
            4,
            &vec![8u8; 256],
            &sig
        ));
        assert!(!verify_share_signature(&vk, "#other", 4, &share, &sig));
        assert!(!verify_share_signature(&vk, "#general", 5, &share, &sig));
        // Garbage signature bytes → false (no panic).
        assert!(!verify_share_signature(
            &vk,
            "#general",
            4,
            &share,
            &[1u8, 2, 3]
        ));
    }

    #[test]
    fn test_round_collector_and_messages() {
        let participants = vec!["alice".to_string(), "bob".to_string()];
        let mut rc = RoundCollector::new("#test", 1, &participants, 10, 256);
        assert!(!rc.is_expired());
        assert!(!rc.is_complete());
        rc.submit_share("alice", &vec![42u8; 256]).unwrap();
        assert!(!rc.is_complete());
        rc.submit_share("bob", &vec![42u8; 256]).unwrap();
        assert!(rc.is_complete());

        let start = build_round_start("#test", 1, "alice", &participants, 10, 256);
        let json = start.to_json();
        assert!(json.contains("dc_round_start"));
        assert!(json.contains("#test"));

        let share = build_round_share("#test", 1, "alice", vec![0u8; 256], vec![1u8; 64]);
        let json = share.to_json();
        assert!(json.contains("dc_round_share"));
    }

    #[test]
    fn test_round_tracker_message_queue() {
        let mut rt = RoundTracker::new();
        rt.queue_message("hello");
        rt.queue_message("world");
        assert_eq!(rt.dequeue_message(), Some("hello".into()));
        assert_eq!(rt.dequeue_message(), Some("world".into()));
        assert_eq!(rt.dequeue_message(), None);
    }

    #[test]
    fn test_simulation_share_symmetry() {
        // The deterministic simulation helper still works (docs/demos only).
        let participants = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
        let msg = b"hello world";
        let alice =
            compute_xor_share_simulation(1, "alice", &participants, Some(msg), 256).expect("alice");
        let bob = compute_xor_share_simulation(1, "bob", &participants, None, 256).expect("bob");
        let carol =
            compute_xor_share_simulation(1, "carol", &participants, None, 256).expect("carol");

        let mut global = vec![0u8; 256];
        for s in [&alice, &bob, &carol] {
            global = xor_bytes(&global, s);
        }
        assert_eq!(unpad_message(&global).as_deref(), Some(&msg[..]));
    }
}
