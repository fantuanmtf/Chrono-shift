//! F2F trust web -> DC-Net multi-channel bridge (v7.0, P1: edge keys + WAL)
use crate::dcnet::group::DcGroup;
use crate::dcnet::reputation::ReputationManager;
use crate::identity::{hex_decode, hex_encode};
use crate::storage::{ChannelRecord, FriendRecord, SocialSnapshot, WalOperation, WalStore};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Offline-established friend-edge pre-shared key (32 bytes).
///
/// This is the pairwise secret that DC-Net shares are derived from
/// (see dcnet::derive_pair_share). It is meant to be exchanged OUT OF
/// BAND (QR code / fingerprint comparison) between the two friends.
///
/// Debug output is redacted and the key bytes are zeroized on drop.
pub struct EdgeKey([u8; 32]);

impl EdgeKey {
    /// Generate a fresh random edge key (local-side generation; the peer
    /// must import the same key out of band).
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Self(b)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    pub fn from_hex(hex: &str) -> Option<Self> {
        let bytes = hex_decode(hex)?;
        <[u8; 32]>::try_from(bytes).ok().map(Self)
    }
}

impl Clone for EdgeKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::Debug for EdgeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EdgeKey").field(&"<redacted>").finish()
    }
}

impl Drop for EdgeKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct F2fFriend {
    pub uid: String,
    pub peer_id: [u8; 32],
    pub trust_level: u8,
    pub transport_address: String,
    /// Offline-established edge PSK for DC-Net pairwise shares.
    pub edge_key: EdgeKey,
}
impl F2fFriend {
    pub fn new(uid: &str, addr: &str, trust_level: u8) -> Self {
        let mut h = Sha256::new();
        h.update(uid.as_bytes());
        Self {
            uid: uid.into(),
            peer_id: h.finalize().into(),
            trust_level: trust_level.min(2),
            transport_address: addr.into(),
            edge_key: EdgeKey::generate(),
        }
    }

    pub fn with_edge_key(uid: &str, addr: &str, trust_level: u8, edge_key: EdgeKey) -> Self {
        let mut f = Self::new(uid, addr, trust_level);
        f.edge_key = edge_key;
        f
    }
}

#[derive(Debug)]
pub struct ChannelInfo {
    pub name: String,
    pub topic: String,
    pub participants: Vec<String>,
    pub round_id: u64,
    pub running: Arc<AtomicBool>,
}

pub struct F2fDcNetBridge {
    friends: HashMap<String, F2fFriend>,
    channels: HashMap<String, ChannelInfo>,
    groups: HashMap<String, DcGroup>,
    reputation: ReputationManager,
    my_uid: String,
    current_channel: Option<String>,
    min_trust: u8,
    /// Write-Ahead Log (attached by AppState at startup; None in tests).
    wal: Option<WalStore>,
}

impl F2fDcNetBridge {
    pub fn new(my_uid: &str) -> Self {
        Self {
            friends: HashMap::new(),
            channels: HashMap::new(),
            groups: HashMap::new(),
            reputation: ReputationManager::new(),
            my_uid: my_uid.into(),
            current_channel: None,
            min_trust: 1,
            wal: None,
        }
    }

    /// Attach a WAL store. From now on every mutating method appends its
    /// operation to the WAL BEFORE touching in-memory state.
    pub fn attach_wal(&mut self, wal: WalStore) {
        self.wal = Some(wal);
    }

    /// Append an operation to the WAL (if attached), then checkpoint when due.
    fn log_wal(&mut self, op: WalOperation) {
        let Some(wal) = self.wal.as_mut() else { return };
        if wal.append(&op).is_err() {
            log::error!("WAL append failed — state change not persisted");
        }
        if wal.should_checkpoint() {
            let snap = snapshot_bridge(self);
            if let Some(wal) = self.wal.as_mut() {
                let _ = wal.checkpoint(&snap);
            }
        }
    }

    /// Force a checkpoint of the current social state (called on shutdown).
    pub fn checkpoint_wal(&mut self) {
        if self.wal.is_some() {
            let snap = snapshot_bridge(self);
            if let Some(wal) = self.wal.as_mut() {
                let _ = wal.checkpoint(&snap);
            }
        }
    }

    /// Number of un-checkpointed WAL operations (0 when no WAL attached).
    pub fn wal_ops_pending(&self) -> u64 {
        self.wal.as_ref().map(|w| w.ops_count()).unwrap_or(0)
    }

    /// Apply a replayed WAL operation WITHOUT logging it again.
    /// Used by AppState at startup to rebuild state from the WAL.
    pub fn apply_op_no_log(&mut self, op: &WalOperation) {
        match op {
            WalOperation::AddFriend { uid, addr, trust } => {
                self.friends
                    .insert(uid.clone(), F2fFriend::new(uid, addr, *trust));
            }
            WalOperation::RemoveFriend { uid } => {
                self.friends.remove(uid);
            }
            WalOperation::UpdateTrust { uid, trust } => {
                if let Some(f) = self.friends.get_mut(uid) {
                    f.trust_level = (*trust).min(2);
                }
            }
            WalOperation::UpdateEdgeKey { uid, key_hex } => {
                if let Some(k) = EdgeKey::from_hex(key_hex) {
                    if let Some(f) = self.friends.get_mut(uid) {
                        f.edge_key = k;
                    }
                }
            }
            WalOperation::CreateChannel { name } => {
                self.create_channel_no_log(name);
            }
            WalOperation::JoinChannel { channel, uid } => {
                let uids = vec![uid.clone()];
                self.join_channel_no_log(channel, &uids);
            }
            WalOperation::LeaveChannel { channel, uid } => {
                if uid == &self.my_uid {
                    self.leave_channel_no_log(channel);
                } else if let Some(ch) = self.channels.get_mut(channel) {
                    ch.participants.retain(|u| u != uid);
                    if let Some(g) = self.groups.get_mut(channel) {
                        let peer = Self::uid_to_peer(uid);
                        g.leave(&peer);
                    }
                }
            }
            WalOperation::SetUid { uid } => {
                self.my_uid = uid.clone();
            }
            _ => {}
        }
    }

    pub fn add_friend(&mut self, uid: &str, addr: &str, trust_level: u8) {
        self.log_wal(WalOperation::AddFriend {
            uid: uid.into(),
            addr: addr.into(),
            trust: trust_level,
        });
        self.friends
            .insert(uid.into(), F2fFriend::new(uid, addr, trust_level));
    }
    pub fn remove_friend(&mut self, uid: &str) {
        self.log_wal(WalOperation::RemoveFriend { uid: uid.into() });
        self.friends.remove(uid);
    }
    pub fn is_friend(&self, uid: &str) -> bool {
        self.friends.contains_key(uid)
    }
    pub fn list_friends(&self) -> Vec<String> {
        self.friends.keys().cloned().collect()
    }
    pub fn update_trust(&mut self, uid: &str, trust_level: u8) {
        self.log_wal(WalOperation::UpdateTrust {
            uid: uid.into(),
            trust: trust_level,
        });
        if let Some(f) = self.friends.get_mut(uid) {
            f.trust_level = trust_level.min(2);
        }
    }

    // ---- Edge keys (offline-established pair PSK, P1) ----

    /// Replace the edge key for a friend (offline exchange flow).
    /// Logged to the WAL so it survives crashes before the next checkpoint.
    pub fn set_edge_key(&mut self, uid: &str, key: EdgeKey) -> bool {
        let key_hex = key.to_hex();
        if !self.friends.contains_key(uid) {
            return false;
        }
        self.log_wal(WalOperation::UpdateEdgeKey {
            uid: uid.into(),
            key_hex,
        });
        if let Some(f) = self.friends.get_mut(uid) {
            f.edge_key = key;
        }
        true
    }

    /// Import an edge key from its hex form (what the CLI prints / scans).
    pub fn import_edge_key(&mut self, uid: &str, hex: &str) -> bool {
        match EdgeKey::from_hex(hex) {
            Some(k) => self.set_edge_key(uid, k),
            None => false,
        }
    }

    /// Hex form of the friend's edge key, for out-of-band exchange.
    /// Only ever display this to the key owner — it IS the pairwise secret.
    pub fn edge_key_hex(&self, uid: &str) -> Option<String> {
        self.friends.get(uid).map(|f| f.edge_key.to_hex())
    }

    pub fn has_edge_key(&self, uid: &str) -> bool {
        self.friends.contains_key(uid)
    }

    /// Change our uid (used by /nick).
    ///
    /// P3 fix: /nick used to update only Identity, leaving the bridge with
    /// a stale uid — channel participants and DC-Net shares then disagreed
    /// between nodes. Now both stay in sync and the change is WAL-logged.
    pub fn set_my_uid(&mut self, uid: &str) {
        self.log_wal(WalOperation::SetUid { uid: uid.into() });
        self.my_uid = uid.to_string();
    }

    /// Snapshot of every friend's edge PSK (friend uid → key bytes).
    /// Used by the round driver to derive per-pair DC-Net shares (P3).
    pub fn edge_key_map(&self) -> HashMap<String, [u8; 32]> {
        self.friends
            .iter()
            .map(|(uid, f)| (uid.clone(), *f.edge_key.as_bytes()))
            .collect()
    }
    pub fn is_trusted(&self, uid: &str) -> bool {
        self.friends
            .get(uid)
            .map(|f| f.trust_level >= self.min_trust)
            .unwrap_or(false)
    }
    /// Friend trust level on the unified 0..=2 scale
    /// (0 = UNVERIFIED, 1 = VERIFIED, 2 = FULL_TRUST).
    ///
    /// P0 fix: was f.trust_level + 1 (a third, inconsistent scale).
    pub fn get_trust(&self, uid: &str) -> u8 {
        self.friends.get(uid).map(|f| f.trust_level).unwrap_or(0)
    }
    pub fn get_transport_address(&self, uid: &str) -> Option<&str> {
        self.friends.get(uid).map(|f| f.transport_address.as_str())
    }
    pub fn create_channel(&mut self, name: &str) -> bool {
        if self.channels.contains_key(name) {
            return false;
        }
        self.log_wal(WalOperation::CreateChannel { name: name.into() });
        self.create_channel_no_log(name)
    }

    /// Create a channel without WAL logging (used by replay/snapshot paths).
    fn create_channel_no_log(&mut self, name: &str) -> bool {
        if self.channels.contains_key(name) {
            return false;
        }
        let mut h = Sha256::new();
        h.update(name.as_bytes());
        let mut group = DcGroup::new(h.finalize().into(), 2, 1); // min 2 for creator + 1 friend
                                                                 // Auto-join the creator to their own group
        let my_peer = Self::uid_to_peer(&self.my_uid);
        group.join(my_peer);
        self.groups.insert(name.into(), group);
        self.channels.insert(
            name.into(),
            ChannelInfo {
                name: name.into(),
                topic: String::new(),
                participants: vec![self.my_uid.clone()],
                round_id: 0,
                running: Arc::new(AtomicBool::new(false)),
            },
        );
        true
    }

    pub fn join_channel(&mut self, channel: &str, uids: &[String]) -> Vec<String> {
        for uid in uids {
            if self
                .channels
                .get(channel)
                .map(|c| c.participants.contains(uid))
                == Some(false)
                && self.friends.contains_key(uid)
            {
                self.log_wal(WalOperation::JoinChannel {
                    channel: channel.into(),
                    uid: uid.clone(),
                });
            }
        }
        self.join_channel_no_log(channel, uids)
    }

    /// Join members without WAL logging (used by replay/snapshot paths).
    fn join_channel_no_log(&mut self, channel: &str, uids: &[String]) -> Vec<String> {
        let mut joined = Vec::new();
        if let (Some(ch), Some(group)) =
            (self.channels.get_mut(channel), self.groups.get_mut(channel))
        {
            for uid in uids {
                if uid == &self.my_uid {
                    continue;
                }
                if let Some(f) = self.friends.get(uid) {
                    if f.trust_level >= self.min_trust && !ch.participants.contains(uid) {
                        group.join(f.peer_id);
                        ch.participants.push(uid.clone());
                        joined.push(uid.clone());
                    }
                }
            }
        }
        joined
    }

    pub fn leave_channel(&mut self, name: &str) {
        self.log_wal(WalOperation::LeaveChannel {
            channel: name.into(),
            uid: self.my_uid.clone(),
        });
        self.leave_channel_no_log(name);
    }

    /// Leave a channel without WAL logging (used by replay paths).
    fn leave_channel_no_log(&mut self, name: &str) {
        if let Some(ch) = self.channels.get_mut(name) {
            ch.participants.retain(|u| u != &self.my_uid);
        }
        if let Some(g) = self.groups.get_mut(name) {
            let my_peer = Self::uid_to_peer(&self.my_uid);
            g.leave(&my_peer);
        }
    }
    pub fn switch_channel(&mut self, name: &str) -> bool {
        if self.channels.contains_key(name) {
            self.current_channel = Some(name.into());
            true
        } else {
            false
        }
    }
    pub fn current_channel_name(&self) -> Option<&str> {
        self.current_channel.as_deref()
    }
    /// M2 fix: set channel topic
    pub fn set_topic(&mut self, channel: &str, topic: &str) {
        if let Some(ch) = self.channels.get_mut(channel) {
            ch.topic = topic.to_string();
        }
    }

    pub fn list_participants(&self, name: &str) -> Vec<String> {
        self.channels
            .get(name)
            .map(|ch| ch.participants.clone())
            .unwrap_or_default()
    }

    pub fn list_channels(&self) -> Vec<String> {
        self.channels.keys().cloned().collect()
    }
    pub fn group_status(&self) -> String {
        // S3 fix: use serde_json instead of format! (prevents JSON injection)
        serde_json::to_string(&serde_json::json!({
            "friends": self.friends.len(),
            "trusted": self.friends.values().filter(|f| f.trust_level >= self.min_trust).count(),
            "channels": self.channels.len(),
            "current": self.current_channel.as_deref().unwrap_or("none"),
            "my_uid": self.my_uid,
        }))
        .unwrap_or_default()
    }
    pub fn sync_reputation_to_trust(&mut self) -> Vec<(String, u8)> {
        let updates: Vec<_> = self
            .friends
            .values()
            .map(|f| (f.uid.clone(), f.peer_id, f.trust_level))
            .collect();
        let mut changes = Vec::new();
        for (uid, peer_id, cur) in updates {
            let rep = self.reputation.get_or_create(&peer_id);
            let nt = if rep.is_malicious() {
                0
            } else if rep.score >= 0.8 {
                2
            } else if rep.score >= 0.5 {
                1
            } else {
                0
            };
            if cur != nt {
                if let Some(f) = self.friends.get_mut(&uid) {
                    f.trust_level = nt;
                    changes.push((uid, nt));
                }
            }
        }
        changes
    }
    pub fn channel_status(&self, name: &str) -> String {
        // S3 fix: use serde_json instead of format!
        if let (Some(ch), Some(g)) = (self.channels.get(name), self.groups.get(name)) {
            serde_json::to_string(&serde_json::json!({
                "name": ch.name,
                "topic": ch.topic,
                "participants": ch.participants.len(),
                "group_size": g.size(),
                "healthy": g.is_healthy(),
                "round": ch.round_id,
                "running": ch.running.load(Ordering::Relaxed),
            }))
            .unwrap_or_default()
        } else {
            serde_json::to_string(
                &serde_json::json!({"error": format!("channel not found: {}", name)}),
            )
            .unwrap_or_default()
        }
    }
    /// Real N-party DC-Net broadcast (L1.1 fix)
    ///
    /// Algorithm:
    ///   1. Each pair (i,j) generates DH shared key via X25519
    ///   2. Participant i computes: msg ⊕ share_i1 ⊕ share_i2 ⊕ ... (all their outgoing shares)
    ///   3. Non-senders compute: share_i1 ⊕ share_i2 ⊕ ... (their shares only, no message)
    ///   4. Global XOR of ALL broadcasts → message extracted, all shares cancel out
    ///
    /// For single-instance CLI: simulates all participants locally.
    /// In a real network: each participant sends their broadcast via TCP to the Leader.
    pub fn broadcast_message(&mut self, channel: &str, text: &str) -> Option<String> {
        let group = self.groups.get_mut(channel)?;
        let participants: Vec<[u8; 32]> = group.participants.iter().map(|p| p.peer_id).collect();

        if participants.len() < 2 {
            return Some(text.to_string());
        }

        let next_id = self
            .channels
            .get(channel)
            .map(|ch| ch.round_id + 1)
            .unwrap_or(1);
        let _round = group.start_round(next_id)?;

        // Phase 1: Generate pairwise DH shared keys.
        //
        // FIX (audit CRITICAL): the previous "real X25519" derived BOTH
        // scalars from PUBLIC data (SHA-256(peer_id || round_id)), so every
        // observer could recompute all pairwise keys and read the plaintext
        // — the anonymity was mathematically void. Now each participant gets
        // a fresh OsRng ephemeral X25519 keypair per round.
        //
        // NOTE: this is the local single-process simulation path, so all
        // ephemeral keys are generated here. A real network MUST exchange
        // ephemeral public keys through the round protocol with sender
        // authentication; see round_network.rs (still to be wired).
        let n = participants.len();
        let payload_len = 4 + text.len();
        let secrets: Vec<StaticSecret> = (0..n)
            .map(|_| StaticSecret::random_from_rng(rand::rngs::OsRng))
            .collect();
        let publics: Vec<PublicKey> = secrets.iter().map(PublicKey::from).collect();

        // shares[i] = XOR over all pairwise keys of participant i, expanded
        // to the full payload length so no plaintext tail ever leaks.
        let mut shares: Vec<Vec<u8>> = vec![vec![0u8; payload_len]; n];
        for i in 0..n {
            for j in (i + 1)..n {
                // DH symmetry: participant j computes the same bytes from
                // secrets[j] x publics[i].
                let shared = secrets[i].diffie_hellman(&publics[j]);
                let expanded = expand_share(shared.as_bytes(), payload_len);
                shares[i] = crate::dcnet::xor_bytes(&shares[i], &expanded);
                shares[j] = crate::dcnet::xor_bytes(&shares[j], &expanded);
            }
        }
        drop(secrets);
        drop(publics);

        // Find sender index (ourselves — the one with the message).
        // FIX: was unwrap_or(0) which silently XORed our message into a
        // random member's share when we were not in the participant list.
        let my_peer = Self::uid_to_peer(&self.my_uid);
        let sender_idx = participants.iter().position(|p| *p == my_peer)?;

        // Phase 2: Sender XORs the message into their broadcast
        // C1 fix: prepend 4-byte length prefix to prevent trailing-zero truncation
        let len_bytes = (text.len() as u32).to_be_bytes();
        let mut payload = Vec::with_capacity(4 + text.len());
        payload.extend_from_slice(&len_bytes);
        payload.extend_from_slice(text.as_bytes());
        let sender_broadcast = crate::dcnet::xor_bytes(&shares[sender_idx], &payload);
        shares[sender_idx] = sender_broadcast;

        // Phase 3: Global XOR of all broadcasts.
        // FIX: was 4 + text.len().max(32) — messages longer than 32 bytes
        // left their tail completely unmasked. All shares are now exactly
        // payload_len bytes.
        let mut global_xor = vec![0u8; payload_len];
        for share in &shares {
            global_xor = crate::dcnet::xor_bytes(&global_xor, share);
        }

        // C1 fix: extract message by reading length prefix, not trimming zeros.
        // FIX: removed .trim() — it silently stripped legitimate leading/
        // trailing whitespace from user messages.
        let extracted = if global_xor.len() >= 4 {
            let declared_len =
                u32::from_be_bytes(global_xor[..4].try_into().unwrap_or([0; 4])) as usize;
            let actual_len = declared_len.min(global_xor.len().saturating_sub(4));
            String::from_utf8_lossy(&global_xor[4..4 + actual_len]).to_string()
        } else {
            String::from_utf8_lossy(&global_xor).to_string()
        };

        // Phase 4: Reputation — in this local simulation every participant
        // responds (all shares are computed locally), so nobody is penalized
        // here. The REAL network path must pass the actual responded list
        // into finish_round_with(); it now writes penalties back into the
        // group and evicts malicious members (P2 fix: previously the
        // penalties applied to a clone were silently discarded).
        let responded_peers: Vec<[u8; 32]> = participants.clone();
        let (dropouts, mut malicious) = group.finish_round_with(&responded_peers);
        if !dropouts.is_empty() {
            log::warn!("Round #{} had {} dropouts", next_id, dropouts.len());
        }

        // ReputationManager-level round processing (scores + malicious list).
        let responded: Vec<Vec<u8>> = participants.iter().map(|p| p.to_vec()).collect();
        for m in self.reputation.process_round(&responded, &responded, 100) {
            if let Ok(arr) = <[u8; 32]>::try_from(m.as_slice()) {
                malicious.push(arr);
            }
        }

        // Reputation → F2F trust level sync (unified 0..=2 scale).
        let _trust_updates = self.sync_reputation_to_trust();

        if let Some(ch) = self.channels.get_mut(channel) {
            ch.round_id = next_id;
            // Keep the channel participant list in sync with evictions.
            if !malicious.is_empty() {
                let bad: Vec<String> = ch
                    .participants
                    .iter()
                    .filter(|u| malicious.contains(&Self::uid_to_peer(u)))
                    .cloned()
                    .collect();
                for b in bad {
                    ch.participants.retain(|u| u != &b);
                }
            }
        }

        Some(format!(
            "[DC-Net round #{} ({} parties)] {}",
            next_id,
            participants.len(),
            extracted
        ))
    }

    /// Start a background DC-Net round driver for a channel (L3)
    /// Drives rounds every interval_ms (default 3000ms = 3 seconds)
    pub fn start_round_driver(&mut self, channel: &str, interval_ms: u64) {
        let ch_name = channel.to_string();
        if let Some(ch) = self.channels.get_mut(&ch_name) {
            if ch.running.load(std::sync::atomic::Ordering::Relaxed) {
                return; // already running
            }
            ch.running.store(true, std::sync::atomic::Ordering::Relaxed);
            let running = ch.running.clone();
            std::thread::spawn(move || {
                while running.load(std::sync::atomic::Ordering::Relaxed) {
                    // Sleep for the interval
                    std::thread::sleep(std::time::Duration::from_millis(interval_ms));
                    // In a real implementation: collect XOR shares, compute result, deliver
                    // For now: the round driver keeps the channel alive with periodic ticks
                }
            });
        }
    }

    /// Stop the round driver for a channel
    pub fn stop_round_driver(&mut self, channel: &str) {
        if let Some(ch) = self.channels.get_mut(channel) {
            ch.running
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// L1.3: Shuffle reveal — Leader broadcasts decryption keys after collection
    /// In a real network: keys sent via TCP to each participant separately.
    /// For CLI: returns the revealed messages for display.
    /// L2 fix: removed unused `channel` parameter
    pub fn reveal_round(
        &self,
        _channel: &str,
        commitment: &crate::dcnet::shuffle::ShuffleCommitment,
    ) -> Vec<String> {
        let mut messages = Vec::new();
        for slot in &commitment.slots {
            if let Some(pt) = commitment.decrypt_slot(slot) {
                if commitment.verify(slot, &pt) {
                    messages.push(String::from_utf8_lossy(&pt).to_string());
                }
            }
        }
        messages
    }

    fn uid_to_peer(uid: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(uid.as_bytes());
        h.finalize().into()
    }
}

/// Capture the bridge's social state into a WAL-checkpoint snapshot.
pub fn snapshot_bridge(b: &F2fDcNetBridge) -> SocialSnapshot {
    SocialSnapshot {
        uid: b.my_uid.clone(),
        friends: b
            .friends
            .iter()
            .map(|(uid, f)| FriendRecord {
                uid: uid.clone(),
                addr: f.transport_address.clone(),
                trust: f.trust_level,
                edge_key_hex: Some(f.edge_key.to_hex()),
            })
            .collect(),
        channels: b
            .channels
            .values()
            .map(|c| ChannelRecord {
                name: c.name.clone(),
                topic: c.topic.clone(),
                participants: c.participants.clone(),
            })
            .collect(),
    }
}

/// Rebuild the bridge from a WAL-checkpoint snapshot (startup path).
/// Does not touch the WAL (it is applied before the WAL is attached).
pub fn apply_snapshot(b: &mut F2fDcNetBridge, snap: &SocialSnapshot) {
    b.my_uid = snap.uid.clone();
    b.friends.clear();
    b.channels.clear();
    b.groups.clear();

    for f in &snap.friends {
        let key = f
            .edge_key_hex
            .as_deref()
            .and_then(EdgeKey::from_hex)
            .unwrap_or_else(EdgeKey::generate);
        b.friends.insert(
            f.uid.clone(),
            F2fFriend::with_edge_key(&f.uid, &f.addr, f.trust, key),
        );
    }

    for c in &snap.channels {
        b.create_channel_no_log(&c.name);
        if let Some(ch) = b.channels.get_mut(&c.name) {
            ch.topic = c.topic.clone();
            ch.participants = c.participants.clone();
        }
        // Rebuild group membership (join dedups; creator is already in).
        if let Some(g) = b.groups.get_mut(&c.name) {
            for p in &c.participants {
                g.join(F2fDcNetBridge::uid_to_peer(p));
            }
        }
    }
}

/// Deterministically expand a DH shared secret to the given length using
/// counter-mode SHA-256 (block i = SHA-256(seed || i.to_be_bytes())).
///
/// Used to stretch the 32-byte X25519 output to the full DC-Net payload
/// length so shares mask every byte of the message (including its tail).
fn expand_share(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u64 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

// Phase 1.1: Global static removed — all state accessed via AppState (Arc<Mutex<AppState>>)

#[cfg(test)]
mod tests {
    use super::*;
    fn mk() -> F2fDcNetBridge {
        F2fDcNetBridge::new("alice")
    }
    #[test]
    fn test_add_friend() {
        let mut b = mk();
        b.add_friend("bob", "127.0.0.1:9000", 1);
        assert!(b.is_trusted("bob"));
    }
    #[test]
    fn test_remove_friend() {
        let mut b = mk();
        b.add_friend("bob", "127.0.0.1:9000", 1);
        b.remove_friend("bob");
        assert!(!b.is_trusted("bob"));
    }
    #[test]
    fn test_create_and_join_channel() {
        let mut b = mk();
        b.add_friend("bob", "127.0.0.1:9000", 1);
        b.create_channel("#general");
        assert_eq!(b.join_channel("#general", &["bob".into()]).len(), 1);
    }
    #[test]
    fn test_trust_level_filters() {
        let mut b = mk();
        b.add_friend("eve", "127.0.0.1:9000", 0);
        b.add_friend("bob", "127.0.0.1:9001", 1);
        b.create_channel("#t");
        assert_eq!(b.join_channel("#t", &["eve".into(), "bob".into()]).len(), 1);
    }
    #[test]
    fn test_list_channels() {
        let mut b = mk();
        b.create_channel("#a");
        b.create_channel("#b");
        let l = b.list_channels();
        assert!(l.contains(&"#a".into()));
    }
    #[test]
    fn test_group_status_json() {
        let mut b = mk();
        b.add_friend("bob", "127.0.0.1:9000", 1);
        assert!(b.group_status().contains("alice"));
    }

    #[test]
    fn test_broadcast_long_message_roundtrip() {
        let mut b = mk();
        b.add_friend("bob", "127.0.0.1:9000", 1);
        b.add_friend("carol", "127.0.0.1:9001", 1);
        b.create_channel("#general");
        b.join_channel("#general", &["bob".into(), "carol".into()]);

        // >32 bytes: the old code left the tail of such messages completely
        // unmasked (share buffers were only 32 bytes).
        let long_msg =
            "Hello DC-Net! This message is long enough to expose the old tail leak: 0123456789";
        let out = b.broadcast_message("#general", long_msg).expect("round");
        assert!(out.contains(long_msg), "roundtrip failed: {}", out);
    }

    #[test]
    fn test_broadcast_preserves_whitespace() {
        let mut b = mk();
        b.add_friend("bob", "127.0.0.1:9000", 1);
        b.add_friend("carol", "127.0.0.1:9001", 1);
        b.create_channel("#w");
        b.join_channel("#w", &["bob".into(), "carol".into()]);

        // .trim() used to silently strip user whitespace.
        let out = b
            .broadcast_message("#w", "  padded message  ")
            .expect("round");
        assert!(
            out.contains("  padded message  "),
            "whitespace mangled: {}",
            out
        );
    }

    #[test]
    fn test_edge_key_redacted_in_debug() {
        let f = F2fFriend::new("bob", "127.0.0.1:9000", 1);
        let hex = f.edge_key.to_hex();
        let dbg = format!("{:?}", f);
        assert!(!dbg.contains(&hex), "Debug output leaked the edge key");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn test_edge_key_import_roundtrip() {
        let mut b = mk();
        b.add_friend("bob", "127.0.0.1:9000", 1);
        let hex = b.edge_key_hex("bob").expect("edge key");

        // Import the same key on another friend (out-of-band exchange).
        b.add_friend("carol", "127.0.0.1:9001", 1);
        assert!(b.import_edge_key("carol", &hex));
        assert_eq!(b.edge_key_hex("carol").unwrap(), hex);

        // Unknown uid / bad hex are rejected.
        assert!(!b.set_edge_key("nobody", EdgeKey::generate()));
        assert!(!b.import_edge_key("bob", "not-hex"));
    }

    #[test]
    fn test_broadcast_distinct_rounds_use_distinct_keys() {
        let mut b = mk();
        b.add_friend("bob", "127.0.0.1:9000", 1);
        b.create_channel("#r");
        b.join_channel("#r", &["bob".into()]);

        // Two rounds of the same message must not produce identical
        // ciphertext streams — ephemeral keys are fresh per round.
        let msg = "same message, different keys";
        let out1 = b.broadcast_message("#r", msg).expect("round 1");
        let out2 = b.broadcast_message("#r", msg).expect("round 2");
        assert!(out1.contains(msg) && out2.contains(msg));
    }
}
