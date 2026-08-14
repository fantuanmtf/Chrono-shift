//! Mesh DC-Net round driver (P3 — channel messages over the real network).
//!
//! Protocol (mesh, no trusted collector):
//!   1. A member with a message initiates: DcRoundStart to all participants.
//!   2. Every OTHER participant computes a NEUTRAL share (keys XOR only)
//!      and broadcasts DcRoundShare to everyone.
//!   3. When the initiator has received every other participant's share,
//!      it broadcasts its own share (keys XOR + message) LAST.
//!   4. Every node XORs all shares and extracts the message locally.
//!
//! Why the initiator's share goes last: if two members initiate the same
//! round id simultaneously, the higher-uid initiator aborts BEFORE sending
//! its message-share (it only ever sent the start) and simply participates
//! neutrally — the lower-uid initiator's round stays clean and delivers.
//!
//! Sender anonymity: every member transmits a share every round, and all
//! shares are pseudorandom to anyone without the edge keys, so nobody can
//! tell which member embedded the message.
//!
//! Rounds expire after CHANNEL_ROUND_DEADLINE_SECS; an expired round we
//! initiated is retried (bounded) instead of silently dropping the message.
//!
//! This module is pure state-machine logic: it returns the messages to
//! send and the texts extracted, and never touches sockets. AppState
//! forwards outgoing messages to the connection manager and extracted
//! texts to the event bus.

use crate::dcnet::round_network::*;
use crate::identity::hex_decode;
use crate::net::tcp::PeerMessage;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};

/// Fixed payload length for channel rounds (message limit = len - 36).
pub const CHANNEL_PAYLOAD_LEN: usize = 4096;

/// Round deadline in seconds.
pub const CHANNEL_ROUND_DEADLINE_SECS: u64 = 30;

/// Max retries (conflicts/expiry) before dropping a queued message.
pub const MAX_CONFLICT_RETRIES: u32 = 3;

/// Immutable context passed into driver calls.
pub struct RoundContext<'a> {
    pub my_uid: &'a str,
    pub signing_key: &'a SigningKey,
    /// friend uid → edge PSK with that friend (P1).
    pub edge_keys: &'a HashMap<String, [u8; 32]>,
    /// uid → Ed25519 identity public key hex (empty map = accept unsigned).
    pub known_keys: &'a HashMap<String, String>,
}

/// A message extracted from a completed round.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedMessage {
    pub channel: String,
    pub text: String,
    pub round_id: u64,
}

/// Result of handling one incoming message: texts to display plus
/// messages to send on the network.
#[derive(Debug, Default)]
pub struct RoundAction {
    pub extracted: Vec<ExtractedMessage>,
    /// (target_uid, message) pairs to hand to the connection manager.
    pub outgoing: Vec<(String, PeerMessage)>,
}

/// Bundled DcRoundStart fields (keeps handler signatures small).
struct RoundStartInfo<'a> {
    channel: &'a str,
    round_id: u64,
    leader_id: &'a str,
    participants: &'a [String],
    deadline_secs: u64,
    payload_len: usize,
}

/// Per-channel round state machine.
pub struct RoundDriver {
    pub tracker: RoundTracker,
    /// Our queued message (stays until a round completes).
    pub pending_message: Option<Vec<u8>>,
    /// Round id of OUR initiated round (None when we have none in flight).
    pub pending_round_id: Option<u64>,
    retries: u32,
    /// Round id → share collector (for every round we participate in).
    collectors: HashMap<u64, RoundCollector>,
    /// Rounds we already emitted (dedup).
    emitted: HashSet<u64>,
    /// Our own share for the round we initiated (message embedded),
    /// broadcast only after every other participant's share arrived.
    my_share: Option<(Vec<u8>, Vec<u8>)>, // (share, signature)
    /// True once our share has been broadcast.
    my_share_broadcast: bool,
    /// Outgoing messages produced internally (retries) that the next
    /// handle()/drain call must deliver.
    pending_outgoing: Vec<(String, PeerMessage)>,
    /// Round id we lost a conflict against; retry our message when it
    /// completes.
    retry_after_peer: Option<u64>,
}

impl RoundDriver {
    pub fn new() -> Self {
        Self {
            tracker: RoundTracker::new(),
            pending_message: None,
            pending_round_id: None,
            retries: 0,
            collectors: HashMap::new(),
            emitted: HashSet::new(),
            my_share: None,
            my_share_broadcast: false,
            pending_outgoing: Vec::new(),
            retry_after_peer: None,
        }
    }

    /// Initiate a round carrying our message. Broadcasts ONLY the start;
    /// our message-share is sent later once all other shares arrived.
    pub fn initiate(
        &mut self,
        channel: &str,
        text: &str,
        participants: &[String],
        ctx: &RoundContext,
    ) -> Result<Vec<(String, PeerMessage)>, String> {
        if text.len() + 36 > CHANNEL_PAYLOAD_LEN {
            return Err(format!(
                "message too long (max {} bytes)",
                CHANNEL_PAYLOAD_LEN - 36
            ));
        }
        if participants.len() < 2 || !participants.iter().any(|u| u == ctx.my_uid) {
            return Err("not a participant of this channel".to_string());
        }

        let round_id = self.tracker.next_round();
        let share = compute_xor_share_secure(
            round_id,
            ctx.my_uid,
            participants,
            Some(text.as_bytes()),
            CHANNEL_PAYLOAD_LEN,
            ctx.edge_keys,
        )
        .ok_or_else(|| "cannot participate securely: missing edge keys".to_string())?;
        let signature = sign_share(ctx.signing_key, channel, round_id, &share);

        // Collector for our round (starts empty; others' shares arrive).
        let collector = RoundCollector::new(
            channel,
            round_id,
            participants,
            CHANNEL_ROUND_DEADLINE_SECS,
            CHANNEL_PAYLOAD_LEN,
        );
        self.collectors.insert(round_id, collector);

        self.pending_message = Some(text.as_bytes().to_vec());
        self.pending_round_id = Some(round_id);
        self.my_share = Some((share, signature));
        self.my_share_broadcast = false;
        self.retries = 0;

        let start = build_round_start(
            channel,
            round_id,
            ctx.my_uid,
            participants,
            CHANNEL_ROUND_DEADLINE_SECS,
            CHANNEL_PAYLOAD_LEN,
        );
        let mut out = Vec::new();
        for uid in participants {
            if uid != ctx.my_uid {
                out.push((uid.clone(), start.clone()));
            }
        }
        Ok(out)
    }

    /// Handle one incoming round message.
    pub fn handle(&mut self, msg: &PeerMessage, ctx: &RoundContext) -> RoundAction {
        self.drop_expired(ctx);
        let mut action = match msg {
            PeerMessage::DcRoundStart {
                channel,
                round_id,
                leader_id,
                participants,
                deadline_secs,
                payload_len,
            } => self.on_round_start(
                RoundStartInfo {
                    channel,
                    round_id: *round_id,
                    leader_id,
                    participants,
                    deadline_secs: *deadline_secs,
                    payload_len: *payload_len,
                },
                ctx,
            ),
            PeerMessage::DcRoundShare {
                channel,
                round_id,
                peer_uid,
                xored_payload,
                signature,
            } => self.on_round_share(channel, *round_id, peer_uid, xored_payload, signature, ctx),
            _ => RoundAction::default(),
        };
        action.outgoing.append(&mut self.pending_outgoing);
        action
    }

    /// Deliver internally-buffered outgoing messages (retries).
    pub fn drain_pending_outgoing(&mut self) -> Vec<(String, PeerMessage)> {
        std::mem::take(&mut self.pending_outgoing)
    }

    fn on_round_start(&mut self, info: RoundStartInfo, ctx: &RoundContext) -> RoundAction {
        let RoundStartInfo {
            channel,
            round_id,
            leader_id,
            participants,
            deadline_secs,
            payload_len,
        } = info;
        if !self.tracker.mark_seen(round_id) {
            // Rejected: stale, duplicate, far-future — or a CONFLICT with
            // our own pending round id (two initiators picked the same id).
            let conflict = self.pending_round_id == Some(round_id) && leader_id != ctx.my_uid;
            if conflict && leader_id < ctx.my_uid {
                // We LOSE the tie-break: abort ours. We only ever sent the
                // start, so the winner's round is still clean. Fall through
                // and participate neutrally below; our message retries once
                // the winner's round completes.
                self.abort_pending_round();
                self.retry_after_peer = Some(round_id);
            } else {
                return RoundAction::default();
            }
        }
        if !participants.iter().any(|u| u == ctx.my_uid) {
            return RoundAction::default();
        }

        // Participate with a NEUTRAL share (our own message, if any, goes
        // out with our own initiated rounds).
        let Some(share) = compute_xor_share_secure(
            round_id,
            ctx.my_uid,
            participants,
            None,
            payload_len,
            ctx.edge_keys,
        ) else {
            log::warn!(
                "Round {} on {}: cannot compute share (missing edge keys)",
                round_id,
                channel
            );
            return RoundAction::default();
        };
        let signature = sign_share(ctx.signing_key, channel, round_id, &share);
        let share_msg = build_round_share(channel, round_id, ctx.my_uid, share.clone(), signature);

        let mut collector =
            RoundCollector::new(channel, round_id, participants, deadline_secs, payload_len);
        let _ = collector.submit_share(ctx.my_uid, &share);
        self.collectors.insert(round_id, collector);

        let mut action = RoundAction::default();
        for uid in participants {
            if uid != ctx.my_uid {
                action.outgoing.push((uid.clone(), share_msg.clone()));
            }
        }
        action
    }

    fn on_round_share(
        &mut self,
        channel: &str,
        round_id: u64,
        peer_uid: &str,
        share: &[u8],
        signature: &[u8],
        ctx: &RoundContext,
    ) -> RoundAction {
        // Verify the share signature when we know the peer's identity key.
        if let Some(key_hex) = ctx.known_keys.get(peer_uid) {
            match parse_verifying_key(key_hex) {
                Some(vk) => {
                    if !verify_share_signature(&vk, channel, round_id, share, signature) {
                        log::warn!("Rejecting share from {}: bad signature", peer_uid);
                        return RoundAction::default();
                    }
                }
                None => log::warn!(
                    "Peer {} has an unparsable key; share accepted unverified",
                    peer_uid
                ),
            }
        }

        let is_my_round = self.pending_round_id == Some(round_id);

        let Some(collector) = self.collectors.get_mut(&round_id) else {
            return RoundAction::default();
        };
        if collector.submit_share(peer_uid, share).is_err() {
            return RoundAction::default();
        }
        // After submitting: every other participant's share has arrived?
        let all_others_arrived = collector.missing_participants() == [ctx.my_uid.to_string()];

        let mut action = RoundAction::default();
        // If this is OUR round and every other participant's share has now
        // arrived, broadcast our message-share last.
        if is_my_round && !self.my_share_broadcast && all_others_arrived {
            if let Some((my_share, my_sig)) = self.my_share.clone() {
                let share_msg =
                    build_round_share(channel, round_id, ctx.my_uid, my_share.clone(), my_sig);
                collector.submit_share(ctx.my_uid, &my_share).ok();
                self.my_share_broadcast = true;
                for uid in &collector.participants {
                    if uid != ctx.my_uid {
                        action.outgoing.push((uid.clone(), share_msg.clone()));
                    }
                }
            }
        }

        if collector.is_complete() {
            let extracted_ok = if let Some(payload) = collector.extract_message() {
                match unpad_message(&payload).and_then(|b| String::from_utf8(b).ok()) {
                    Some(text) if self.emitted.insert(round_id) => {
                        action.extracted.push(ExtractedMessage {
                            channel: channel.to_string(),
                            text,
                            round_id,
                        });
                        true
                    }
                    _ => false,
                }
            } else {
                false
            };
            let round_participants: Vec<String> = collector.participants.iter().cloned().collect();
            self.collectors.remove(&round_id);
            if is_my_round {
                self.pending_round_id = None;
                self.my_share = None;
                self.my_share_broadcast = false;
                if !extracted_ok {
                    self.retry_pending(channel, &round_participants, ctx);
                } else {
                    self.pending_message = None;
                }
            }
            // If we lost a conflict against this round, retry our message
            // now that the winner's round has completed.
            if self.retry_after_peer == Some(round_id) {
                self.retry_after_peer = None;
                if self.pending_message.is_some() {
                    self.retry_pending(channel, &round_participants, ctx);
                }
            }
        }
        action
    }

    /// Abort our initiated round without dropping the queued message.
    fn abort_pending_round(&mut self) {
        if let Some(id) = self.pending_round_id.take() {
            self.collectors.remove(&id);
        }
        self.my_share = None;
        self.my_share_broadcast = false;
    }

    /// Re-initiate our pending message with the next round id.
    fn retry_pending(&mut self, channel: &str, participants: &[String], ctx: &RoundContext) {
        if self.retries >= MAX_CONFLICT_RETRIES {
            log::warn!(
                "Dropping message after {} failed rounds",
                MAX_CONFLICT_RETRIES
            );
            self.pending_message = None;
            return;
        }
        self.retries += 1;
        let Some(text) = self.pending_message.clone() else {
            return;
        };
        let text = String::from_utf8_lossy(&text).to_string();
        if let Ok(out) = self.initiate(channel, &text, participants, ctx) {
            self.pending_outgoing.extend(out);
            log::warn!("Round failed; requeued message on {}", channel);
        }
    }

    fn drop_expired(&mut self, ctx: &RoundContext) {
        let expired: Vec<u64> = self
            .collectors
            .iter()
            .filter(|(_, c)| c.is_expired())
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            let was_mine = self.pending_round_id == Some(id);
            let participants: Vec<String> = self
                .collectors
                .get(&id)
                .map(|c| c.participants.iter().cloned().collect())
                .unwrap_or_default();
            let channel: String = self
                .collectors
                .get(&id)
                .map(|c| c.channel.clone())
                .unwrap_or_default();
            self.collectors.remove(&id);
            if was_mine {
                self.pending_round_id = None;
                self.my_share = None;
                self.my_share_broadcast = false;
                // Retry instead of silently dropping the message.
                if !participants.is_empty() {
                    self.retry_pending(&channel, &participants, ctx);
                }
            }
        }
    }
}

impl Default for RoundDriver {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_verifying_key(key_hex: &str) -> Option<VerifyingKey> {
    let bytes = hex_decode(key_hex)?;
    let arr = <[u8; 32]>::try_from(bytes).ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    struct Node {
        id: Identity,
        uid: String,
        edge_keys: HashMap<String, [u8; 32]>,
        known_keys: HashMap<String, String>,
    }

    fn node(uid: &str) -> Node {
        let id = Identity::generate(uid);
        Node {
            uid: uid.to_string(),
            id,
            edge_keys: HashMap::new(),
            known_keys: HashMap::new(),
        }
    }

    fn pair(a: &mut Node, b: &mut Node, key: [u8; 32]) {
        a.edge_keys.insert(b.uid.clone(), key);
        b.edge_keys.insert(a.uid.clone(), key);
        a.known_keys
            .insert(b.uid.clone(), b.id.public_hex().to_string());
        b.known_keys
            .insert(a.uid.clone(), a.id.public_hex().to_string());
    }

    /// A tiny two-node message pump: delivers queued messages to the right
    /// driver and collects everything extracted.
    struct Pump<'a> {
        da: &'a mut RoundDriver,
        db: &'a mut RoundDriver,
        ctx_a: &'a RoundContext<'a>,
        ctx_b: &'a RoundContext<'a>,
        queue: Vec<(String, PeerMessage)>,
        delivered: Vec<ExtractedMessage>,
    }

    impl<'a> Pump<'a> {
        fn push(&mut self, msgs: Vec<(String, PeerMessage)>) {
            self.queue.extend(msgs);
        }
        fn run(&mut self, max_steps: usize) {
            for _ in 0..max_steps {
                if self.queue.is_empty() {
                    break;
                }
                let (uid, msg) = self.queue.remove(0);
                let action = if uid == "alice" {
                    self.da.handle(&msg, self.ctx_a)
                } else {
                    self.db.handle(&msg, self.ctx_b)
                };
                self.delivered.extend(action.extracted);
                self.queue.extend(action.outgoing);
                let pending = if uid == "alice" {
                    self.da.drain_pending_outgoing()
                } else {
                    self.db.drain_pending_outgoing()
                };
                self.queue.extend(pending);
            }
        }
    }

    #[test]
    fn test_mesh_round_delivers_message_to_all() {
        let mut alice = node("alice");
        let mut bob = node("bob");
        pair(&mut alice, &mut bob, [7u8; 32]);
        let participants = vec!["alice".to_string(), "bob".to_string()];

        let sk_a = alice.id.signing_key().expect("sk");
        let sk_b = bob.id.signing_key().expect("sk");
        let ctx_a = RoundContext {
            my_uid: &alice.uid,
            signing_key: &sk_a,
            edge_keys: &alice.edge_keys,
            known_keys: &alice.known_keys,
        };
        let ctx_b = RoundContext {
            my_uid: &bob.uid,
            signing_key: &sk_b,
            edge_keys: &bob.edge_keys,
            known_keys: &bob.known_keys,
        };

        let mut da = RoundDriver::new();
        let mut db = RoundDriver::new();

        // initiate() broadcasts ONLY the start now.
        let out = da
            .initiate("#g", "hello mesh", &participants, &ctx_a)
            .expect("initiate");
        assert_eq!(out.len(), 1);
        if let PeerMessage::DcRoundStart { .. } = &out[0].1 {
        } else {
            panic!("expected start message");
        }

        let mut pump = Pump {
            da: &mut da,
            db: &mut db,
            ctx_a: &ctx_a,
            ctx_b: &ctx_b,
            queue: Vec::new(),
            delivered: Vec::new(),
        };
        pump.push(out);
        pump.run(64);

        let texts: Vec<&str> = pump.delivered.iter().map(|e| e.text.as_str()).collect();
        assert!(
            texts.contains(&"hello mesh"),
            "message not delivered: {:?}",
            texts
        );
        // Both nodes extract (each XORs all shares).
        assert_eq!(
            pump.delivered
                .iter()
                .filter(|e| e.text == "hello mesh")
                .count(),
            2
        );
    }

    #[test]
    fn test_forged_share_rejected_when_key_known() {
        let mut alice = node("alice");
        let mut bob = node("bob");
        pair(&mut alice, &mut bob, [7u8; 32]);
        let participants = vec!["alice".to_string(), "bob".to_string()];

        let sk_a = alice.id.signing_key().expect("sk");
        let sk_b = bob.id.signing_key().expect("sk");
        let ctx_a = RoundContext {
            my_uid: &alice.uid,
            signing_key: &sk_a,
            edge_keys: &alice.edge_keys,
            known_keys: &alice.known_keys,
        };
        let ctx_b = RoundContext {
            my_uid: &bob.uid,
            signing_key: &sk_b,
            edge_keys: &bob.edge_keys,
            known_keys: &bob.known_keys,
        };

        let mut da = RoundDriver::new();
        let mut db = RoundDriver::new();
        let out = da.initiate("#g", "msg", &participants, &ctx_a).unwrap();
        let (_, start_msg) = out[0].clone();

        let b_action = db.handle(&start_msg, &ctx_b);
        let (_, b_share_msg) = b_action.outgoing[0].clone();

        if let PeerMessage::DcRoundShare {
            channel,
            round_id,
            peer_uid,
            xored_payload,
            ..
        } = b_share_msg
        {
            let forged = PeerMessage::DcRoundShare {
                channel,
                round_id,
                peer_uid,
                xored_payload,
                signature: vec![9u8; 64],
            };
            let a_action = da.handle(&forged, &ctx_a);
            assert!(a_action.extracted.is_empty());
            // Alice's round must NOT have completed (no share broadcast).
            assert!(a_action.outgoing.is_empty());
        } else {
            panic!("expected share message");
        }
    }

    #[test]
    fn test_concurrent_initiation_delivers_both_messages() {
        let mut alice = node("alice");
        let mut bob = node("bob");
        pair(&mut alice, &mut bob, [7u8; 32]);
        let participants = vec!["alice".to_string(), "bob".to_string()];

        let sk_a = alice.id.signing_key().expect("sk");
        let sk_b = bob.id.signing_key().expect("sk");
        let ctx_a = RoundContext {
            my_uid: &alice.uid,
            signing_key: &sk_a,
            edge_keys: &alice.edge_keys,
            known_keys: &alice.known_keys,
        };
        let ctx_b = RoundContext {
            my_uid: &bob.uid,
            signing_key: &sk_b,
            edge_keys: &bob.edge_keys,
            known_keys: &bob.known_keys,
        };

        let mut da = RoundDriver::new();
        let mut db = RoundDriver::new();
        let out_a = da
            .initiate("#g", "from alice", &participants, &ctx_a)
            .unwrap();
        let out_b = db
            .initiate("#g", "from bob", &participants, &ctx_b)
            .unwrap();

        let mut pump = Pump {
            da: &mut da,
            db: &mut db,
            ctx_a: &ctx_a,
            ctx_b: &ctx_b,
            queue: Vec::new(),
            delivered: Vec::new(),
        };
        pump.push(out_a);
        pump.push(out_b);
        pump.run(128);

        let texts: Vec<&str> = pump.delivered.iter().map(|e| e.text.as_str()).collect();
        assert!(
            texts.contains(&"from alice"),
            "alice's message lost: {:?}",
            texts
        );
        assert!(
            texts.contains(&"from bob"),
            "bob's message lost: {:?}",
            texts
        );
    }

    #[test]
    fn test_message_too_long_rejected() {
        let mut alice = node("alice");
        let mut bob = node("bob");
        pair(&mut alice, &mut bob, [7u8; 32]);
        let participants = vec!["alice".to_string(), "bob".to_string()];
        let sk_a = alice.id.signing_key().expect("sk");
        let ctx_a = RoundContext {
            my_uid: &alice.uid,
            signing_key: &sk_a,
            edge_keys: &alice.edge_keys,
            known_keys: &alice.known_keys,
        };
        let mut da = RoundDriver::new();
        let long = "x".repeat(CHANNEL_PAYLOAD_LEN);
        assert!(da.initiate("#g", &long, &participants, &ctx_a).is_err());
    }

    #[test]
    fn test_missing_edge_key_refuses_round() {
        let mut alice = node("alice");
        let mut bob = node("bob");
        // no pair() call — alice has no edge key for bob
        let participants = vec!["alice".to_string(), "bob".to_string()];
        let sk_a = alice.id.signing_key().expect("sk");
        let ctx_a = RoundContext {
            my_uid: &alice.uid,
            signing_key: &sk_a,
            edge_keys: &alice.edge_keys,
            known_keys: &alice.known_keys,
        };
        let mut da = RoundDriver::new();
        assert!(da.initiate("#g", "hi", &participants, &ctx_a).is_err());
    }
}
