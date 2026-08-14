//! DC-Net Round Engine (v8.0 — Phase 4, v0.0.8.2 安全移植)
//!
//! 职责:
//!   1. Send: 用边密钥计算 XOR 份额 → 广播带签名的 DcRoundShare
//!   2. Receive: 处理 DcRoundStart/Share/Result/Sync
//!   3. Track: 单一单调 round_id（防脑裂）
//!   4. Coordinate: 收集份额、提取消息（checksum 校验）、广播结果
//!
//! v0.0.8.2 移植: compute_xor_share_secure（边密钥, P1/P2）+ 份额签名验证
//!（P2）+ 新 RoundTracker 单调计数器语义 + checksum 消息帧（P2）。
//! 注意: 每轮允许一个参与者嵌入消息；若两个参与者同时有排队消息，
//! 提取会因 checksum 失败而丢弃（碰撞不伪造数据）。

use crate::dcnet::round_driver::RoundContext;
use crate::dcnet::round_network::{
    build_round_share, compute_xor_share_secure, sign_share, unpad_message, verify_share_signature,
    RoundCollector, RoundTracker, DEFAULT_PAYLOAD_LEN, MAX_ROUND_DEADLINE_SECS,
};
use crate::identity::hex_decode;
use crate::net::tcp::PeerMessage;
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;

/// Central engine for DC-Net round coordination over the network
pub struct RoundEngine {
    pub tracker: RoundTracker,
    pub collectors: HashMap<u64, RoundCollector>,
    pub my_uid: String,
    pub leader_uid: Option<String>,
}

impl RoundEngine {
    pub fn new(my_uid: &str) -> Self {
        Self {
            tracker: RoundTracker::new(),
            collectors: HashMap::new(),
            my_uid: my_uid.to_string(),
            leader_uid: None,
        }
    }

    pub fn queue_message(&mut self, text: &str) {
        self.tracker.queue_message(text);
    }

    /// Start a new round as leader. The leader also submits its own share
    /// (carrying its queued message, if any) into the collector.
    pub fn start_round_as_leader(
        &mut self,
        channel: &str,
        participants: &[String],
        ctx: &RoundContext,
    ) -> Vec<(String, PeerMessage)> {
        let round_id = self.tracker.next_round();
        let deadline = 30u64.min(MAX_ROUND_DEADLINE_SECS);
        let payload_len = DEFAULT_PAYLOAD_LEN;

        let mut collector =
            RoundCollector::new(channel, round_id, participants, deadline, payload_len);
        // Leader's own share (with queued message if any).
        if let Some(message) = self.tracker.dequeue_message() {
            if let Some(share) = compute_xor_share_secure(
                round_id,
                &self.my_uid,
                participants,
                Some(message.as_bytes()),
                payload_len,
                ctx.edge_keys,
            ) {
                let _ = collector.submit_share(&self.my_uid, &share);
            }
        } else if let Some(share) = compute_xor_share_secure(
            round_id,
            &self.my_uid,
            participants,
            None,
            payload_len,
            ctx.edge_keys,
        ) {
            let _ = collector.submit_share(&self.my_uid, &share);
        }
        self.collectors.insert(round_id, collector);

        let start_msg = crate::dcnet::round_network::build_round_start(
            channel,
            round_id,
            &self.my_uid,
            participants,
            deadline,
            payload_len,
        );
        let msgs: Vec<(String, PeerMessage)> = participants
            .iter()
            .map(|p| (p.clone(), start_msg.clone()))
            .collect();
        log::info!(
            "Round #{} started ({} participants)",
            round_id,
            participants.len()
        );
        msgs
    }

    /// Handle an incoming PeerMessage from the network.
    pub fn handle_incoming(
        &mut self,
        msg: &PeerMessage,
        ctx: &RoundContext,
    ) -> (Option<RoundEvent>, Vec<(String, PeerMessage)>) {
        match msg {
            PeerMessage::DcRoundStart {
                channel,
                round_id,
                leader_id,
                participants,
                deadline_secs,
                payload_len,
            } => self.handle_round_start(
                channel,
                *round_id,
                leader_id,
                participants,
                *deadline_secs,
                *payload_len,
                ctx,
            ),
            PeerMessage::DcRoundShare {
                channel,
                round_id,
                peer_uid,
                xored_payload,
                signature,
            } => {
                self.handle_round_share(channel, *round_id, peer_uid, xored_payload, signature, ctx)
            }
            PeerMessage::DcRoundResult {
                channel,
                round_id,
                extracted_message,
                leader_signature: _,
            } => (
                self.handle_round_result(channel, *round_id, extracted_message),
                vec![],
            ),
            PeerMessage::RoundSyncRequest { from_uid, channel } => {
                (self.handle_sync_request(from_uid, channel), vec![])
            }
            PeerMessage::RoundSyncResponse { .. } => {
                log::debug!("Received RoundSyncResponse");
                (None, vec![])
            }
            _ => (None, vec![]),
        }
    }

    #[allow(clippy::too_many_arguments)] // dispatcher bundles DcRoundStart fields
    fn handle_round_start(
        &mut self,
        channel: &str,
        round_id: u64,
        leader_id: &str,
        participants: &[String],
        deadline_secs: u64,
        payload_len: usize,
        ctx: &RoundContext,
    ) -> (Option<RoundEvent>, Vec<(String, PeerMessage)>) {
        // P2: single monotonic counter — mark_seen accepts exactly +1.
        if !self.tracker.mark_seen(round_id) {
            log::warn!("Rejected stale/future round #{}", round_id);
            return (None, vec![]);
        }
        self.leader_uid = Some(leader_id.to_string());

        let my_message = self.tracker.dequeue_message();
        let Some(share) = compute_xor_share_secure(
            round_id,
            &self.my_uid,
            participants,
            my_message.as_ref().map(|s| s.as_bytes()),
            payload_len,
            ctx.edge_keys,
        ) else {
            log::warn!(
                "Round #{}: cannot compute share (missing edge keys)",
                round_id
            );
            return (None, vec![]);
        };
        let signature = sign_share(ctx.signing_key, channel, round_id, &share);
        let share_msg = build_round_share(channel, round_id, &self.my_uid, share, signature);
        let _ = deadline_secs;
        log::debug!("Round #{}: sending share to leader {}", round_id, leader_id);
        (None, vec![(leader_id.to_string(), share_msg)])
    }

    fn handle_round_share(
        &mut self,
        channel: &str,
        round_id: u64,
        peer_uid: &str,
        xored_payload: &[u8],
        signature: &[u8],
        ctx: &RoundContext,
    ) -> (Option<RoundEvent>, Vec<(String, PeerMessage)>) {
        // P2: verify the share signature when the peer's key is known.
        if let Some(key_hex) = ctx.known_keys.get(peer_uid) {
            match parse_verifying_key(key_hex) {
                Some(vk) => {
                    if !verify_share_signature(&vk, channel, round_id, xored_payload, signature) {
                        log::warn!("Round #{}: bad share signature from {}", round_id, peer_uid);
                        return (None, vec![]);
                    }
                }
                None => log::warn!(
                    "Peer {} unparsable key; share accepted unverified",
                    peer_uid
                ),
            }
        }

        if let Some(collector) = self.collectors.get_mut(&round_id) {
            if let Err(e) = collector.submit_share(peer_uid, xored_payload) {
                log::warn!("Round #{}: bad share from {}: {}", round_id, peer_uid, e);
                return (None, vec![]);
            }

            if collector.is_complete() || collector.is_expired() {
                if let Some(payload) = collector.extract_message() {
                    // P2: checksummed frame — corrupted extractions are dropped.
                    let Some(bytes) = unpad_message(&payload) else {
                        log::warn!(
                            "Round #{}: extraction failed checksum (collision?)",
                            round_id
                        );
                        self.collectors.remove(&round_id);
                        return (None, vec![]);
                    };
                    let text = String::from_utf8(bytes.clone())
                        .unwrap_or_else(|_| "(binary data)".to_string());
                    let result_msg = PeerMessage::DcRoundResult {
                        channel: channel.to_string(),
                        round_id,
                        extracted_message: payload,
                        leader_signature: vec![],
                    };
                    let msgs: Vec<(String, PeerMessage)> = collector
                        .participants
                        .iter()
                        .map(|p| (p.clone(), result_msg.clone()))
                        .collect();
                    self.collectors.remove(&round_id);
                    return (
                        Some(RoundEvent::MessageExtracted {
                            channel: channel.to_string(),
                            text,
                            round_id,
                        }),
                        msgs,
                    );
                }
            }
        }
        (None, vec![])
    }

    fn handle_round_result(
        &mut self,
        channel: &str,
        round_id: u64,
        extracted_message: &[u8],
    ) -> Option<RoundEvent> {
        // P2: checksummed frame — verify before accepting.
        let bytes = unpad_message(extracted_message)?;
        let text = String::from_utf8(bytes).unwrap_or_else(|_| "(binary data)".to_string());
        self.tracker.mark_seen(round_id);
        Some(RoundEvent::MessageReceived {
            channel: channel.to_string(),
            text,
            round_id,
        })
    }

    fn handle_sync_request(&self, from_uid: &str, channel: &str) -> Option<RoundEvent> {
        log::info!(
            "RoundSync request from {} for channel {}",
            from_uid,
            channel
        );
        None
    }
}

/// Events emitted by RoundEngine to be forwarded to IPC
#[derive(Debug, Clone)]
pub enum RoundEvent {
    MessageReceived {
        channel: String,
        text: String,
        round_id: u64,
    },
    MessageExtracted {
        channel: String,
        text: String,
        round_id: u64,
    },
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
    use std::collections::HashMap;

    #[test]
    fn test_engine_queue_and_dequeue() {
        let mut engine = RoundEngine::new("alice");
        engine.queue_message("hello");
        engine.queue_message("world");
        assert_eq!(engine.tracker.dequeue_message().unwrap(), "hello");
        assert_eq!(engine.tracker.dequeue_message().unwrap(), "world");
        assert!(engine.tracker.dequeue_message().is_none());
    }

    #[test]
    fn test_monotonic_counter_rejects_gaps() {
        let mut engine = RoundEngine::new("alice");
        assert!(engine.tracker.mark_seen(1));
        // far-future injection rejected (split-brain fix)
        assert!(!engine.tracker.mark_seen(100));
        assert!(engine.tracker.is_stale(1));
        assert!(!engine.tracker.is_stale(2));
    }

    #[test]
    fn test_handle_round_result_checksum() {
        let mut engine = RoundEngine::new("bob");
        engine.tracker.mark_seen(1);
        let padded = crate::dcnet::round_network::pad_message(b"hello", 256).unwrap();
        let event = engine.handle_round_result("#test", 1, &padded);
        assert!(event.is_some());
        match event.unwrap() {
            RoundEvent::MessageReceived { text, round_id, .. } => {
                assert_eq!(text, "hello");
                assert_eq!(round_id, 1);
            }
            _ => panic!("wrong event"),
        }
        // Corrupted frame → rejected.
        let mut bad = padded.clone();
        bad[40] ^= 0xFF;
        assert!(engine.handle_round_result("#test", 2, &bad).is_none());
    }

    #[test]
    fn test_leader_round_start() {
        let mut engine = RoundEngine::new("leader");
        let participants = vec!["leader".to_string(), "node2".to_string()];
        engine.queue_message("test broadcast");

        let id = Identity::generate("leader");
        let sk = id.signing_key().unwrap();
        let mut edge_keys = HashMap::new();
        edge_keys.insert("node2".to_string(), [7u8; 32]);
        let known_keys = HashMap::new();
        let uid = "leader".to_string();
        let ctx = RoundContext {
            my_uid: &uid,
            signing_key: &sk,
            edge_keys: &edge_keys,
            known_keys: &known_keys,
        };

        let msgs = engine.start_round_as_leader("#general", &participants, &ctx);
        assert_eq!(msgs.len(), participants.len());
        assert!(engine.collectors.contains_key(&1));
        assert_eq!(engine.tracker.current_round_id(), 1);
    }
}
