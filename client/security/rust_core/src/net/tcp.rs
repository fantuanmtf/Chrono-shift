//! Direct TCP peer-to-peer messaging (v7.2 L2: traffic padding)
//!
//! Frame format: [4 bytes length (BE)] [AES-256-GCM encrypted payload] [padding to 1024]
//! Handshake: AuthChallenge → AuthResponse (Ed25519 signature)
use crate::crypto;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// Start listening for incoming friend connections (non-blocking)
pub fn start_listener(port: u16) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Connect to a friend
pub fn connect_to(addr: &str) -> std::io::Result<TcpStream> {
    TcpStream::connect(addr)
}

/// Send an AES-256-GCM encrypted frame (v7.1 S3)
pub fn send_encrypted_frame(
    stream: &mut TcpStream,
    payload: &[u8],
    key: &[u8; 32],
) -> std::io::Result<()> {
    let encrypted =
        crypto::encrypt_e2e(payload, key).ok_or_else(|| std::io::Error::other("encrypt failed"))?;
    send_frame(stream, &encrypted)
}

/// Receive and decrypt an AES-256-GCM frame (v7.1 S3)
pub fn recv_encrypted_frame(stream: &mut TcpStream, key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
    let encrypted = recv_frame(stream)?;
    crypto::decrypt_e2e(&encrypted, key).ok_or_else(|| std::io::Error::other("decrypt failed"))
}

/// Send a length-framed message
pub fn send_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(payload)?;
    Ok(())
}

/// Receive a length-framed message
pub fn recv_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 65536 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Message types for the P2P protocol (v7.6 — Phase 4: DC-Net distributed rounds)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PeerMessage {
    // ---- Friendship ----
    #[serde(rename = "friend_req")]
    FriendRequest { from_uid: String, greeting: String },
    #[serde(rename = "friend_accept")]
    FriendAccept { from_uid: String },

    // ---- Messaging ----
    #[serde(rename = "channel_msg")]
    ChannelMessage {
        channel: String,
        from_uid: String,
        text: String,
    },

    // ---- DC-Net rounds (Phase 4) ----
    #[serde(rename = "dc_round")]
    DcRound {
        channel: String,
        round_id: u64,
        xored_payload: Vec<u8>,
    },
    /// Leader initiates a new DC-Net round
    #[serde(rename = "dc_round_start")]
    DcRoundStart {
        channel: String,
        round_id: u64,
        leader_id: String,
        participants: Vec<String>,
        deadline_secs: u64,
        payload_len: usize, // all participants must XOR this many bytes
    },
    /// Participant sends their XOR share to the leader
    #[serde(rename = "dc_round_share")]
    DcRoundShare {
        channel: String,
        round_id: u64,
        peer_uid: String,
        xored_payload: Vec<u8>, // length must == DcRoundStart.payload_len
        /// Ed25519 signature over (channel || round_id || xored_payload)
        /// — see round_network::share_signature_message.
        signature: Vec<u8>,
    },
    /// Leader broadcasts the extracted message
    #[serde(rename = "dc_round_result")]
    DcRoundResult {
        channel: String,
        round_id: u64,
        extracted_message: Vec<u8>,
        leader_signature: Vec<u8>, // Ed25519 signature to prevent tampering
    },
    /// Reconnecting node requests current round state from Leader.
    /// Does NOT contain private shares — only public metadata.
    #[serde(rename = "round_sync_request")]
    RoundSyncRequest { from_uid: String, channel: String },
    /// Leader replies with current round_id + list of commitments.
    /// Commitments are SHA-256 hashes of each node's XOR share,
    /// NOT the shares themselves — anonymity is preserved.
    #[serde(rename = "round_sync_response")]
    RoundSyncResponse {
        leader_uid: String,
        channel: String,
        round_id: u64,
        payload_len: usize,
        /// Commitments: participant_uid → SHA-256(their XOR share)
        /// Used only to verify that a share seen later matches the
        /// commitment received here (prevents downgrade attacks).
        share_commitments: Vec<(String, String)>,
    },
    /// Leader changed (failover or transfer)
    #[serde(rename = "leader_change")]
    LeaderChange {
        network: String,
        new_leader: String,
        reason: String, // "timeout" | "transfer"
        round_id: u64,
    },

    // ---- Network membership (Phase 3) ----
    #[serde(rename = "network_invite")]
    NetworkInvite {
        from_uid: String,
        network_name: String,
        pgp_fingerprint: String,
        signature: Vec<u8>,
    },
    #[serde(rename = "network_join_request")]
    NetworkJoinRequest {
        from_uid: String,
        network_name: String,
        pgp_fingerprint: String,
        signature: Vec<u8>,
    },
    #[serde(rename = "network_join_accept")]
    NetworkJoinAccept {
        from_uid: String,
        network_name: String,
        member_list: Vec<String>,
        signature: Vec<u8>,
    },
    #[serde(rename = "network_kick")]
    NetworkKick {
        from_uid: String,
        network_name: String,
        kicked_uid: String,
        reason: String,
        signature: Vec<u8>,
    },
    #[serde(rename = "network_sync")]
    NetworkSync {
        from_uid: String,
        network_name: String,
        members: Vec<String>,
        topic: String,
        round_id: u64,
        signature: Vec<u8>,
    },

    // ---- Keepalive ----
    #[serde(rename = "ping")]
    Ping { ts: u64 },
    #[serde(rename = "pong")]
    Pong { ts: u64 },

    // ---- Auth ----
    // ---- Auth (session handshake: X25519 ephemeral + Ed25519 identity sig) ----
    #[serde(rename = "auth_challenge")]
    AuthChallenge {
        from_uid: String,
        /// Ed25519 identity public key (hex)
        public_key_hex: String,
        /// X25519 ephemeral public key for this session (hex)
        eph_pub_hex: String,
        nonce: Vec<u8>,
        /// Ed25519 signature over (eph_pub || nonce)
        signature: Vec<u8>,
    },
    #[serde(rename = "auth_response")]
    AuthResponse {
        from_uid: String,
        /// Ed25519 identity public key (hex)
        public_key_hex: String,
        /// X25519 ephemeral public key for this session (hex)
        eph_pub_hex: String,
        /// Ed25519 signature over (challenge_eph_pub || eph_pub || nonce)
        signature: Vec<u8>,
    },

    // ---- Relay (P4: signed, replay-protected, loop-limited) ----
    #[serde(rename = "relay_request")]
    RelayRequest {
        from_uid: String,
        to_uid: String,
        /// The originator's Ed25519 identity public key (hex) so recipients
        /// who never met the originator can verify (TOFU-pinned per sender).
        origin_key_hex: String,
        /// Sender-monotonic nonce (anti-replay).
        nonce: u64,
        /// Unix seconds when the request was created (anti-expiry).
        timestamp: u64,
        /// Remaining hops; every relay decrements it (anti-loop). NOT
        /// covered by the signature so relays can decrement it.
        hops_left: u8,
        /// Ed25519 signature over (from, to, nonce, timestamp, payload).
        signature: Vec<u8>,
        encrypted_payload: Vec<u8>,
    },
    #[serde(rename = "relay_response")]
    RelayResponse {
        from_uid: String,
        to_uid: String,
        origin_key_hex: String,
        nonce: u64,
        timestamp: u64,
        hops_left: u8,
        signature: Vec<u8>,
        encrypted_payload: Vec<u8>,
    },
}

impl PeerMessage {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

// === Traffic padding (L2) ===

/// All frames padded to this size (hides message length)
pub const PADDED_SIZE: usize = 1024;

/// Pad a payload to PADDED_SIZE with random bytes (C3 fix: reject oversized)
pub fn pad_frame(payload: &[u8]) -> std::io::Result<Vec<u8>> {
    if payload.len() > PADDED_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("payload too large: {} > {}", payload.len(), PADDED_SIZE),
        ));
    }
    let mut padded = vec![0u8; PADDED_SIZE];
    padded[..payload.len()].copy_from_slice(payload);
    if payload.len() < PADDED_SIZE {
        rand::rngs::OsRng.fill_bytes(&mut padded[payload.len()..]);
    }
    Ok(padded)
}

/// Generate a keepalive frame (random padding, no content)
pub fn keepalive_frame() -> Vec<u8> {
    let mut buf = vec![0u8; PADDED_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Unpad: extract actual payload length from padded frame
/// Returns the original payload bytes (before padding)
pub fn unpad_frame(padded: &[u8], original_len: usize) -> &[u8] {
    let len = original_len.min(padded.len());
    &padded[..len]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let msg = PeerMessage::Ping { ts: 42 };
        let json = msg.to_json();
        let parsed = PeerMessage::from_json(&json).unwrap();
        assert!(matches!(parsed, PeerMessage::Ping { ts: 42 }));
    }

    #[test]
    fn test_message_types() {
        let cm = PeerMessage::ChannelMessage {
            channel: "#test".into(),
            from_uid: "alice".into(),
            text: "hello".into(),
        };
        let json = cm.to_json();
        assert!(json.contains("channel_msg"));
        assert!(json.contains("#test"));
    }
}
