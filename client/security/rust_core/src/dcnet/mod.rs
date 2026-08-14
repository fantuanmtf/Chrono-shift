pub mod f2f;
pub mod group;
pub mod network;
pub mod reputation;
pub mod round;
pub mod round_driver;
pub mod round_network;
pub mod shuffle;

use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub peer_id: [u8; 32],
    pub shares: Vec<[u8; 32]>,
    pub reputation: f64,
    pub consecutive_drops: u32,
    pub rounds_participated: u64,
}

impl Participant {
    pub fn new(peer_id: [u8; 32]) -> Self {
        Self {
            peer_id,
            shares: Vec::new(),
            reputation: 1.0,
            consecutive_drops: 0,
            rounds_participated: 0,
        }
    }
    pub fn penalize(&mut self) {
        self.consecutive_drops += 1;
        self.reputation *= 0.7;
    }
    pub fn reward(&mut self) {
        self.consecutive_drops = 0;
        self.reputation = (self.reputation + 0.05).min(1.0);
    }
    pub fn is_malicious(&self) -> bool {
        self.consecutive_drops >= 3 || self.reputation < 0.3
    }

    /// Copy reputation state from another participant.
    ///
    /// P2 fix: DC-Net rounds operate on a CLONE of the group members; this
    /// writes the round's penalty/reward results back to the group so
    /// dropouts actually lose reputation (previously the penalties were
    /// silently discarded).
    pub fn absorb_from(&mut self, other: &Participant) {
        self.reputation = other.reputation;
        self.consecutive_drops = other.consecutive_drops;
        self.rounds_participated = other.rounds_participated;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcMessage {
    pub round_id: u64,
    pub sender_id: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().max(b.len());
    let mut result = vec![0u8; len];
    for (i, byte) in result.iter_mut().enumerate() {
        let va = a.get(i).copied().unwrap_or(0);
        let vb = b.get(i).copied().unwrap_or(0);
        *byte = va ^ vb;
    }
    result
}

/// Derive a pairwise XOR share for one DC-Net round from a friend-edge
/// PSK (offline-established, see f2f::EdgeKey).
///
/// info = "chrono-dcnet-pair-v1" || round_id || min(peer_a, peer_b) || max(peer_a, peer_b)
///
/// Peer ids are sorted so both ends derive the same bytes. The HKDF output
/// is expanded in blocks for arbitrary lengths.
pub fn derive_pair_share(
    edge_key: &[u8],
    round_id: u64,
    peer_a: &[u8; 32],
    peer_b: &[u8; 32],
    len: usize,
) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let (lo, hi) = if peer_a < peer_b {
        (peer_a, peer_b)
    } else {
        (peer_b, peer_a)
    };
    let mut info = Vec::with_capacity(16 + 8 + 64);
    info.extend_from_slice(b"chrono-dcnet-pair-v1");
    info.extend_from_slice(&round_id.to_be_bytes());
    info.extend_from_slice(lo);
    info.extend_from_slice(hi);

    let hk = Hkdf::<Sha256>::new(None, edge_key);
    let mut out = Vec::with_capacity(len);
    let mut block: u8 = 0;
    while out.len() < len {
        let mut info_block = info.clone();
        info_block.push(block);
        let mut okm = [0u8; 32];
        hk.expand(&info_block, &mut okm)
            .expect("32-byte HKDF output is always valid");
        out.extend_from_slice(&okm);
        block += 1;
    }
    out.truncate(len);
    out
}

pub fn generate_share() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_xor_symmetry() {
        let a = b"hello";
        let b = b"world";
        let ab = xor_bytes(a, b);
        assert_eq!(&xor_bytes(&ab, a)[..5], b);
    }
    #[test]
    fn test_participant_penalize() {
        let mut p = Participant::new([0u8; 32]);
        p.penalize();
        p.penalize();
        p.penalize();
        assert!(p.is_malicious());
    }
    #[test]
    fn test_dcnet_round_simple() {
        let share_ab = generate_share();
        let share_bc = generate_share();
        let share_ca = generate_share();
        let msg_a = b"secret message";
        let a_broadcast = xor_bytes(&xor_bytes(msg_a, &share_ab), &share_ca);
        let b_broadcast = xor_bytes(&share_ab, &share_bc);
        let c_broadcast = xor_bytes(&share_bc, &share_ca);
        let result = xor_bytes(&xor_bytes(&a_broadcast, &b_broadcast), &c_broadcast);
        assert_eq!(&result[..msg_a.len()], msg_a);
    }

    #[test]
    fn test_derive_pair_share_symmetry_and_independence() {
        let key = [7u8; 32];
        let a = [1u8; 32];
        let b = [2u8; 32];

        // Both peers derive identical bytes regardless of argument order.
        let s1 = derive_pair_share(&key, 5, &a, &b, 100);
        let s2 = derive_pair_share(&key, 5, &b, &a, 100);
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 100);

        // Round separation: a different round id must yield a different share.
        let s3 = derive_pair_share(&key, 6, &a, &b, 100);
        assert_ne!(s1, s3);

        // Key separation: a different edge key must yield a different share.
        let s4 = derive_pair_share(&[8u8; 32], 5, &a, &b, 100);
        assert_ne!(s1, s4);

        // Peer separation: sharing with a different peer differs.
        let s5 = derive_pair_share(&key, 5, &a, &[3u8; 32], 100);
        assert_ne!(s1, s5);
    }
}
