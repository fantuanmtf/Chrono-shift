//! Dissent Verifiable Shuffle (CRITICAL-3 fixed: AES-256-GCM replaces XOR-with-discarded-key)
use aes_gcm::{
    aead::{Aead, Nonce},
    Aes256Gcm, KeyInit,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Shuffle slot — encrypted message + commitment (HIGH-3: key separated)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShuffleSlot {
    pub index: u16,
    pub ciphertext: Vec<u8>, // AES-256-GCM(nonce || ciphertext || tag)
    pub commitment: Vec<u8>, // SHA-256(plaintext) — for verification after reveal
    pub node_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShuffleCommitment {
    pub round_id: u64,
    pub node_count: u16,
    pub slots: Vec<ShuffleSlot>,
    pub merkle_root: Vec<u8>,
    /// HIGH-3 fix: decryption keys stored locally, NOT transmitted with slots
    #[serde(skip)]
    slot_keys: std::collections::HashMap<u16, [u8; 32]>,
}

impl ShuffleCommitment {
    pub fn new(round_id: u64, node_count: u16) -> Self {
        Self {
            round_id,
            node_count,
            slots: Vec::with_capacity(node_count as usize),
            merkle_root: vec![0u8; 32],
            slot_keys: std::collections::HashMap::new(),
        }
    }

    /// Submit encrypted message to a slot. Key is stored for later reveal.
    pub fn submit(&mut self, node_id: &[u8], message: &[u8]) -> ShuffleSlot {
        let idx = self.slots.len() as u16;

        // Commitment: SHA-256(plaintext)
        let mut h = Sha256::new();
        h.update(message);
        let commitment = h.finalize().to_vec();

        // AES-256-GCM encrypt (key stored in slot for later reveal)
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 key");
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, message).expect("AES-256-GCM encrypt");
        // Format: [nonce(12) || ciphertext+tag]
        let mut ciphertext = Vec::with_capacity(12 + ct.len());
        ciphertext.extend_from_slice(&nonce_bytes);
        ciphertext.extend_from_slice(&ct);

        // HIGH-3: store key locally, NOT in the serialized slot
        self.slot_keys.insert(idx, key);

        let slot = ShuffleSlot {
            index: idx,
            ciphertext,
            commitment,
            node_id: node_id.to_vec(),
        };
        self.slots.push(slot.clone());
        self.update_merkle_root();
        slot
    }

    /// Verify: SHA-256(plaintext) == commitment
    pub fn verify(&self, slot: &ShuffleSlot, plaintext: &[u8]) -> bool {
        let mut h = Sha256::new();
        h.update(plaintext);
        // Constant-time comparison
        let hash = h.finalize();
        crate::crypto::constant_time_eq(hash.as_slice(), &slot.commitment)
    }

    /// Decrypt a slot using locally-stored key (called during reveal phase, HIGH-3 fix)
    pub fn decrypt_slot(&self, slot: &ShuffleSlot) -> Option<Vec<u8>> {
        if slot.ciphertext.len() < 28 {
            return None;
        }
        let key_arr = self.slot_keys.get(&slot.index)?;
        let cipher = Aes256Gcm::new_from_slice(key_arr).ok()?;
        let nonce = Nonce::<Aes256Gcm>::from_slice(&slot.ciphertext[..12]);
        cipher.decrypt(nonce, &slot.ciphertext[12..]).ok()
    }

    /// Reveal decryption key for a slot (Leader calls this after collection)
    pub fn reveal_key(&self, index: u16) -> Option<&[u8; 32]> {
        self.slot_keys.get(&index)
    }

    /// Find cheater: decrypt all slots and verify commitments (HIGH-3: uses local keys)
    pub fn find_cheater(&self) -> Option<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(pt) = self.decrypt_slot(slot) {
                if !self.verify(slot, &pt) {
                    return Some(i);
                }
            } else {
                return Some(i); // undecryptable = cheating
            }
        }
        None
    }

    fn update_merkle_root(&mut self) {
        if self.slots.is_empty() {
            return;
        }
        let mut h = Sha256::new();
        for s in &self.slots {
            h.update(&s.commitment);
        }
        self.merkle_root = h.finalize().to_vec();
    }
}

/// Blame protocol verdict
#[derive(Debug)]
pub enum BlameVerdict {
    Offline { node_id: Vec<u8> },
    Cheating { node_id: Vec<u8>, slot: u16 },
    Clean,
}

pub struct BlameProtocol {
    pub round_id: u64,
}

impl BlameProtocol {
    pub fn new(round_id: u64) -> Self {
        Self { round_id }
    }
    pub fn check_attendance(&self, expected: &[Vec<u8>], actual: &[Vec<u8>]) -> Vec<BlameVerdict> {
        let mut v = Vec::new();
        for e in expected {
            if !actual.contains(e) {
                v.push(BlameVerdict::Offline { node_id: e.clone() });
            }
        }
        v
    }
    pub fn check_cheating(&self, commitment: &ShuffleCommitment) -> Vec<BlameVerdict> {
        let mut v = Vec::new();
        for (i, slot) in commitment.slots.iter().enumerate() {
            if let Some(pt) = commitment.decrypt_slot(slot) {
                if !commitment.verify(slot, &pt) {
                    v.push(BlameVerdict::Cheating {
                        node_id: slot.node_id.clone(),
                        slot: i as u16,
                    });
                }
            } else {
                v.push(BlameVerdict::Cheating {
                    node_id: slot.node_id.clone(),
                    slot: i as u16,
                });
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shuffle_commit_and_verify() {
        let mut sc = ShuffleCommitment::new(1, 3);
        let slot = sc.submit(&[1, 2, 3], b"test message");

        // Decrypt and verify (HIGH-3: uses local keys via instance method)
        let pt = sc.decrypt_slot(&slot).unwrap();
        assert!(sc.verify(&slot, &pt));
    }

    #[test]
    fn test_wrong_message_fails_verification() {
        let mut sc = ShuffleCommitment::new(1, 3);
        let slot = sc.submit(&[1, 2, 3], b"test message");
        let _pt = sc.decrypt_slot(&slot).unwrap();
        assert!(!sc.verify(&slot, b"wrong message"));
    }

    #[test]
    fn test_find_cheater() {
        let mut sc = ShuffleCommitment::new(1, 2);
        sc.submit(&[1], b"msg1");
        sc.submit(&[2], b"msg2");
        // All slots should verify
        assert_eq!(sc.find_cheater(), None);
    }

    #[test]
    fn test_blame_offline() {
        let bp = BlameProtocol::new(1);
        let expected = vec![vec![1u8], vec![2], vec![3]];
        let actual = vec![vec![1u8], vec![3]]; // node 2 is offline
        let v = bp.check_attendance(&expected, &actual);
        assert_eq!(v.len(), 1);
    }
}
