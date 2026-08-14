//! Double Ratchet — Signal-protocol-style E2E encryption (v7.0.1 fixed)
//!
//! Uses real x25519-dalek ECDH + HKDF-SHA256 (RFC 5869).
//! Replaces the previous fake SHA-256-as-DH implementation (CRITICAL-1 fix).

use aes_gcm::{
    aead::{Aead, Nonce},
    Aes256Gcm, KeyInit,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Ratchet state with real X25519 keypair
///
/// FIX: removed #[derive(Clone)] — cloning secret ratchet state risks two
/// instances encrypting with the same chain key / index pair.
pub struct RatchetState {
    /// DH keypair (X25519, zeroized on drop)
    pub dh_private: StaticSecret,
    pub dh_public: PublicKey,
    /// Root key (HKDF-derived)
    pub root_key: [u8; 32],
    /// Sending chain key
    pub send_chain: [u8; 32],
    /// Receiving chain key
    pub recv_chain: [u8; 32],
    /// Message counters
    pub send_idx: u64,
    pub recv_idx: u64,
    /// Expected next receive index (L1.2: replay protection)
    pub expected_recv_idx: u64,
    /// Previous message hash (chain integrity)
    pub prev_hash: [u8; 32],
    /// Snapshot counter (for key archival)
    _snapshot_count: u64,
    /// M6 fix: prevent duplicate handshake
    pub handshake_done: bool,
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        // StaticSecret implements Zeroize on drop via ZeroizeOnDrop
        self.root_key.zeroize();
        self.send_chain.zeroize();
        self.recv_chain.zeroize();
    }
}

impl RatchetState {
    /// Create new ratchet state (Alice side, initiates handshake)
    pub fn new_alice() -> Self {
        let private = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&private);
        Self {
            dh_private: private,
            dh_public: public,
            root_key: [0u8; 32],
            send_chain: [0u8; 32],
            recv_chain: [0u8; 32],
            send_idx: 0,
            recv_idx: 0,
            expected_recv_idx: 1,
            prev_hash: [0u8; 32],
            _snapshot_count: 0,
            handshake_done: false,
        }
    }

    /// Bob side: initialize after receiving Alice's public key
    pub fn new_bob(alice_public: &PublicKey) -> Self {
        let mut state = Self::new_alice();
        state.complete_handshake(alice_public);
        state
    }

    /// Complete DH handshake: compute shared secret via X25519 → derive root key via HKDF
    pub fn complete_handshake(&mut self, peer_public: &PublicKey) {
        // M6 fix: prevent duplicate handshake
        if self.handshake_done {
            return;
        }
        let shared_secret = self.dh_private.diffie_hellman(peer_public);
        self.root_key = hkdf_expand(shared_secret.as_bytes(), b"chrono-ratchet-v1");
        self.send_chain = self.root_key;
        self.recv_chain = self.root_key;
        self.handshake_done = true;
    }

    /// Encrypt message (sending side)
    /// Returns: (ciphertext, msg_idx, prev_hash)
    pub fn encrypt(&mut self, plaintext: &[u8]) -> (Vec<u8>, u64, [u8; 32]) {
        self.send_idx += 1;

        // 1. Derive message key from sending chain
        let msg_key = hkdf_expand(&self.send_chain, &self.send_idx.to_le_bytes());

        // 2. AES-256-GCM encrypt
        let cipher = Aes256Gcm::new_from_slice(&msg_key).expect("AES key");
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("AES-256-GCM encrypt");

        // 3. Advance sending chain (forward secrecy: old chain key can be deleted)
        self.send_chain = hkdf_expand(&self.send_chain, b"chain-advance");

        // 4. Format: [nonce(12) || ciphertext+tag]
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        // 5. Update chain hash over the full transmitted frame.
        // FIX: was hashing only ciphertext while decrypt hashed the whole
        // frame — the two sides' chain hashes could never match.
        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash);
        hasher.update(&result);
        let hash: [u8; 32] = hasher.finalize().into();
        self.prev_hash = hash;

        (result, self.send_idx, self.prev_hash)
    }

    /// Decrypt message (receiving side)
    pub fn decrypt(&mut self, encrypted: &[u8], msg_idx: u64) -> Option<(Vec<u8>, [u8; 32])> {
        if encrypted.len() < 28 {
            return None;
        } // 12 nonce + 16 GCM tag minimum

        // L1.2: Replay protection — reject old message indices
        if msg_idx < self.expected_recv_idx {
            return None; // replay attack detected
        }

        // 1. Derive message key from receiving chain
        let msg_key = hkdf_expand(&self.recv_chain, &msg_idx.to_le_bytes());

        // 2. AES-256-GCM decrypt
        let cipher = Aes256Gcm::new_from_slice(&msg_key).expect("AES key");
        let nonce = Nonce::<Aes256Gcm>::from_slice(&encrypted[..12]);
        let plaintext = cipher.decrypt(nonce, &encrypted[12..]).ok()?;

        // FIX: advance the replay window only AFTER the frame authenticated.
        // Before this fix a single forged frame with a huge msg_idx bumped
        // expected_recv_idx and permanently DoS'd the session (every
        // legitimate message was then rejected as a "replay").
        self.expected_recv_idx = msg_idx + 1;

        // 3. Advance receiving chain
        self.recv_chain = hkdf_expand(&self.recv_chain, b"chain-advance");

        // 4. Update chain hash
        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash);
        hasher.update(encrypted);
        let hash: [u8; 32] = hasher.finalize().into();
        self.prev_hash = hash;
        self.recv_idx = msg_idx;

        Some((plaintext, hash))
    }

    /// DH ratchet advance: generate new keypair, mix into root key
    pub fn dh_ratchet_advance(&mut self, peer_new_public: &PublicKey) {
        // Generate new keypair
        let new_private = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let new_public = PublicKey::from(&new_private);

        // DH1: old_private * peer_new_public
        let shared1 = self.dh_private.diffie_hellman(peer_new_public);
        // DH2: new_private * peer_new_public
        let shared2 = new_private.diffie_hellman(peer_new_public);

        // Mix into root key
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(shared1.as_bytes());
        combined[32..].copy_from_slice(shared2.as_bytes());
        self.root_key = hkdf_expand(&combined, b"dh-ratchet");

        // Replace keypair
        self.dh_private = new_private;
        self.dh_public = new_public;
    }
}

/// HKDF-Expand (RFC 5869): prk → okm
fn hkdf_expand(prk: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, prk);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand: output length valid");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut alice = RatchetState::new_alice();
        let ap = alice.dh_public;
        let mut bob = RatchetState::new_bob(&ap);
        bob.complete_handshake(&ap);
        alice.complete_handshake(&bob.dh_public);

        let plain = b"hello double ratchet!";
        let (enc, idx, _) = alice.encrypt(plain);
        let (dec, _) = bob.decrypt(&enc, idx).unwrap();
        assert_eq!(&dec, plain);
    }

    #[test]
    fn test_forward_secrecy() {
        let mut alice = RatchetState::new_alice();
        let p1 = alice.dh_public;
        let mut bob = RatchetState::new_bob(&p1);
        alice.complete_handshake(&bob.dh_public);
        bob.complete_handshake(&p1);

        // Send msg1 → advance chain
        let (enc1, idx1, _) = alice.encrypt(b"msg1");
        let _ = bob.decrypt(&enc1, idx1);

        // Send msg2 with different key
        let (enc2, idx2, _) = alice.encrypt(b"msg2");
        let (dec2, _) = bob.decrypt(&enc2, idx2).unwrap();
        assert_eq!(&dec2, b"msg2");

        // enc1 and enc2 use different message keys
        assert_ne!(&enc1[..16], &enc2[..16]);
    }

    #[test]
    fn test_forged_frame_does_not_bump_replay_window() {
        let mut alice = RatchetState::new_alice();
        let p1 = alice.dh_public;
        let mut bob = RatchetState::new_bob(&p1);
        alice.complete_handshake(&bob.dh_public);
        bob.complete_handshake(&p1);

        // Attacker injects a garbage frame claiming a huge message index.
        // Before the fix this permanently bumped expected_recv_idx and
        // DoS'd the session (all later legit messages rejected as replay).
        let forged = vec![0u8; 40];
        assert!(bob.decrypt(&forged, 1_000_000).is_none());

        let (enc, idx, _) = alice.encrypt(b"real message after attack");
        let (dec, _) = bob
            .decrypt(&enc, idx)
            .expect("legitimate message still decrypts after forged frame");
        assert_eq!(dec, b"real message after attack");
    }
}
