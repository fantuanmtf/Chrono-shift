//! AES-256-GCM crypto (OsRng, FIPS 140-2)
use aes_gcm::{
    aead::{Aead, Nonce},
    Aes256Gcm, KeyInit,
};
use rand::RngCore;
use sha2::{Digest, Sha256 as Sha256Hasher};
use zeroize::Zeroize;

pub fn encrypt_e2e(plaintext: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).ok()?;
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Some(result)
}

pub fn decrypt_e2e(encrypted: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if encrypted.len() < 28 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::<Aes256Gcm>::from_slice(&encrypted[..12]);
    cipher.decrypt(nonce, &encrypted[12..]).ok()
}

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

pub fn generate_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

pub fn secure_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // CRITICAL-3 fix: use black_box to prevent compiler from optimizing away
    // the constant-time comparison. Always compare min_len bytes, never early-return.
    let min_len = a.len().min(b.len());
    let same_len = a.len() == b.len();
    let mut diff = 0u8;
    for i in 0..min_len {
        diff |= a[i] ^ b[i];
    }
    // Prevent compiler optimization: force the comparison result
    let result = diff == 0 && same_len;
    std::hint::black_box(result)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256Hasher::new();
    h.update(data);
    h.finalize().into()
}

/// HKDF-Expand (RFC 5869): PRK + info → 32-byte key.
pub fn hkdf_expand32(prk: &[u8], info: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    let hk = Hkdf::<sha2::Sha256>::new(None, prk);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32-byte OKM is always within HKDF limits");
    okm
}

/// Derive a session master key from an X25519 shared secret plus both
/// ephemeral public keys. The two public keys are sorted before use, so
/// both peers compute the same value regardless of role.
pub fn derive_session_key(
    shared_secret: &[u8; 32],
    eph_a: &[u8; 32],
    eph_b: &[u8; 32],
) -> [u8; 32] {
    use hkdf::Hkdf;
    let (lo, hi) = if eph_a < eph_b {
        (eph_a, eph_b)
    } else {
        (eph_b, eph_a)
    };
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(lo);
    salt[32..].copy_from_slice(hi);
    let hk = Hkdf::<sha2::Sha256>::new(Some(&salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"chrono-session-v1", &mut okm)
        .expect("32-byte OKM is always within HKDF limits");
    okm
}

pub fn secure_clear(data: &mut [u8]) {
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plain = b"Hello, Chrono-shift E2E test!";
        let enc = encrypt_e2e(plain, &key).unwrap();
        let dec = decrypt_e2e(&enc, &key).unwrap();
        assert_eq!(plain.as_slice(), dec.as_slice());
    }
    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
    }
}
