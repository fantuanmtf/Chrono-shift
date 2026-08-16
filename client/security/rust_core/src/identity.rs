//! Identity management — Ed25519 keypair generation, fingerprint, persistence (v7.1 S1)
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Write private key material to a file that is only readable by the owner.
///
/// FIX (audit HIGH): load_or_generate used to write identity.json with
/// default umask permissions (0644 on typical systems), leaving the private
/// key world-readable. This helper creates the file with mode 0600 on Unix
/// from the moment of creation (no chmod-after-write TOCTOU window) and
/// fsyncs the contents before returning.
pub(crate) fn write_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut file = {
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path)?
    };
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    // Re-assert owner-only permissions after the write, so a pre-existing
    // 0644 file is repaired even if it was not created by us (also covers any
    // rename/truncate path that could drop the mode).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// User identity with Ed25519 keypair (HIGH-1/2: Drop zeroizes + file permissions)
#[derive(Deserialize)]
pub struct Identity {
    pub uid: String,
    /// Ed25519 secret key (32 bytes, hex-encoded) — zeroized on Drop
    secret_hex: String,
    /// Ed25519 public key (32 bytes, hex-encoded)
    public_hex: String,
    /// Unix timestamp of creation
    pub created: u64,
}

impl Drop for Identity {
    fn drop(&mut self) {
        // HIGH-2 fix: zeroize private key hex on drop
        unsafe {
            for b in self.secret_hex.as_bytes_mut() {
                *b = 0;
            }
        }
    }
}

impl Identity {
    /// Generate a new identity with a fresh Ed25519 keypair
    pub fn generate(uid: &str) -> Self {
        // Zeroizing so the 32 raw seed bytes are wiped once the key is built.
        let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            uid: uid.to_string(),
            secret_hex: hex_encode(signing_key.as_bytes()),
            public_hex: hex_encode(verifying_key.as_bytes()),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Load identity from file, or generate if not exists
    pub fn load_or_generate(data_dir: &Path, uid: &str) -> Self {
        let keys_dir = data_dir.join("keys");
        fs::create_dir_all(&keys_dir).ok();
        // Best-effort: keep the keys directory owner-only too.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&keys_dir, fs::Permissions::from_mode(0o700));
        }
        let path = keys_dir.join("identity.json");

        if let Ok(json) = fs::read_to_string(&path) {
            if let Ok(id) = serde_json::from_str::<Identity>(&json) {
                return id;
            }
        }

        let id = Self::generate(uid);
        // Hand-built JSON: Identity is intentionally NOT Serialize so the
        // secret key cannot be accidentally serialized elsewhere.
        let value = serde_json::json!({
            "uid": id.uid,
            "secret_hex": id.secret_hex,
            "public_hex": id.public_hex,
            "created": id.created,
        });
        if let Ok(json) = serde_json::to_string_pretty(&value) {
            // FIX: create with mode 0600 from the start (was fs::write → 0644)
            let _ = write_private_file(&path, &json);
        }
        id
    }

    /// Save identity to file (HIGH-1: writes with owner-only permissions)
    pub fn save(&self, data_dir: &Path) {
        let keys_dir = data_dir.join("keys");
        fs::create_dir_all(&keys_dir).ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&keys_dir, fs::Permissions::from_mode(0o700));
        }
        let path = keys_dir.join("identity.json");
        // Hand-built JSON: Identity deliberately does NOT derive Serialize, so
        // the secret key can only be persisted here (never logged or sent).
        let value = serde_json::json!({
            "uid": self.uid,
            "secret_hex": self.secret_hex,
            "public_hex": self.public_hex,
            "created": self.created,
        });
        if let Ok(json) = serde_json::to_string_pretty(&value) {
            // FIX: single atomic-ish write with 0600 at creation time,
            // no chmod-after-write window.
            let _ = write_private_file(&path, &json);
        }
    }

    /// Get the verifying (public) key
    pub fn public_key(&self) -> Option<VerifyingKey> {
        let bytes = zeroize::Zeroizing::new(hex_decode(&self.public_hex)?);
        let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
        VerifyingKey::from_bytes(&arr).ok()
    }

    /// Get the signing (secret) key
    pub fn signing_key(&self) -> Option<SigningKey> {
        // Zeroizing so the temporary decoded secret bytes are wiped on drop.
        let bytes = zeroize::Zeroizing::new(hex_decode(&self.secret_hex)?);
        let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
        Some(SigningKey::from_bytes(&arr))
    }

    /// Sign a message with the identity's secret key
    pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        use ed25519_dalek::Signer;
        let sk = self.signing_key()?;
        Some(sk.sign(message).to_vec())
    }

    /// SHA-256 fingerprint of the public key (for human verification)
    /// Get the public key hex
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_of_public_hex(&self.public_hex)
    }

    /// Display public key in compact hex
    pub fn public_hex_short(&self) -> String {
        let h = &self.public_hex;
        // FIX: guard against tampered/truncated hex (was: unconditional
        // slicing would panic on short keys loaded from disk)
        if h.len() < 8 || !h.is_ascii() {
            return h.to_string();
        }
        format!("{}...{}", &h[..8], &h[h.len() - 8..])
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// SHA-256 fingerprint of a public key (hex), formatted like
/// Identity::fingerprint — usable for imported keys without a secret key.
pub fn fingerprint_of_public_hex(public_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update(public_hex);
    let hash: [u8; 32] = h.finalize().into();
    // Format: FC89 B3A1 2D4E ... (8 groups of 4)
    let hex = hex_encode(&hash);
    hex.as_bytes()
        .chunks(4)
        .take(8)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
}

pub(crate) fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    // FIX: reject odd-length / non-ASCII input instead of panicking on
    // slice boundaries or char misalignment (was: &hex[i..i+2] could panic
    // on tampered identity files).
    if hex.len() % 2 != 0 || !hex.is_ascii() {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_fingerprint() {
        let id = Identity::generate("alice");
        assert_eq!(id.uid, "alice");
        assert!(!id.fingerprint().is_empty());
        assert!(id.public_key().is_some());
        assert!(id.signing_key().is_some());
    }

    #[test]
    fn test_sign_and_verify() {
        use ed25519_dalek::Verifier;
        let id = Identity::generate("bob");
        let msg = b"test message";
        let sig = id.sign(msg).unwrap();
        let vk = id.public_key().unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        assert!(vk.verify(msg, &signature).is_ok());
    }

    #[test]
    fn test_save_and_load() {
        let tmp = std::env::temp_dir().join("chrono_test_id");
        std::fs::create_dir_all(&tmp).ok();
        let id = Identity::generate("carol");
        id.save(&tmp);
        let loaded = Identity::load_or_generate(&tmp, "carol");
        assert_eq!(loaded.public_hex, id.public_hex);
        assert_eq!(loaded.fingerprint(), id.fingerprint());
        std::fs::remove_dir_all(tmp).ok();
    }

    #[test]
    #[cfg(unix)]
    fn test_write_private_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join("chrono_test_id_perm");
        std::fs::create_dir_all(&tmp).ok();
        let path = tmp.join("identity.json");

        // New file must be created 0600.
        write_private_file(&path, "{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new private file must be 0600, got {mode:o}");

        // A pre-existing 0644 file must be repaired to 0600.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&path, "{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "existing 0644 file must be repaired, got {mode:o}"
        );

        std::fs::remove_dir_all(tmp).ok();
    }
}
