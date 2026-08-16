//! Authenticated session establishment (security fix)
//!
//! Replaces the previous plaintext-JSON-over-TCP path with:
//!   1. X25519 ephemeral ECDH handshake (AuthChallenge / AuthResponse)
//!   2. Ed25519 signatures binding the ephemeral keys to identity keys
//!   3. per-direction AES-256-GCM keys derived via HKDF (anti-reflection)
//!   4. per-direction monotonic sequence counters (anti-replay)
//!
//! Handshake (plaintext frames, JSON PeerMessage):
//!   initiator → AuthChallenge { eph_pub, nonce, sig = Sign(eph_pub || nonce) }
//!   responder → AuthResponse { eph_pub, sig = Sign(chal_eph || resp_eph || nonce) }
//!   session   = HKDF(X25519(eph_sec_i, eph_pub_r), info)
//!   dir-a/dir-b = HKDF(session); initiator sends with dir-a, responder with
//!   dir-b — a reflected copy of our own frames cannot decrypt/verify.

use crate::crypto;
use crate::identity::{hex_decode, hex_encode};
use crate::net::tcp::PeerMessage;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Maximum frame size accepted on the wire (handshake + data frames).
const MAX_FRAME: usize = 65536;

/// Identity material needed to authenticate our side of a session.
pub struct SessionAuth {
    pub uid: String,
    pub public_hex: String,
    pub signing_key: SigningKey,
}

/// Established session keys + peer identity info.
pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub peer_uid: String,
    /// The peer's claimed Ed25519 identity public key (hex). Recorded via
    /// TOFU (trust-on-first-use) by the connection manager so later
    /// per-message signatures (DC-Net shares, relay traffic) can verify.
    pub peer_public_hex: String,
    /// True when the peer's handshake signature verified against a key we know.
    pub peer_authenticated: bool,
}

enum PeerSigCheck {
    Verified,
    Unverified,
    Rejected,
}

/// Verify a peer's handshake signature against the key we have on record.
///
/// - no record for the uid          → Unverified (encrypt, but don't trust)
/// - record exists but key differs  → Rejected (impersonation of a known peer)
/// - record key parses and verifies → Verified
/// - record key is not a valid Ed25519 key → Unverified (can't verify)
fn check_peer_sig(
    known_keys: &Mutex<HashMap<String, String>>,
    uid: &str,
    claimed_key_hex: &str,
    msg: &[u8],
    sig: &[u8],
) -> PeerSigCheck {
    let expected = match known_keys.lock() {
        Ok(map) => match map.get(uid) {
            Some(k) => k.clone(),
            None => return PeerSigCheck::Unverified,
        },
        Err(_) => return PeerSigCheck::Unverified,
    };
    if expected != claimed_key_hex {
        return PeerSigCheck::Rejected;
    }
    let vk = match hex_decode(&expected)
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
    {
        Some(vk) => vk,
        None => return PeerSigCheck::Unverified,
    };
    match Signature::from_slice(sig) {
        Ok(s) if vk.verify(msg, &s).is_ok() => PeerSigCheck::Verified,
        _ => PeerSigCheck::Rejected,
    }
}

fn hex_to_32(hex: &str) -> io::Result<[u8; 32]> {
    let bytes =
        hex_decode(hex).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad hex"))?;
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad key length"))
}

/// Derive the X25519 shared secret, rejecting non-contributory peer
/// ephemeral keys (all-zero / low-order points). x25519-dalek 2.x marks such
/// secrets via `SharedSecret::was_contributory()`; using one would let an
/// attacker force a predictable session key.
fn derive_shared(secret: &StaticSecret, peer_eph: &[u8; 32]) -> io::Result<SharedSecret> {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_eph));
    if !shared.was_contributory() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer ephemeral key is not contributory (low-order point)",
        ));
    }
    Ok(shared)
}

/// Send a JSON PeerMessage as a length-prefixed frame (handshake only).
async fn send_json<S: AsyncWrite + Unpin>(stream: &mut S, msg: &PeerMessage) -> io::Result<()> {
    let payload = msg.to_json().into_bytes();
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

/// Receive a JSON PeerMessage frame (handshake only).
async fn recv_json<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<PeerMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let text = String::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 frame"))?;
    PeerMessage::from_json(&text)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad JSON frame"))
}

/// Initiator side of the session handshake.
pub async fn outbound_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    auth: &SessionAuth,
    known_keys: &Mutex<HashMap<String, String>>,
) -> io::Result<SessionKeys> {
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    // Sign (eph_pub || nonce) with our identity key.
    let mut challenge_msg = Vec::with_capacity(64);
    challenge_msg.extend_from_slice(eph_pub.as_bytes());
    challenge_msg.extend_from_slice(&nonce);
    let challenge_sig = auth.signing_key.sign(&challenge_msg).to_vec();

    send_json(
        stream,
        &PeerMessage::AuthChallenge {
            from_uid: auth.uid.clone(),
            public_key_hex: auth.public_hex.clone(),
            eph_pub_hex: hex_encode(eph_pub.as_bytes()),
            nonce: nonce.to_vec(),
            signature: challenge_sig,
        },
    )
    .await?;

    let resp = recv_json(stream).await?;
    let (resp_uid, resp_key_hex, resp_eph_hex, resp_sig) = match resp {
        PeerMessage::AuthResponse {
            from_uid,
            public_key_hex,
            eph_pub_hex,
            signature,
        } => (from_uid, public_key_hex, eph_pub_hex, signature),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected auth_response",
            ))
        }
    };
    if !crate::validate_uid(&resp_uid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid responder uid",
        ));
    }
    let resp_eph = hex_to_32(&resp_eph_hex)?;

    // Verify responder signature over (chal_eph || resp_eph || nonce).
    let mut resp_msg = Vec::with_capacity(96);
    resp_msg.extend_from_slice(eph_pub.as_bytes());
    resp_msg.extend_from_slice(&resp_eph);
    resp_msg.extend_from_slice(&nonce);
    let peer_authenticated =
        match check_peer_sig(known_keys, &resp_uid, &resp_key_hex, &resp_msg, &resp_sig) {
            PeerSigCheck::Verified => true,
            PeerSigCheck::Unverified => {
                log::warn!(
                    "Peer {} not in known keys — session encrypted but unauthenticated",
                    resp_uid
                );
                false
            }
            PeerSigCheck::Rejected => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("peer {} failed handshake signature check", resp_uid),
                ))
            }
        };

    let shared = derive_shared(&eph_secret, &resp_eph)?;
    let master = crypto::derive_session_key(shared.as_bytes(), eph_pub.as_bytes(), &resp_eph);
    let dir_a = crypto::hkdf_expand32(&master, b"chrono-dir-a");
    let dir_b = crypto::hkdf_expand32(&master, b"chrono-dir-b");

    Ok(SessionKeys {
        send_key: dir_a,
        recv_key: dir_b,
        peer_uid: resp_uid,
        peer_public_hex: resp_key_hex,
        peer_authenticated,
    })
}

/// Responder side of the session handshake.
pub async fn inbound_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    auth: &SessionAuth,
    known_keys: &Mutex<HashMap<String, String>>,
) -> io::Result<SessionKeys> {
    let chal = recv_json(stream).await?;
    let (chal_uid, chal_key_hex, chal_eph_hex, chal_nonce, chal_sig) = match chal {
        PeerMessage::AuthChallenge {
            from_uid,
            public_key_hex,
            eph_pub_hex,
            nonce,
            signature,
        } => (from_uid, public_key_hex, eph_pub_hex, nonce, signature),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected auth_challenge",
            ))
        }
    };
    if !crate::validate_uid(&chal_uid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid challenger uid",
        ));
    }
    let chal_eph = hex_to_32(&chal_eph_hex)?;

    // Verify the challenge signature over (eph_pub || nonce).
    let mut chal_msg = Vec::with_capacity(64);
    chal_msg.extend_from_slice(&chal_eph);
    chal_msg.extend_from_slice(&chal_nonce);
    let peer_authenticated =
        match check_peer_sig(known_keys, &chal_uid, &chal_key_hex, &chal_msg, &chal_sig) {
            PeerSigCheck::Verified => true,
            PeerSigCheck::Unverified => {
                log::warn!(
                    "Peer {} not in known keys — session encrypted but unauthenticated",
                    chal_uid
                );
                false
            }
            PeerSigCheck::Rejected => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("peer {} failed handshake signature check", chal_uid),
                ))
            }
        };

    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);

    // Sign (chal_eph || resp_eph || nonce) with our identity key.
    let mut resp_msg = Vec::with_capacity(96);
    resp_msg.extend_from_slice(&chal_eph);
    resp_msg.extend_from_slice(eph_pub.as_bytes());
    resp_msg.extend_from_slice(&chal_nonce);
    let resp_sig = auth.signing_key.sign(&resp_msg).to_vec();

    send_json(
        stream,
        &PeerMessage::AuthResponse {
            from_uid: auth.uid.clone(),
            public_key_hex: auth.public_hex.clone(),
            eph_pub_hex: hex_encode(eph_pub.as_bytes()),
            signature: resp_sig,
        },
    )
    .await?;

    let shared = derive_shared(&eph_secret, &chal_eph)?;
    let master = crypto::derive_session_key(shared.as_bytes(), &chal_eph, eph_pub.as_bytes());
    let dir_a = crypto::hkdf_expand32(&master, b"chrono-dir-a");
    let dir_b = crypto::hkdf_expand32(&master, b"chrono-dir-b");

    Ok(SessionKeys {
        send_key: dir_b,
        recv_key: dir_a,
        peer_uid: chal_uid,
        peer_public_hex: chal_key_hex,
        peer_authenticated,
    })
}

/// Send one authenticated-encrypted frame: [len][AES-GCM(nonce || seq || payload)].
pub async fn send_secure_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
    key: &[u8; 32],
    seq: &mut u64,
) -> io::Result<()> {
    // Sequences start at 1 so the first frame is never mistaken for a
    // replay (receivers initialize last_seq to 0).
    *seq += 1;
    let mut plain = Vec::with_capacity(8 + payload.len());
    plain.extend_from_slice(&seq.to_be_bytes());
    plain.extend_from_slice(payload);
    let enc = crypto::encrypt_e2e(&plain, key).ok_or_else(|| io::Error::other("encrypt failed"))?;
    let len = (enc.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&enc).await?;
    Ok(())
}

/// Receive one authenticated-encrypted frame, rejecting replays.
pub async fn recv_secure_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    key: &[u8; 32],
    last_seq: &mut u64,
) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut enc = vec![0u8; len];
    stream.read_exact(&mut enc).await?;
    let plain = crypto::decrypt_e2e(&enc, key)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "decrypt/authenticate failed"))?;
    if plain.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short frame"));
    }
    let seq = u64::from_be_bytes(plain[..8].try_into().expect("8 bytes"));
    if seq <= *last_seq {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "replayed frame"));
    }
    *last_seq = seq;
    Ok(plain[8..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};

    fn auth_for(uid: &str) -> SessionAuth {
        let id = Identity::generate(uid);
        SessionAuth {
            uid: uid.to_string(),
            public_hex: id.public_hex().to_string(),
            signing_key: id.signing_key().expect("signing key"),
        }
    }

    #[tokio::test]
    async fn test_handshake_and_secure_roundtrip() {
        let alice = auth_for("alice");
        let bob = auth_for("bob");
        let known: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
        {
            known
                .lock()
                .unwrap()
                .insert("alice".into(), alice.public_hex.clone());
            known
                .lock()
                .unwrap()
                .insert("bob".into(), bob.public_hex.clone());
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (mut a_stream, mut b_stream) = {
            let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
            let client = TcpStream::connect(addr).await.unwrap();
            (client, server.await.unwrap())
        };

        // Run both handshakes concurrently.
        let a_fut = outbound_handshake(&mut a_stream, &alice, &known);
        let b_fut = inbound_handshake(&mut b_stream, &bob, &known);
        let (a_keys, b_keys) = tokio::join!(a_fut, b_fut);
        let a_keys = a_keys.expect("alice handshake");
        let b_keys = b_keys.expect("bob handshake");

        assert!(a_keys.peer_authenticated);
        assert!(b_keys.peer_authenticated);
        assert_eq!(a_keys.peer_uid, "bob");
        assert_eq!(b_keys.peer_uid, "alice");
        // Cross-direction keys must match.
        assert_eq!(a_keys.send_key, b_keys.recv_key);
        assert_eq!(a_keys.recv_key, b_keys.send_key);

        // Alice → Bob
        let mut a_seq = 0u64;
        let mut b_last = 0u64;
        send_secure_frame(&mut a_stream, b"hello bob", &a_keys.send_key, &mut a_seq)
            .await
            .unwrap();
        let msg = recv_secure_frame(&mut b_stream, &b_keys.recv_key, &mut b_last)
            .await
            .unwrap();
        assert_eq!(msg, b"hello bob");

        // Bob → Alice
        let mut b_seq = 0u64;
        let mut a_last = 0u64;
        send_secure_frame(&mut b_stream, b"hello alice", &b_keys.send_key, &mut b_seq)
            .await
            .unwrap();
        let msg = recv_secure_frame(&mut a_stream, &a_keys.recv_key, &mut a_last)
            .await
            .unwrap();
        assert_eq!(msg, b"hello alice");
    }

    #[tokio::test]
    async fn test_known_peer_impersonation_rejected() {
        let alice = auth_for("alice");
        let mut mallory = auth_for("mallory"); // attacker
        mallory.uid = "alice".into(); // claims to be alice, with her own key
        let known: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
        known
            .lock()
            .unwrap()
            .insert("alice".into(), alice.public_hex.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (mut a_stream, mut b_stream) = {
            let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
            let client = TcpStream::connect(addr).await.unwrap();
            (client, server.await.unwrap())
        };

        // Mallory claims to be alice (with her own key) — must be rejected.
        // Bob fails the handshake and never replies, so Mallory's side just
        // waits; bound both futures with a timeout.
        let a_fut = outbound_handshake(&mut a_stream, &mallory, &known);
        let b_fut = inbound_handshake(&mut b_stream, &alice, &known);
        let (a_res, b_res) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(2), a_fut),
            tokio::time::timeout(Duration::from_secs(2), b_fut),
        );
        // Bob (the verifier) must reject the forged identity.
        if let Ok(Ok(_)) = b_res {
            panic!("bob accepted impersonation");
        }
        // Mallory must never end up with a working session.
        if let Ok(Ok(_)) = a_res {
            panic!("impersonator obtained a session");
        }
    }

    #[test]
    fn test_low_order_point_rejected() {
        // An all-zero public key is a low-order point: the resulting shared
        // secret is non-contributory, and our guard must reject it so an
        // attacker can't force a predictable session key.
        let secret = StaticSecret::random_from_rng(OsRng);
        let shared = secret.diffie_hellman(&PublicKey::from([0u8; 32]));
        assert!(!shared.was_contributory());
        assert!(derive_shared(&secret, &[0u8; 32]).is_err());
    }
}
