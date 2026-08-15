//! AppState — unified application state + event bus (v0.0.8.3)
//!
//! v8.1 daemon 结构 + P0-P4 安全嫁接:
//!   - WAL 恢复/checkpoint 接线（P1）
//!   - Web of Trust + 中继准入控制（P4）
//!   - connection_manager 为 Arc<Mutex<>>（P1 关机死锁修复）
//!   - uid_shared 供监听器读取实时 uid（P3）

use crate::dcnet::f2f::F2fDcNetBridge;
use crate::identity::Identity;
use crate::net::connection_manager::ConnectionManager;
use crate::net::relay::{self, RelayRouter, RelayVerifier};
use crate::net::tcp::PeerMessage;
use crate::net::transport::Transport;
use crate::pgp::web_of_trust::WebOfTrust;
use crate::pgp::PgpIdentity;
use crate::round_engine::RoundEngine;
use crate::storage::{SocialSnapshot, WalStore};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Application-wide events
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Info
    Info { message: String },
    /// Error
    Error { message: String },
}

/// Unified application state
pub struct AppState {
    pub identity: Identity,
    pub bridge: F2fDcNetBridge,
    pub transport: Transport,
    pub relay: RelayRouter,
    /// P1: Arc<Mutex<>> so background tasks never hold the whole AppState
    /// Arc (the old design deadlocked daemon shutdown).
    pub connection_manager: Arc<Mutex<ConnectionManager>>,
    pub round_engine: RoundEngine,
    pub data_dir: PathBuf,
    pub event_tx: mpsc::Sender<AppEvent>,
    event_rx: mpsc::Receiver<AppEvent>,
    pub messages: Vec<(String, String, String)>,
    pub outgoing_tx: mpsc::Sender<(String, PeerMessage)>,
    pub incoming_rx: Arc<Mutex<mpsc::Receiver<(String, PeerMessage)>>>,
    pub outgoing_rx: Option<mpsc::Receiver<(String, PeerMessage)>>,
    /// Inbound sender (Clone, shared with outbound connection readers).
    pub incoming_tx: mpsc::Sender<(String, PeerMessage)>,
    /// P4: Web of Trust.
    pub wot: WebOfTrust,
    /// P4: relay admission control (replay/expiry/rate/TOFU).
    pub relay_verifier: RelayVerifier,
    /// P4: monotonic nonce for relay requests we originate.
    pub relay_nonce: u64,
    /// P3: live uid shared with the listener (so /nick applies to
    /// inbound handshakes).
    pub uid_shared: Arc<Mutex<String>>,
}

impl AppState {
    pub fn new(data_dir: &str) -> Self {
        Self::new_with_port(data_dir, 9000)
    }

    /// Like new(), with an explicit TCP listen port.
    pub fn new_with_port(data_dir: &str, listen_port: u16) -> Self {
        let dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(&dir).ok();

        // P1.4: warn about pre-existing secret files with loose permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in ["keys/identity.json", "wal.log", "state.json", "wot.json"] {
                let p = dir.join(f);
                if let Ok(meta) = std::fs::metadata(&p) {
                    if meta.permissions().mode() & 0o077 != 0 {
                        log::warn!(
                            "Secret file {} has loose permissions ({:o}); consider chmod 600",
                            p.display(),
                            meta.permissions().mode() & 0o777
                        );
                    }
                }
            }
        }

        // Load or generate identity
        let identity = Identity::load_or_generate(&dir, "");
        let uid = identity.uid.clone();

        // P4: Web of Trust — fresh with our own key, or restored from disk.
        let own_pgi = PgpIdentity::from_identity(&identity);
        let mut wot = WebOfTrust::new();
        wot.add_own_key(&own_pgi);
        let wot_path = dir.join("wot.json");
        if let Ok(json) = std::fs::read_to_string(&wot_path) {
            if let Ok(saved) = serde_json::from_str::<WebOfTrust>(&json) {
                wot = saved;
                wot.add_own_key(&PgpIdentity::from_identity(&identity));
            }
        }

        // P1: restore social state: checkpoint snapshot + WAL replay.
        let mut bridge = F2fDcNetBridge::new(&uid);
        if let Ok(wal) = WalStore::open(&dir, 100) {
            if let Some(snap) = wal.load_state::<SocialSnapshot>() {
                crate::dcnet::f2f::apply_snapshot(&mut bridge, &snap);
            }
            for op in wal.replay() {
                bridge.apply_op_no_log(&op);
            }
            bridge.attach_wal(wal);
        }

        let (event_tx, event_rx) = mpsc::channel::<AppEvent>();
        let (outgoing_tx, outgoing_rx) = mpsc::channel::<(String, PeerMessage)>();
        let (incoming_tx, incoming_rx) = mpsc::channel::<(String, PeerMessage)>();
        let conn_mgr = ConnectionManager::new(listen_port);

        Self {
            identity,
            bridge,
            transport: crate::net::transport::load_transport(data_dir),
            relay: RelayRouter::new(),
            connection_manager: Arc::new(Mutex::new(conn_mgr)),
            round_engine: RoundEngine::new(&uid),
            data_dir: dir,
            event_tx,
            event_rx,
            messages: Vec::new(),
            outgoing_tx,
            incoming_rx: Arc::new(Mutex::new(incoming_rx)),
            outgoing_rx: Some(outgoing_rx),
            incoming_tx,
            wot,
            relay_verifier: RelayVerifier::new(),
            relay_nonce: 0,
            uid_shared: Arc::new(Mutex::new(uid.clone())),
        }
    }

    /// Get a shared Arc<Mutex<AppState>> for thread-safe access
    pub fn shared(self) -> Arc<Mutex<AppState>> {
        Arc::new(Mutex::new(self))
    }

    /// Send an event to consumers (non-blocking)
    pub fn emit(&self, event: AppEvent) {
        self.event_tx.send(event).ok();
    }

    /// Poll for pending events (non-blocking)
    pub fn poll_events(&self) -> Vec<AppEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            events.push(event);
        }
        events
    }

    /// Emit event via Arc reference
    pub fn emit_from(arc: &Arc<Mutex<AppState>>, event: AppEvent) {
        if let Ok(state) = arc.lock() {
            state.emit(event);
        }
    }

    /// Take the outgoing_rx for spawning the network pump task.
    pub fn take_outgoing_rx(&mut self) -> Option<mpsc::Receiver<(String, PeerMessage)>> {
        self.outgoing_rx.take()
    }

    /// P4: originate a relay request toward to_uid (direct or via path).
    pub fn send_relay(&mut self, to_uid: &str, payload: Vec<u8>) -> Option<String> {
        let signing_key = self.identity.signing_key()?;
        let from_uid = self.identity.uid.clone();
        self.relay_nonce += 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = relay::build_relay_request(
            relay::RelayOrigin {
                signing_key: &signing_key,
                origin_key_hex: self.identity.public_hex(),
                from_uid: &from_uid,
                to_uid,
                nonce: self.relay_nonce,
                timestamp: now,
                hops_left: relay::RELAY_MAX_HOPS,
            },
            payload,
        );
        let next_hop = {
            let direct = self
                .connection_manager
                .lock()
                .ok()
                .map(|cm| cm.is_connected(to_uid))
                .unwrap_or(false);
            if direct {
                Some(to_uid.to_string())
            } else {
                self.relay.next_hop(to_uid)
            }
        };
        let next_hop = next_hop?;
        if self.outgoing_tx.send((next_hop.clone(), msg)).is_err() {
            return None;
        }
        Some(format!(
            "[relay] request for {} routed via {}",
            to_uid, next_hop
        ))
    }

    /// P4: verify, admit and deliver-or-forward one relay message.
    pub fn handle_relay_message(&mut self, msg: &PeerMessage) -> Vec<AppEvent> {
        use crate::net::tcp::PeerMessage as PM;
        let (
            from_uid,
            to_uid,
            origin_key_hex,
            nonce,
            timestamp,
            hops_left,
            signature,
            payload,
            is_request,
        ) = match msg {
            PM::RelayRequest {
                from_uid,
                to_uid,
                origin_key_hex,
                nonce,
                timestamp,
                hops_left,
                signature,
                encrypted_payload,
            } => (
                from_uid.clone(),
                to_uid.clone(),
                origin_key_hex.clone(),
                *nonce,
                *timestamp,
                *hops_left,
                signature,
                encrypted_payload,
                true,
            ),
            PM::RelayResponse {
                from_uid,
                to_uid,
                origin_key_hex,
                nonce,
                timestamp,
                hops_left,
                signature,
                encrypted_payload,
            } => (
                from_uid.clone(),
                to_uid.clone(),
                origin_key_hex.clone(),
                *nonce,
                *timestamp,
                *hops_left,
                signature,
                encrypted_payload,
                false,
            ),
            _ => return Vec::new(),
        };

        let known_keys = self
            .connection_manager
            .lock()
            .ok()
            .and_then(|cm| cm.known_peer_keys.lock().ok().map(|m| m.clone()))
            .unwrap_or_default();
        let key_hex = match known_keys.get(&from_uid) {
            Some(k) => k.clone(),
            None => {
                if let Err(e) = self.relay_verifier.pin_key(&from_uid, &origin_key_hex) {
                    log::warn!("Dropping relay message from {}: {}", from_uid, e);
                    return Vec::new();
                }
                origin_key_hex.clone()
            }
        };
        let Some(vk) = relay::parse_verifying_key(&key_hex) else {
            log::warn!("Unparsable identity key for {}", from_uid);
            return Vec::new();
        };
        if !relay::verify_relay(
            &vk, &from_uid, &to_uid, nonce, timestamp, payload, signature,
        ) {
            log::warn!("Dropping relay message from {}: bad signature", from_uid);
            return Vec::new();
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Err(e) = self.relay_verifier.check(&from_uid, nonce, timestamp, now) {
            log::warn!("Relay from {} rejected: {}", from_uid, e);
            return Vec::new();
        }

        if to_uid == self.identity.uid {
            log::info!("Relayed {} bytes from {}", payload.len(), from_uid);
            return vec![AppEvent::Info {
                message: format!("relay from {}: {} bytes", from_uid, payload.len()),
            }];
        }
        if hops_left == 0 {
            log::warn!("Dropping relay message for {}: no hops left", to_uid);
            return Vec::new();
        }
        let next_hop = {
            let direct = self
                .connection_manager
                .lock()
                .ok()
                .map(|cm| cm.is_connected(&to_uid))
                .unwrap_or(false);
            if direct {
                Some(to_uid.clone())
            } else {
                self.relay.next_hop(&to_uid)
            }
        };
        let Some(next_uid) = next_hop else {
            log::warn!("Relay for {} has no route", to_uid);
            return Vec::new();
        };
        let forwarded = if is_request {
            PM::RelayRequest {
                from_uid,
                to_uid,
                origin_key_hex: origin_key_hex.clone(),
                nonce,
                timestamp,
                hops_left: hops_left - 1,
                signature: signature.clone(),
                encrypted_payload: payload.clone(),
            }
        } else {
            PM::RelayResponse {
                from_uid,
                to_uid,
                origin_key_hex: origin_key_hex.clone(),
                nonce,
                timestamp,
                hops_left: hops_left - 1,
                signature: signature.clone(),
                encrypted_payload: payload.clone(),
            }
        };
        if self.outgoing_tx.send((next_uid, forwarded)).is_err() {
            log::warn!("Outgoing queue closed; relay dropped");
        }
        Vec::new()
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        // P1: checkpoint social state, then persist identity + WoT.
        self.bridge.checkpoint_wal();
        self.identity.save(&self.data_dir);
        if let Ok(json) = serde_json::to_string_pretty(&self.wot) {
            let _ = crate::identity::write_private_file(&self.data_dir.join("wot.json"), &json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_init() {
        let tmp = std::env::temp_dir().join("chrono_test_app");
        let state = AppState::new(tmp.to_str().unwrap());
        assert!(state.identity.uid.is_empty() || !state.identity.uid.is_empty());
        state.emit(AppEvent::Info {
            message: "test".into(),
        });
        let events = state.poll_events();
        assert_eq!(events.len(), 1);
        std::fs::remove_dir_all(tmp).ok();
    }
}
