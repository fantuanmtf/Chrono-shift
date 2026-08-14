//! P2P Connection Manager (v7.6 — Phase 1.2 + session security fix)
//!
//! Hybrid P2P model: each node listens on a TCP port, discovers peers via LAN
//! UDP broadcast, and maintains direct TCP connections to known peers.
//!
//! Security fix: every connection now starts with an authenticated X25519
//! handshake (net::session) and all subsequent frames are AES-256-GCM
//! encrypted with per-direction keys + sequence numbers. The previous
//! plaintext-JSON path is gone.
//!
//! Thread safety design:
//!   Each connection spawns a writer task that owns the TCP WriteHalf.
//!   The HashMap stores mpsc::Sender<Vec<u8>> — to send to a peer,
//!   we push bytes into the channel and the writer task encrypts + flushes.
//!
//! Channel ownership:
//!   - ConnectionManager holds outgoing_tx → network writer task consumes
//!   - AppState exclusively holds incoming_rx (Receiver is not Clone)

use crate::net::session::{self, SessionAuth};
use crate::net::tcp::PeerMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// Information about a known peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub uid: String,
    /// Known addresses (LAN + public)
    pub addresses: Vec<SocketAddr>,
    /// Ed25519 public key hex
    pub public_key: String,
    /// Last time we saw this peer (via LAN broadcast or direct connection)
    pub last_seen: Instant,
    /// PGP fingerprint (if available, Phase 2)
    pub pgp_fingerprint: Option<String>,
}

/// Capacity of each connection's outbound queue (backpressure: when full,
/// try_send fails and the caller sees a send error instead of unbounded
/// memory growth on a slow peer).
pub const WRITER_QUEUE_CAP: usize = 256;

/// Idle read timeout: a peer that sends nothing for this long is declared
/// dead and the connection is cleaned up.
pub const READ_IDLE_TIMEOUT_SECS: u64 = 90;

/// Per-frame write timeout (slow/congested peers).
pub const WRITE_TIMEOUT_SECS: u64 = 15;

/// Connection id counter (unique per connection; reused uids get new ids).
static NEXT_CONN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Writer handle for a connected peer — send bytes to the writer task.
/// Carries a unique connection id so cleanup can remove exactly the right
/// entry when a connection dies (a newer connection may reuse the uid).
#[derive(Clone)]
pub struct PeerWriter {
    pub tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub conn_id: u64,
}

impl PeerWriter {
    fn new() -> (Self, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = tokio::sync::mpsc::channel(WRITER_QUEUE_CAP);
        let conn_id = NEXT_CONN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        (Self { tx, conn_id }, rx)
    }
}

/// P2P connection manager — manages active TCP connections to friends
pub struct ConnectionManager {
    /// Active connections: UID → channel to writer task
    /// Thread-safe: Arc<Mutex<>> for sharing with spawned tasks
    pub active_connections: Arc<Mutex<HashMap<String, PeerWriter>>>,
    /// Known peers discovered via LAN or manual /connect
    pub known_peers: HashMap<String, PeerInfo>,
    /// Known peer identity keys: uid → Ed25519 public key hex.
    /// Shared with the listener tasks so handshakes can verify peers.
    pub known_peer_keys: Arc<Mutex<HashMap<String, String>>>,
    /// TCP listen port
    pub listen_port: u16,
}

impl ConnectionManager {
    /// Create a new connection manager.
    ///
    /// P1 fix: the outgoing_tx field was removed — it was never read, and
    /// worse, the outgoing pump task holds this struct in an Arc; keeping a
    /// Sender for its own receive channel here made the pump wait forever
    /// for itself to disconnect, deadlocking process shutdown.
    pub fn new(listen_port: u16) -> Self {
        Self {
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            known_peers: HashMap::new(),
            known_peer_keys: Arc::new(Mutex::new(HashMap::new())),
            listen_port,
        }
    }

    /// Register a known peer (from LAN discovery or manual /connect)
    pub fn register_peer(&mut self, uid: &str, addr: SocketAddr, public_key: &str) {
        self.known_peers
            .entry(uid.to_string())
            .and_modify(|p| {
                if !p.addresses.contains(&addr) {
                    p.addresses.push(addr);
                }
                p.last_seen = Instant::now();
                p.public_key = public_key.to_string();
            })
            .or_insert(PeerInfo {
                uid: uid.to_string(),
                addresses: vec![addr],
                public_key: public_key.to_string(),
                last_seen: Instant::now(),
                pgp_fingerprint: None,
            });
        // Keep the identity-key map in sync for handshake verification.
        if let Ok(mut keys) = self.known_peer_keys.lock() {
            keys.insert(uid.to_string(), public_key.to_string());
        }
    }

    /// Check if we have an active connection to a peer
    pub fn is_connected(&self, uid: &str) -> bool {
        match self.active_connections.lock() {
            Ok(conns) => conns.contains_key(uid),
            Err(_) => false,
        }
    }

    /// Get the addresses of a known peer
    pub fn peer_addresses(&self, uid: &str) -> Vec<SocketAddr> {
        self.known_peers
            .get(uid)
            .map(|p| p.addresses.clone())
            .unwrap_or_default()
    }

    /// Queue a message to be sent to a specific peer (non-blocking).
    /// The payload is plaintext here; the per-connection writer task
    /// encrypts it with the session key before it hits the wire.
    ///
    /// P4: bounded queue — when the peer is too slow and the queue is full,
    /// this returns an error instead of growing memory without bound.
    pub fn send_to(&self, uid: &str, msg: &PeerMessage) -> Result<(), String> {
        let json = msg.to_json();
        let payload = json.into_bytes();
        let conns = self
            .active_connections
            .lock()
            .map_err(|_| "connection map poisoned".to_string())?;
        let writer = conns
            .get(uid)
            .ok_or_else(|| format!("No active connection to {}", uid))?;
        writer
            .tx
            .try_send(payload)
            .map_err(|e| format!("Send error: {}", e))
    }

    /// Queue a broadcast to a list of peers (best-effort, drops silently if
    /// disconnected or the peer's queue is full).
    pub fn broadcast_to(&self, uids: &[String], msg: &PeerMessage) {
        let json = msg.to_json();
        let payload = json.into_bytes();
        let conns = match self.active_connections.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        for uid in uids {
            if let Some(writer) = conns.get(uid) {
                writer.tx.try_send(payload.clone()).ok();
            }
        }
    }

    /// Remove a dead connection from the active map — only when the entry
    /// still belongs to that connection id (a newer connection with the
    /// same uid must not be clobbered).
    fn remove_connection(
        active: &Arc<Mutex<HashMap<String, PeerWriter>>>,
        uid: &str,
        conn_id: u64,
    ) {
        if let Ok(mut conns) = active.lock() {
            let stale = conns
                .get(uid)
                .map(|w| w.conn_id == conn_id)
                .unwrap_or(false);
            if stale {
                conns.remove(uid);
                log::info!("Cleaned up dead connection to {}", uid);
            }
        }
    }

    /// Start the TCP listener (tokio async task).
    /// Each accepted connection first performs the authenticated X25519
    /// handshake; only then are the writer/reader tasks spawned.
    ///
    /// P3 fix: uid comes from a shared cell read per connection, so /nick
    /// applies to inbound handshakes (previously the uid was snapshotted
    /// at startup).
    pub async fn start_listener(
        port: u16,
        active: Arc<Mutex<HashMap<String, PeerWriter>>>,
        incoming_tx: mpsc::Sender<(String, PeerMessage)>,
        public_hex: String,
        signing_key: ed25519_dalek::SigningKey,
        uid_shared: Arc<Mutex<String>>,
        known_keys: Arc<Mutex<HashMap<String, String>>>,
    ) {
        // v8.1 port: IPv6 dual-stack first, IPv4 fallback.
        let listener = match tokio::net::TcpListener::bind(format!("[::]:{}", port)).await {
            Ok(l) => {
                log::info!("TCP listener on [::]:{} (IPv6 dual-stack)", port);
                l
            }
            Err(_) => match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await {
                Ok(l) => {
                    log::info!("TCP listener on 0.0.0.0:{} (IPv4 fallback)", port);
                    l
                }
                Err(e) => {
                    log::error!("Failed to bind TCP listener on port {}: {}", port, e);
                    return;
                }
            },
        };

        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    log::info!("Incoming connection from {}", addr);
                    let auth = SessionAuth {
                        uid: uid_shared.lock().map(|u| u.clone()).unwrap_or_default(),
                        public_hex: public_hex.clone(),
                        signing_key: signing_key.clone(),
                    };
                    let keys = known_keys.clone();
                    let active = active.clone();
                    let tx = incoming_tx.clone();
                    tokio::spawn(async move {
                        // Authenticate + agree on session keys before any
                        // application data is exchanged.
                        let handshake = tokio::time::timeout(
                            Duration::from_secs(10),
                            session::inbound_handshake(&mut stream, &auth, &keys),
                        )
                        .await;
                        let session = match handshake {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                log::warn!("Handshake with {} failed: {}", addr, e);
                                return;
                            }
                            Err(_) => {
                                log::warn!("Handshake with {} timed out", addr);
                                return;
                            }
                        };

                        // TOFU: pin the peer's claimed identity key so later
                        // per-message signatures (DC-Net shares, relay) verify.
                        if let Ok(mut k) = keys.lock() {
                            k.entry(session.peer_uid.clone())
                                .or_insert_with(|| session.peer_public_hex.clone());
                        }

                        let (read_half, write_half) = stream.into_split();
                        let (writer, rx) = PeerWriter::new();
                        let conn_id = writer.conn_id;
                        {
                            match active.lock() {
                                Ok(mut conns) => {
                                    conns.insert(session.peer_uid.clone(), writer);
                                }
                                Err(_) => return,
                            }
                        }
                        tokio::spawn(connection_writer(
                            write_half,
                            rx,
                            session.send_key,
                            active.clone(),
                            session.peer_uid.clone(),
                            conn_id,
                        ));
                        tokio::spawn(connection_reader(
                            read_half,
                            ReaderCtx {
                                addr,
                                incoming_tx: tx,
                                recv_key: session.recv_key,
                                peer_uid: session.peer_uid.clone(),
                                peer_authenticated: session.peer_authenticated,
                                active: active.clone(),
                                conn_id,
                            },
                        ));
                    });
                }
                Err(e) => {
                    log::error!("Accept error: {}", e);
                }
            }
        }
    }

    /// Connect to a peer (active outbound connection).
    /// Performs the authenticated handshake before spawning the tasks.
    /// Incoming messages from this connection are forwarded to incoming_tx.
    ///
    /// Associated function taking the shared Arc fields directly so the
    /// future never holds a MutexGuard across an await point (Send).
    pub async fn connect_to_peer(
        active: Arc<Mutex<HashMap<String, PeerWriter>>>,
        known_keys: Arc<Mutex<HashMap<String, String>>>,
        uid: &str,
        addr: SocketAddr,
        auth: &SessionAuth,
        incoming_tx: mpsc::Sender<(String, PeerMessage)>,
    ) -> Result<(), std::io::Error> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            session::outbound_handshake(&mut stream, auth, &known_keys),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "handshake timed out"))??;

        // Only accept an authenticated peer when we asked for a known uid.
        if session.peer_uid != uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("peer identified as {}, expected {}", session.peer_uid, uid),
            ));
        }

        // TOFU: pin the peer's claimed identity key (same as the listener).
        if let Ok(mut k) = known_keys.lock() {
            k.entry(session.peer_uid.clone())
                .or_insert_with(|| session.peer_public_hex.clone());
        }

        let (read_half, write_half) = stream.into_split();

        // Spawn writer task
        let (writer, rx) = PeerWriter::new();
        let conn_id = writer.conn_id;
        match active.lock() {
            Ok(mut conns) => {
                conns.insert(uid.to_string(), writer);
            }
            Err(_) => {
                return Err(std::io::Error::other("connection map poisoned"));
            }
        }
        tokio::spawn(connection_writer(
            write_half,
            rx,
            session.send_key,
            active.clone(),
            uid.to_string(),
            conn_id,
        ));

        // Spawn reader task — P3: inbound messages now reach the CLI queue.
        tokio::spawn(connection_reader(
            read_half,
            ReaderCtx {
                addr,
                incoming_tx,
                recv_key: session.recv_key,
                peer_uid: session.peer_uid.clone(),
                peer_authenticated: session.peer_authenticated,
                active: active.clone(),
                conn_id,
            },
        ));

        Ok(())
    }

    /// Get connected peer count
    pub fn connected_count(&self) -> usize {
        match self.active_connections.lock() {
            Ok(conns) => conns.len(),
            Err(_) => 0,
        }
    }

    /// Dump debug information about connections and peers
    pub fn debug_info(&self) -> String {
        let conns = match self.active_connections.lock() {
            Ok(c) => c,
            Err(_) => return "=== Connection Manager === (map poisoned)".into(),
        };
        let mut lines = vec![
            format!("=== Connection Manager ==="),
            format!("Listen port: {}", self.listen_port),
            format!(
                "Active connections: {} | Known peers: {}",
                conns.len(),
                self.known_peers.len()
            ),
        ];
        if !conns.is_empty() {
            lines.push("  Connected to:".into());
            for uid in conns.keys() {
                lines.push(format!("    {}", uid));
            }
        }
        if !self.known_peers.is_empty() {
            lines.push("  Known peers:".into());
            for (uid, info) in &self.known_peers {
                let seen = Instant::now().duration_since(info.last_seen).as_secs();
                lines.push(format!(
                    "    {} (last seen: {}s ago, addrs: {:?})",
                    uid, seen, info.addresses
                ));
            }
        }
        lines.join(
            "
",
        )
    }
}

// ---- Background tasks ----

/// Writer task: owns OwnedWriteHalf, receives plaintext payloads from the
/// bounded tokio channel, encrypts each as a secure frame and writes it to
/// TCP with a per-frame timeout. Removes the connection from the active map
/// when it dies.
async fn connection_writer(
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    send_key: [u8; 32],
    active: Arc<Mutex<HashMap<String, PeerWriter>>>,
    uid: String,
    conn_id: u64,
) {
    let mut seq: u64 = 0;
    while let Some(payload) = rx.recv().await {
        let write = tokio::time::timeout(
            Duration::from_secs(WRITE_TIMEOUT_SECS),
            session::send_secure_frame(&mut write_half, &payload, &send_key, &mut seq),
        )
        .await;
        match write {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                log::debug!("Write to {} failed: {}", uid, e);
                break;
            }
            Err(_) => {
                log::warn!("Write to {} timed out after {}s", uid, WRITE_TIMEOUT_SECS);
                break;
            }
        }
    }
    ConnectionManager::remove_connection(&active, &uid, conn_id);
    log::info!("Connection writer closed");
}

/// Everything a reader task needs besides the stream half.
struct ReaderCtx {
    addr: SocketAddr,
    incoming_tx: mpsc::Sender<(String, PeerMessage)>,
    recv_key: [u8; 32],
    peer_uid: String,
    peer_authenticated: bool,
    active: Arc<Mutex<HashMap<String, PeerWriter>>>,
    conn_id: u64,
}

/// Reader task: receives secure frames, decrypts + authenticates them,
/// parses PeerMessage, binds from_uid to the handshake-authenticated uid
/// and forwards to the CLI queue. A peer that stays silent for
/// READ_IDLE_TIMEOUT_SECS is declared dead and the connection is removed
/// from the active map.
async fn connection_reader(mut read_half: tokio::net::tcp::OwnedReadHalf, ctx: ReaderCtx) {
    let ReaderCtx {
        addr,
        incoming_tx,
        recv_key,
        peer_uid,
        peer_authenticated,
        active,
        conn_id,
    } = ctx;
    let mut last_seq: u64 = 0;
    loop {
        let read = tokio::time::timeout(
            Duration::from_secs(READ_IDLE_TIMEOUT_SECS),
            session::recv_secure_frame(&mut read_half, &recv_key, &mut last_seq),
        )
        .await;
        let payload = match read {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                log::debug!("Secure read from {} ended: {}", addr, e);
                break;
            }
            Err(_) => {
                log::warn!(
                    "Peer {} idle for {}s — closing connection",
                    peer_uid,
                    READ_IDLE_TIMEOUT_SECS
                );
                break;
            }
        };
        match String::from_utf8(payload) {
            Ok(text) => {
                if let Some(msg) = PeerMessage::from_json(&text) {
                    let claimed_uid = extract_uid(&msg, &addr);
                    // Bind identity: messages must come from the uid that
                    // authenticated in the handshake. Anonymous types
                    // (Ping/Pong) are routed under the peer uid.
                    //
                    // P4 exception: relay messages carry the ORIGINATOR as
                    // from_uid (which is not the relay node's uid); their
                    // originator identity is verified cryptographically in
                    // AppState::handle_relay_message, so let them through.
                    let is_anonymous = claimed_uid.starts_with("peer@");
                    let is_relay = matches!(
                        msg,
                        PeerMessage::RelayRequest { .. } | PeerMessage::RelayResponse { .. }
                    );
                    if !is_anonymous && !is_relay && claimed_uid != peer_uid {
                        log::warn!(
                            "Dropping message from {} claiming to be {} (session uid: {})",
                            addr,
                            claimed_uid,
                            peer_uid
                        );
                        continue;
                    }
                    let _ = peer_authenticated; // surfaced via logs for now
                    incoming_tx.send((peer_uid.clone(), msg)).ok();
                }
            }
            Err(_) => {
                log::debug!("Non-utf8 frame from {}", addr);
            }
        }
    }
    ConnectionManager::remove_connection(&active, &peer_uid, conn_id);
    log::info!("Connection reader from {} closed", addr);
}

/// Extract a best-effort UID from a PeerMessage for routing
fn extract_uid(msg: &PeerMessage, addr: &SocketAddr) -> String {
    match msg {
        PeerMessage::FriendRequest { from_uid, .. }
        | PeerMessage::FriendAccept { from_uid }
        | PeerMessage::ChannelMessage { from_uid, .. }
        | PeerMessage::DcRoundShare {
            peer_uid: from_uid, ..
        }
        | PeerMessage::NetworkInvite { from_uid, .. }
        | PeerMessage::NetworkJoinRequest { from_uid, .. }
        | PeerMessage::NetworkJoinAccept { from_uid, .. }
        | PeerMessage::NetworkKick { from_uid, .. }
        | PeerMessage::NetworkSync { from_uid, .. }
        | PeerMessage::AuthChallenge { from_uid, .. }
        | PeerMessage::AuthResponse { from_uid, .. }
        | PeerMessage::RelayRequest { from_uid, .. }
        | PeerMessage::RelayResponse { from_uid, .. } => from_uid.clone(),

        PeerMessage::DcRoundStart { leader_id, .. }
        | PeerMessage::LeaderChange {
            new_leader: leader_id,
            ..
        } => leader_id.clone(),

        PeerMessage::RoundSyncRequest { from_uid, .. } => from_uid.clone(),
        PeerMessage::RoundSyncResponse { leader_uid, .. } => leader_uid.clone(),

        PeerMessage::DcRound { .. }
        | PeerMessage::DcRoundResult { .. }
        | PeerMessage::Ping { .. }
        | PeerMessage::Pong { .. } => format!("peer@{}", addr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_lookup_peer() {
        let mut cm = ConnectionManager::new(9000);

        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        cm.register_peer("alice", addr, "abc123");

        assert_eq!(cm.known_peers.len(), 1);
        assert_eq!(cm.peer_addresses("alice"), vec![addr]);
        assert!(!cm.is_connected("alice")); // registered but not connected
    }

    #[test]
    fn test_peer_multiple_addresses() {
        let mut cm = ConnectionManager::new(9000);

        let addr1: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.1:9000".parse().unwrap();

        cm.register_peer("bob", addr1, "key1");
        cm.register_peer("bob", addr2, "key1");

        let addrs = cm.peer_addresses("bob");
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_register_peer_records_key() {
        let mut cm = ConnectionManager::new(9000);
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        cm.register_peer("alice", addr, "pubkeyhex");
        let keys = cm.known_peer_keys.lock().unwrap();
        assert_eq!(keys.get("alice").map(String::as_str), Some("pubkeyhex"));
    }

    #[test]
    fn test_debug_info() {
        let mut cm = ConnectionManager::new(9000);
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        cm.register_peer("alice", addr, "key");

        let info = cm.debug_info();
        assert!(info.contains("9000"));
        assert!(info.contains("alice"));
    }

    #[test]
    fn test_remove_connection_only_matching_id() {
        // P4: cleanup must not clobber a newer connection reusing the uid.
        let active: Arc<Mutex<HashMap<String, PeerWriter>>> = Arc::new(Mutex::new(HashMap::new()));
        let (w1, _rx1) = PeerWriter::new();
        active.lock().unwrap().insert("bob".to_string(), w1);

        // A stale cleanup with the wrong id leaves the entry alone.
        ConnectionManager::remove_connection(&active, "bob", 999);
        assert!(active.lock().unwrap().contains_key("bob"));

        // The correct id removes it.
        let id = active.lock().unwrap()["bob"].conn_id;
        ConnectionManager::remove_connection(&active, "bob", id);
        assert!(!active.lock().unwrap().contains_key("bob"));
    }

    #[test]
    fn test_writer_queue_is_bounded() {
        // P4: try_send fails once the queue is full (backpressure).
        let (w, mut rx) = PeerWriter::new();
        for i in 0..WRITER_QUEUE_CAP {
            assert!(
                w.tx.try_send(vec![i as u8]).is_ok(),
                "expected queue to accept item {}",
                i
            );
        }
        assert!(w.tx.try_send(vec![9u8]).is_err());
        // Drain a few to prove the queue recovers.
        for _ in 0..4 {
            rx.try_recv().expect("queued item");
        }
        assert!(w.tx.try_send(vec![10u8]).is_ok());
    }
}
