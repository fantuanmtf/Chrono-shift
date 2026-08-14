//! Address Book + F2F Gossip (v7.7 — Phase 4)
//!
//! Three-layer peer discovery:
//!   1. LAN — UDP broadcast (lan.rs, port 9901)
//!   2. F2F Gossip — exchange known peers with trusted friends
//!   3. Manual — /connect <uid> <ip:port>
//!
//! Gossip is trust-filtered: only accept data from Marginal+ trust level,
//! weighted by trust score to prevent Sybil attacks.

use crate::pgp::TrustLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Where a peer address came from
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AddressSource {
    Manual,
    LAN,
    Gossip,
}

/// One entry in the address book
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    pub uid: String,
    pub addresses: Vec<SocketAddr>,
    pub public_key: String,
    pub last_seen: u64,
    pub source: AddressSource,
    /// Confidence weight (0.0-1.0) — higher = more reliable
    pub confidence: f64,
}

/// Peer announcement in gossip messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnounce {
    pub uid: String,
    pub addresses: Vec<SocketAddr>,
    pub public_key: String,
}

/// Address book: all known peers and their addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBook {
    pub entries: HashMap<String, AddressEntry>,
}

impl Default for AddressBook {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressBook {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Add or update a peer address with confidence weighting
    pub fn add_or_update(
        &mut self,
        uid: &str,
        addresses: &[SocketAddr],
        public_key: &str,
        source: AddressSource,
        confidence: f64,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.entries
            .entry(uid.to_string())
            .and_modify(|entry| {
                // Merge addresses (keep existing, add new)
                for addr in addresses {
                    if !entry.addresses.contains(addr) {
                        entry.addresses.push(*addr);
                    }
                }
                // Update if newer or higher confidence
                if confidence > entry.confidence || now > entry.last_seen {
                    entry.last_seen = now;
                    entry.confidence = confidence;
                    entry.source = source.clone();
                }
            })
            .or_insert(AddressEntry {
                uid: uid.to_string(),
                addresses: addresses.to_vec(),
                public_key: public_key.to_string(),
                last_seen: now,
                source,
                confidence,
            });
    }

    /// Get addresses for a peer
    pub fn get(&self, uid: &str) -> Option<&AddressEntry> {
        self.entries.get(uid)
    }

    /// Get all addresses for a peer (sorted by confidence)
    pub fn get_addresses(&self, uid: &str) -> Vec<SocketAddr> {
        self.entries
            .get(uid)
            .map(|e| e.addresses.clone())
            .unwrap_or_default()
    }

    /// Remove stale entries (not seen for N seconds)
    pub fn prune_stale(&mut self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries.retain(|_, e| now - e.last_seen < max_age_secs);
    }

    /// Count entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No entries?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// List all UIDs
    pub fn list_uids(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

/// Handle an incoming gossip response from a friend.
/// Applies trust filtering to prevent Sybil attacks.
pub fn handle_gossip_response(
    book: &mut AddressBook,
    _from_uid: &str,
    trust_level: TrustLevel,
    peers: Vec<PeerAnnounce>,
) -> usize {
    if trust_level < TrustLevel::Marginal {
        return 0; // Untrusted source, ignore entirely
    }

    let weight = match trust_level {
        TrustLevel::Ultimate => 1.0,
        TrustLevel::Full => 0.8,
        TrustLevel::Marginal => 0.4,
        _ => 0.0,
    };

    let mut added = 0;
    for peer in &peers {
        book.add_or_update(
            &peer.uid,
            &peer.addresses,
            &peer.public_key,
            AddressSource::Gossip,
            weight,
        );
        added += 1;
    }
    added
}

/// Build a gossip response — share our known peers
pub fn build_gossip_response(book: &AddressBook, exclude_uid: &str) -> Vec<PeerAnnounce> {
    book.entries
        .iter()
        .filter(|(uid, _)| *uid != exclude_uid)
        .map(|(uid, entry)| PeerAnnounce {
            uid: uid.clone(),
            addresses: entry.addresses.clone(),
            public_key: entry.public_key.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_lookup() {
        let mut book = AddressBook::new();
        let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        book.add_or_update("alice", &[addr], "key1", AddressSource::Manual, 1.0);
        assert_eq!(book.len(), 1);
        assert_eq!(book.get_addresses("alice"), vec![addr]);
    }

    #[test]
    fn test_merge_addresses() {
        let mut book = AddressBook::new();
        let addr1: SocketAddr = "192.168.1.1:9000".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.1:9000".parse().unwrap();

        book.add_or_update("bob", &[addr1], "key1", AddressSource::Manual, 1.0);
        book.add_or_update("bob", &[addr2], "key1", AddressSource::LAN, 0.5);

        let addrs = book.get_addresses("bob");
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_confidence_update() {
        let mut book = AddressBook::new();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        // Low confidence first
        book.add_or_update("eve", &[addr], "key", AddressSource::LAN, 0.3);
        assert_eq!(book.get("eve").unwrap().confidence, 0.3);

        // Higher confidence override
        book.add_or_update("eve", &[addr], "key", AddressSource::Gossip, 0.8);
        assert_eq!(book.get("eve").unwrap().confidence, 0.8);
    }

    #[test]
    fn test_gossip_trust_filter() {
        let mut book = AddressBook::new();
        let addr: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        let peers = vec![PeerAnnounce {
            uid: "carol".into(),
            addresses: vec![addr],
            public_key: "key".into(),
        }];

        // Unknown trust → reject
        let added = handle_gossip_response(&mut book, "bob", TrustLevel::Unknown, peers.clone());
        assert_eq!(added, 0);

        // Marginal trust → accept with weight 0.4
        let added = handle_gossip_response(&mut book, "bob", TrustLevel::Marginal, peers.clone());
        assert_eq!(added, 1);
        assert_eq!(book.get("carol").unwrap().confidence, 0.4);

        // Full trust → weight 0.8
        let added = handle_gossip_response(&mut book, "charlie", TrustLevel::Full, peers);
        assert_eq!(added, 1);
    }

    #[test]
    fn test_build_gossip_response() {
        let mut book = AddressBook::new();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        book.add_or_update("alice", &[addr], "key", AddressSource::Manual, 1.0);
        book.add_or_update("bob", &[addr], "key", AddressSource::LAN, 0.5);

        // Exclude bob from response
        let response = build_gossip_response(&book, "bob");
        assert_eq!(response.len(), 1);
        assert_eq!(response[0].uid, "alice");
    }

    #[test]
    fn test_prune_stale() {
        let mut book = AddressBook::new();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        book.add_or_update("alice", &[addr], "key", AddressSource::Manual, 1.0);

        // Manually set last_seen far in the past
        book.entries.get_mut("alice").unwrap().last_seen = 1000;

        book.prune_stale(3600); // 1 hour max age
        assert_eq!(book.len(), 0);
    }
}
