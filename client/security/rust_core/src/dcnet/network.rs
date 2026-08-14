//! DC-Net Network abstraction (v7.6 — Phase 3.1)
//!
//! A DcNetwork is a named group of friends who participate in DC-Net
//! anonymous rounds together. Each network has an admin who manages
//! membership, trust requirements, and round parameters.
//!
//! Integrates with pgp::TrustLevel for access control.

use crate::pgp::TrustLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A DC-Net network — a named group of trusted friends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcNetwork {
    /// Network name (e.g., "mygroup", referenced as #mygroup)
    pub name: String,
    /// Admin UID — who created and manages this network
    pub admin_uid: String,
    /// Creation timestamp (Unix epoch seconds)
    pub created: u64,
    /// Network topic / description
    pub topic: String,
    /// Member UIDs (includes admin)
    pub members: Vec<String>,
    /// Pending invitations: invitee_uid → invited_by_uid
    pub pending_invites: HashMap<String, String>,
    /// Minimum trust level required to join (default: Marginal)
    pub min_trust: TrustLevel,
    /// Minimum participants to start a DC-Net round
    pub min_participants: usize,
    /// Maximum dropouts allowed before round fails
    pub max_dropouts: usize,
    /// Round interval in milliseconds
    pub round_interval_ms: u64,
    /// Current round leader UID
    pub current_leader: String,
    /// Member join order — used for leader rotation on failure
    pub member_join_order: Vec<String>,
}

impl DcNetwork {
    /// Create a new DC-Net network
    pub fn new(name: &str, admin_uid: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            name: name.to_string(),
            admin_uid: admin_uid.to_string(),
            created: now,
            topic: String::new(),
            members: vec![admin_uid.to_string()],
            pending_invites: HashMap::new(),
            min_trust: TrustLevel::Marginal,
            min_participants: 2,
            max_dropouts: 1,
            round_interval_ms: 3000,
            current_leader: admin_uid.to_string(),
            member_join_order: vec![admin_uid.to_string()],
        }
    }

    // ---- Membership ----

    /// Check if a UID is a member
    pub fn is_member(&self, uid: &str) -> bool {
        self.members.contains(&uid.to_string())
    }

    /// Check if a UID is the admin
    pub fn is_admin(&self, uid: &str) -> bool {
        self.admin_uid == uid
    }

    /// Check if a UID has a pending invitation
    pub fn has_pending_invite(&self, uid: &str) -> bool {
        self.pending_invites.contains_key(uid)
    }

    /// Number of members
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Get the next leader in join order (for failover)
    pub fn next_leader(&self) -> Option<&str> {
        let current_idx = self
            .member_join_order
            .iter()
            .position(|u| u == &self.current_leader)?;
        let next_idx = (current_idx + 1) % self.member_join_order.len();
        self.member_join_order.get(next_idx).map(|s| s.as_str())
    }

    // ---- Admin operations ----

    /// Invite a user to join the network (admin only)
    pub fn invite_member(&mut self, uid: &str, invited_by: &str) -> Result<(), String> {
        if !self.is_admin(invited_by) {
            return Err(format!(
                "Only admin ({}) can invite members",
                self.admin_uid
            ));
        }
        if self.is_member(uid) {
            return Err(format!("{} is already a member", uid));
        }
        self.pending_invites
            .insert(uid.to_string(), invited_by.to_string());
        Ok(())
    }

    /// Accept a join request (admin approves)
    pub fn accept_join(&mut self, uid: &str, trust_level: TrustLevel) -> Result<(), String> {
        if !self.has_pending_invite(uid) {
            return Err(format!("{} has no pending invitation", uid));
        }
        if trust_level < self.min_trust {
            return Err(format!(
                "{} has trust level {:?}, but network requires {:?}",
                uid, trust_level, self.min_trust
            ));
        }
        self.pending_invites.remove(uid);
        if !self.is_member(uid) {
            self.members.push(uid.to_string());
            self.member_join_order.push(uid.to_string());
        }
        Ok(())
    }

    /// Kick a member from the network (admin only)
    pub fn kick_member(&mut self, uid: &str, kicked_by: &str) -> Result<(), String> {
        if !self.is_admin(kicked_by) {
            return Err(format!("Only admin ({}) can kick members", self.admin_uid));
        }
        if uid == self.admin_uid {
            return Err("Admin cannot kick themselves".to_string());
        }
        let kicked_leader = uid == self.current_leader;
        self.members.retain(|u| u != uid);
        self.member_join_order.retain(|u| u != uid);
        self.pending_invites.remove(uid);

        // P2 fix: kicking the current leader used to leave the network with
        // a leader pointing at a non-member — rotation then failed forever.
        // Fail over to the first remaining member immediately.
        if kicked_leader {
            let new_leader = self.member_join_order.first().cloned().unwrap_or_default();
            log::warn!(
                "Network '{}': leader {} was kicked; failing over to '{}'",
                self.name,
                uid,
                new_leader
            );
            self.current_leader = new_leader;
        }
        Ok(())
    }

    /// Transfer admin to another member
    pub fn transfer_admin(&mut self, new_admin: &str, current_admin: &str) -> Result<(), String> {
        if !self.is_admin(current_admin) {
            return Err("Only current admin can transfer admin rights".to_string());
        }
        if !self.is_member(new_admin) {
            return Err(format!("{} is not a member of this network", new_admin));
        }
        self.admin_uid = new_admin.to_string();
        self.current_leader = new_admin.to_string();
        Ok(())
    }

    /// Set the network topic (admin only)
    pub fn set_topic(&mut self, topic: &str, setter: &str) -> Result<(), String> {
        if !self.is_admin(setter) {
            return Err("Only admin can set topic".to_string());
        }
        self.topic = topic.to_string();
        Ok(())
    }

    /// Set minimum trust level (admin only)
    pub fn set_min_trust(&mut self, level: TrustLevel, setter: &str) -> Result<(), String> {
        if !self.is_admin(setter) {
            return Err("Only admin can change trust requirements".to_string());
        }
        self.min_trust = level;
        Ok(())
    }

    // ---- Leader management ----

    /// Rotate to the next leader (used on timeout/failure)
    pub fn rotate_leader(&mut self) -> Option<String> {
        let next_idx = {
            let current_idx = self
                .member_join_order
                .iter()
                .position(|u| u == &self.current_leader)?;
            (current_idx + 1) % self.member_join_order.len()
        };
        let next = self.member_join_order[next_idx].clone();
        let old = std::mem::replace(&mut self.current_leader, next.clone());
        log::warn!(
            "Network '{}': leader rotated from {} to {}",
            self.name,
            old,
            next
        );
        Some(next)
    }

    /// Set a specific leader
    pub fn set_leader(&mut self, uid: &str) -> Result<(), String> {
        if !self.is_member(uid) {
            return Err(format!("{} is not a member", uid));
        }
        self.current_leader = uid.to_string();
        Ok(())
    }

    /// Get network status as a human-readable string
    pub fn status_string(&self) -> String {
        format!(
            "Network '{}' | Admin: {} | Members: {}/{} | Min trust: {:?} | Leader: {}",
            self.name,
            self.admin_uid,
            self.members.len(),
            self.min_participants,
            self.min_trust,
            self.current_leader
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_network() {
        let net = DcNetwork::new("testnet", "alice");
        assert_eq!(net.name, "testnet");
        assert_eq!(net.admin_uid, "alice");
        assert_eq!(net.current_leader, "alice");
        assert!(net.is_member("alice"));
        assert!(net.is_admin("alice"));
        assert_eq!(net.member_count(), 1);
    }

    #[test]
    fn test_invite_and_accept() {
        let mut net = DcNetwork::new("testnet", "alice");
        net.invite_member("bob", "alice").unwrap();
        assert!(net.has_pending_invite("bob"));

        net.accept_join("bob", TrustLevel::Full).unwrap();
        assert!(net.is_member("bob"));
        assert!(!net.has_pending_invite("bob"));
        assert_eq!(net.member_count(), 2);
    }

    #[test]
    fn test_invite_denied_by_trust() {
        let mut net = DcNetwork::new("testnet", "alice");
        net.set_min_trust(TrustLevel::Full, "alice").unwrap();
        net.invite_member("bob", "alice").unwrap();

        // Bob only has Marginal trust → should be rejected
        let result = net.accept_join("bob", TrustLevel::Marginal);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("trust level"));
    }

    #[test]
    fn test_kick_member() {
        let mut net = DcNetwork::new("testnet", "alice");
        net.invite_member("bob", "alice").unwrap();
        net.accept_join("bob", TrustLevel::Full).unwrap();
        assert_eq!(net.member_count(), 2);

        net.kick_member("bob", "alice").unwrap();
        assert!(!net.is_member("bob"));
        assert_eq!(net.member_count(), 1);
    }

    #[test]
    fn test_kick_leader_fails_over() {
        // P2 fix regression: kicking the current leader used to leave the
        // network leaderless — rotation then failed forever.
        let mut net = DcNetwork::new("testnet", "alice");
        net.invite_member("bob", "alice").unwrap();
        net.accept_join("bob", TrustLevel::Full).unwrap();
        net.rotate_leader(); // alice → bob
        assert_eq!(net.current_leader, "bob");

        // Admin (alice) kicks the current leader (bob).
        net.kick_member("bob", "alice").unwrap();
        assert_eq!(net.current_leader, "alice"); // failed over
        assert_eq!(net.members.len(), 1);

        // Rotation keeps working after the failover.
        let next = net.rotate_leader();
        assert_eq!(next.as_deref(), Some("alice"));
    }

    #[test]
    fn test_cannot_kick_admin() {
        let mut net = DcNetwork::new("testnet", "alice");
        let result = net.kick_member("alice", "alice");
        assert!(result.is_err());
    }

    #[test]
    fn test_only_admin_can_invite() {
        let mut net = DcNetwork::new("testnet", "alice");
        net.invite_member("bob", "alice").unwrap();
        net.accept_join("bob", TrustLevel::Full).unwrap();

        // Bob is not admin, cannot invite
        let result = net.invite_member("carol", "bob");
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_admin() {
        let mut net = DcNetwork::new("testnet", "alice");
        net.invite_member("bob", "alice").unwrap();
        net.accept_join("bob", TrustLevel::Full).unwrap();

        net.transfer_admin("bob", "alice").unwrap();
        assert_eq!(net.admin_uid, "bob");
        assert_eq!(net.current_leader, "bob");
        assert!(net.is_admin("bob"));
        assert!(!net.is_admin("alice"));
    }

    #[test]
    fn test_leader_rotation() {
        let mut net = DcNetwork::new("testnet", "alice");
        net.invite_member("bob", "alice").unwrap();
        net.accept_join("bob", TrustLevel::Full).unwrap();
        net.invite_member("carol", "alice").unwrap();
        net.accept_join("carol", TrustLevel::Full).unwrap();

        // Join order: alice, bob, carol
        // Current leader: alice → next should be bob
        assert_eq!(net.current_leader, "alice");
        let next = net.rotate_leader().unwrap();
        assert_eq!(next, "bob");
        assert_eq!(net.current_leader, "bob");

        // bob → next should be carol
        let next = net.rotate_leader().unwrap();
        assert_eq!(next, "carol");

        // carol → next should wrap back to alice
        let next = net.rotate_leader().unwrap();
        assert_eq!(next, "alice");
    }

    #[test]
    fn test_status_string() {
        let net = DcNetwork::new("mynet", "alice");
        let s = net.status_string();
        assert!(s.contains("mynet"));
        assert!(s.contains("alice"));
        assert!(s.contains("Marginal"));
    }
}
