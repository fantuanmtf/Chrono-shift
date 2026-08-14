use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reputation {
    pub peer_id: Vec<u8>,
    pub score: f64,
    pub rounds_total: u64,
    pub rounds_dropped: u64,
    pub consecutive_drops: u32,
    pub drop_timing_pct: Vec<u8>,
    pub first_seen: u64,
    pub banned: bool,
}

impl Reputation {
    pub fn new(peer_id: Vec<u8>) -> Self {
        Self {
            peer_id,
            score: 0.5,
            rounds_total: 0,
            rounds_dropped: 0,
            consecutive_drops: 0,
            drop_timing_pct: Vec::new(),
            first_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            banned: false,
        }
    }
    pub fn reward(&mut self) {
        self.rounds_total += 1;
        self.consecutive_drops = 0;
        self.score = (self.score + 0.05).min(1.0);
    }
    pub fn penalize(&mut self, timing_pct: u8) {
        self.rounds_total += 1;
        self.rounds_dropped += 1;
        self.consecutive_drops += 1;
        self.drop_timing_pct.push(timing_pct);
        self.score *= 0.7;
    }
    pub fn is_malicious(&self) -> bool {
        if self.banned {
            return true;
        }
        if self.consecutive_drops >= 3 {
            let late = self
                .drop_timing_pct
                .iter()
                .rev()
                .take(3)
                .filter(|&&p| p > 80)
                .count();
            if late >= 2 {
                return true;
            }
        }
        if self.rounds_total >= 10 && self.rounds_dropped as f64 / self.rounds_total as f64 > 0.5 {
            return true;
        }
        self.score < 0.3
    }
    pub fn ban(&mut self) {
        self.banned = true;
        self.score = 0.0;
    }
    /// Map reputation score to the unified 0..=2 trust scale
    /// (0 = UNVERIFIED, 1 = VERIFIED, 2 = FULL_TRUST).
    ///
    /// P0 fix: previously used a different 0..=3 scale with different
    /// thresholds than sync_reputation_to_trust — the same score could land
    /// on different levels depending on which function you asked.
    pub fn trust_level(&self) -> u8 {
        if self.banned {
            0
        } else if self.score >= 0.8 {
            2
        } else if self.score >= 0.5 {
            1
        } else {
            0
        }
    }
}

pub struct ReputationManager {
    peers: HashMap<Vec<u8>, Reputation>,
}

impl Default for ReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }
    pub fn get_or_create(&mut self, peer_id: &[u8]) -> &mut Reputation {
        self.peers
            .entry(peer_id.to_vec())
            .or_insert_with(|| Reputation::new(peer_id.to_vec()))
    }
    pub fn get(&self, peer_id: &[u8]) -> Option<&Reputation> {
        self.peers.get(peer_id)
    }
    pub fn process_round(
        &mut self,
        responded: &[Vec<u8>],
        all: &[Vec<u8>],
        round_pct: u8,
    ) -> Vec<Vec<u8>> {
        let mut malicious = Vec::new();
        for pid in all {
            let rep = self.get_or_create(pid);
            if responded.contains(pid) {
                rep.reward();
            } else {
                rep.penalize(round_pct);
                if rep.is_malicious() {
                    rep.ban();
                    malicious.push(pid.clone());
                }
            }
        }
        malicious
    }
    pub fn top_trusted(&self, n: usize) -> Vec<&Reputation> {
        let mut all: Vec<_> = self.peers.values().filter(|r| !r.banned).collect();
        all.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        all.truncate(n);
        all
    }
    pub fn banned_count(&self) -> usize {
        self.peers.values().filter(|r| r.banned).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_new_node_score() {
        let r = Reputation::new(vec![1, 2, 3]);
        assert_eq!(r.score, 0.5);
    }
    #[test]
    fn test_reward_increases_score() {
        let mut r = Reputation::new(vec![1]);
        r.reward();
        assert!(r.score > 0.5);
    }
    #[test]
    fn test_consecutive_drops_detected() {
        let mut r = Reputation::new(vec![1]);
        r.penalize(90);
        r.penalize(90);
        r.penalize(90);
        assert!(r.is_malicious());
    }
    #[test]
    fn test_drop_rate_over_50_pct() {
        let mut r = Reputation::new(vec![1]);
        for _ in 0..10 {
            r.penalize(50);
        }
        assert!(r.is_malicious());
    }
    #[test]
    fn test_reputation_manager() {
        let mut mgr = ReputationManager::new();
        let all = vec![vec![1u8], vec![2], vec![3]];
        let resp = vec![vec![1u8], vec![3]];
        for _ in 0..3 {
            mgr.process_round(&resp, &all, 90);
        }
        assert_eq!(mgr.banned_count(), 1);
    }
}
