use super::Participant;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq)]
pub enum RoundState {
    Collecting,
    Broadcasting,
    Complete,
    Failed,
}

pub struct DcRound {
    pub round_id: u64,
    pub participants: Vec<Participant>,
    pub state: RoundState,
    pub deadline: Instant,
    pub max_dropouts: usize,
}

impl DcRound {
    pub fn new(round_id: u64, participants: Vec<Participant>, max_dropouts: usize) -> Self {
        Self {
            round_id,
            participants,
            state: RoundState::Collecting,
            deadline: Instant::now() + std::time::Duration::from_secs(30),
            max_dropouts,
        }
    }
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.deadline
    }
    pub fn mark_dropouts(&mut self, responded: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut dropouts = Vec::new();
        for p in &mut self.participants {
            if !responded.iter().any(|r| r == &p.peer_id) {
                p.penalize();
                dropouts.push(p.peer_id);
            } else {
                p.reward();
            }
        }
        self.state = if dropouts.len() > self.max_dropouts {
            RoundState::Failed
        } else {
            RoundState::Complete
        };
        dropouts
    }
    pub fn remove_malicious(&mut self) -> Vec<[u8; 32]> {
        let malicious: Vec<_> = self
            .participants
            .iter()
            .filter(|p| p.is_malicious())
            .map(|p| p.peer_id)
            .collect();
        self.participants.retain(|p| !p.is_malicious());
        malicious
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_round_creation() {
        let p1 = Participant::new([1u8; 32]);
        let p2 = Participant::new([2u8; 32]);
        let r = DcRound::new(1, vec![p1, p2], 1);
        assert_eq!(r.round_id, 1);
    }
    #[test]
    fn test_mark_dropouts() {
        let p1 = Participant::new([1u8; 32]);
        let p2 = Participant::new([2u8; 32]);
        let mut r = DcRound::new(2, vec![p1, p2], 1);
        let drops = r.mark_dropouts(&[[1u8; 32]]);
        assert_eq!(drops.len(), 1);
    }
}
