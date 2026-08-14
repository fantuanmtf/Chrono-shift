use super::round::DcRound;
use super::Participant;

pub struct DcGroup {
    pub group_id: [u8; 32],
    pub participants: Vec<Participant>,
    pub current_round: Option<DcRound>,
    pub min_participants: usize,
    pub max_dropouts: usize,
}

impl DcGroup {
    pub fn new(group_id: [u8; 32], min: usize, max_drop: usize) -> Self {
        Self {
            group_id,
            participants: Vec::new(),
            current_round: None,
            min_participants: min,
            max_dropouts: max_drop,
        }
    }
    pub fn join(&mut self, peer_id: [u8; 32]) {
        if !self.participants.iter().any(|p| p.peer_id == peer_id) {
            self.participants.push(Participant::new(peer_id));
        }
    }
    pub fn leave(&mut self, peer_id: &[u8; 32]) {
        self.participants.retain(|p| &p.peer_id != peer_id);
    }
    pub fn start_round(&mut self, round_id: u64) -> Option<&DcRound> {
        // P2 fix: filter malicious members FIRST, then check the minimum —
        // previously a round could start below min_participants after retain.
        self.participants.retain(|p| !p.is_malicious());
        if self.participants.len() < self.min_participants {
            return None;
        }
        let round = DcRound::new(round_id, self.participants.clone(), self.max_dropouts);
        self.current_round = Some(round);
        self.current_round.as_ref()
    }
    pub fn finish_round(&mut self) {
        if self.current_round.take().is_some() {
            let malicious: Vec<_> = self
                .participants
                .iter()
                .filter(|p| p.is_malicious())
                .map(|p| p.peer_id)
                .collect();
            for id in malicious {
                self.leave(&id);
            }
        }
    }

    /// Finish the current round applying real dropout penalties.
    ///
    /// P2 fix: mark_dropouts penalizes the round's participant CLONE;
    /// this writes the results back into the group (via absorb_from) and
    /// removes members that turned malicious. Returns (dropouts, malicious).
    pub fn finish_round_with(&mut self, responded: &[[u8; 32]]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let (dropouts, malicious) = match self.current_round.as_mut() {
            Some(round) => {
                let dropouts = round.mark_dropouts(responded);
                let malicious = round.remove_malicious();
                // Write-back: copy round participant state into the group.
                for rp in &round.participants {
                    if let Some(gp) = self
                        .participants
                        .iter_mut()
                        .find(|p| p.peer_id == rp.peer_id)
                    {
                        gp.absorb_from(rp);
                    }
                }
                (dropouts, malicious)
            }
            None => (Vec::new(), Vec::new()),
        };
        self.current_round = None;
        for id in &malicious {
            self.leave(id);
        }
        (dropouts, malicious)
    }
    pub fn reform(&mut self, dropouts: &[[u8; 32]]) {
        for id in dropouts {
            self.leave(id);
        }
    }
    pub fn is_healthy(&self) -> bool {
        self.participants.len() >= self.min_participants
            && self.participants.iter().all(|p| !p.is_malicious())
    }
    pub fn size(&self) -> usize {
        self.participants.len()
    }
    pub fn malicious_count(&self) -> usize {
        self.participants
            .iter()
            .filter(|p| p.is_malicious())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_group_join_leave() {
        let mut g = DcGroup::new([0u8; 32], 3, 1);
        g.join([1u8; 32]);
        g.join([2u8; 32]);
        g.join([3u8; 32]);
        assert_eq!(g.size(), 3);
        g.leave(&[1u8; 32]);
        assert_eq!(g.size(), 2);
    }
    #[test]
    fn test_group_too_small_for_round() {
        let mut g = DcGroup::new([0u8; 32], 3, 1);
        g.join([1u8; 32]);
        assert!(g.start_round(1).is_none());
    }
    #[test]
    fn test_reform_removes_dropouts() {
        let mut g = DcGroup::new([0u8; 32], 2, 1);
        g.join([1u8; 32]);
        g.join([2u8; 32]);
        g.join([3u8; 32]);
        g.reform(&[[1u8; 32], [2u8; 32]]);
        assert_eq!(g.size(), 1);
    }
    #[test]
    fn test_malicious_filtered_on_new_round() {
        let mut g = DcGroup::new([0u8; 32], 2, 1);
        g.join([1u8; 32]);
        g.join([2u8; 32]);
        if let Some(p) = g.participants.iter_mut().find(|p| p.peer_id == [1u8; 32]) {
            p.penalize();
            p.penalize();
            p.penalize();
        }
        // P2 fix: retain runs FIRST, so a round below min_participants is
        // now refused (previously it started with 1 member).
        assert!(g.start_round(1).is_none());
        assert_eq!(g.size(), 1);
    }

    #[test]
    fn test_finish_round_with_writes_back_penalties() {
        // P2 fix regression: penalties used to apply to the round's
        // participant CLONE and were discarded — dropouts never lost
        // reputation. Now three consecutive drops evict a member.
        let mut g = DcGroup::new([0u8; 32], 2, 1);
        g.join([1u8; 32]);
        g.join([2u8; 32]);
        g.join([3u8; 32]);

        for round in 1..=3 {
            assert!(g.start_round(round).is_some());
            let (dropouts, _) = g.finish_round_with(&[[1u8; 32]]);
            assert!(dropouts.contains(&[2u8; 32]), "round {} missing 2", round);
            assert!(dropouts.contains(&[3u8; 32]), "round {} missing 3", round);
        }

        // The responder survives; both dropouts were evicted after 3 rounds.
        assert!(g.participants.iter().any(|p| p.peer_id == [1u8; 32]));
        assert!(!g.participants.iter().any(|p| p.peer_id == [2u8; 32]));
        assert!(!g.participants.iter().any(|p| p.peer_id == [3u8; 32]));
    }
}
