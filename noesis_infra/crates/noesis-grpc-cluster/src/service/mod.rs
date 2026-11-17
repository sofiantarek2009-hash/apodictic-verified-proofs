use crate::proto::{ConsensusVoteRequest, ConsensusVoteResponse, ReplicationAppendRequest, ReplicationAppendResponse};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct ConsensusRpcService {
    current_term: AtomicU64,
    voted_for: RwLock<Option<u64>>,
    log_entries: RwLock<Vec<(u64, Vec<u8>)>>, // (term, data)
    commit_index: AtomicU64,
    node_id: u64,
}

impl ConsensusRpcService {
    pub fn new(node_id: u64) -> Self {
        Self {
            current_term: AtomicU64::new(0),
            voted_for: RwLock::new(None),
            log_entries: RwLock::new(Vec::new()),
            commit_index: AtomicU64::new(0),
            node_id,
        }
    }

    pub fn handle_vote(&self, req: ConsensusVoteRequest) -> ConsensusVoteResponse {
        let current = self.current_term.load(Ordering::SeqCst);

        if req.term < current {
            return ConsensusVoteResponse {
                term: current,
                vote_granted: false,
            };
        }

        if req.term > current {
            self.current_term.store(req.term, Ordering::SeqCst);
            *self.voted_for.write() = None;
        }

        let mut voted_guard = self.voted_for.write();
        let vote_granted = match *voted_guard {
            None => {
                *voted_guard = Some(req.candidate_id);
                true
            }
            Some(cand) if cand == req.candidate_id => true,
            _ => false,
        };

        ConsensusVoteResponse {
            term: self.current_term.load(Ordering::SeqCst),
            vote_granted,
        }
    }

    pub fn handle_append(&self, req: ReplicationAppendRequest) -> ReplicationAppendResponse {
        let current = self.current_term.load(Ordering::SeqCst);

        if req.term < current {
            return ReplicationAppendResponse {
                term: current,
                success: false,
                match_index: self.log_entries.read().len() as u64,
            };
        }

        if req.term > current {
            self.current_term.store(req.term, Ordering::SeqCst);
            *self.voted_for.write() = None;
        }

        let mut log = self.log_entries.write();
        if req.prev_log_index > 0 && req.prev_log_index as usize > log.len() {
            return ReplicationAppendResponse {
                term: req.term,
                success: false,
                match_index: log.len() as u64,
            };
        }

        for entry in req.entries {
            log.push((req.term, entry));
        }

        let match_index = log.len() as u64;
        if req.leader_commit > self.commit_index.load(Ordering::SeqCst) {
            self.commit_index.store(req.leader_commit.min(match_index), Ordering::SeqCst);
        }

        ReplicationAppendResponse {
            term: req.term,
            success: true,
            match_index,
        }
    }
}
