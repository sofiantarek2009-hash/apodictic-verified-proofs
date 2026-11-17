use crate::wal_replay::{ReplayableWalRecord, WalReplayEngine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchUpChunk {
    pub start_index: u64,
    pub end_index: u64,
    pub records_count: usize,
    pub is_last_chunk: bool,
}

pub struct ReplicaCatchUpCoordinator {
    engine: Arc<RwLock<WalReplayEngine>>,
    chunk_size: usize,
}

impl ReplicaCatchUpCoordinator {
    pub fn new(engine: Arc<RwLock<WalReplayEngine>>, chunk_size: usize) -> Self {
        Self { engine, chunk_size }
    }

    pub fn prepare_catch_up_slice(&self, from_index: u64, all_records: &[ReplayableWalRecord]) -> (Vec<ReplayableWalRecord>, CatchUpChunk) {
        let slice: Vec<ReplayableWalRecord> = all_records
            .iter()
            .filter(|r| r.index >= from_index)
            .take(self.chunk_size)
            .cloned()
            .collect();

        let count = slice.len();
        let (start, end, is_last) = if let (Some(first), Some(last)) = (slice.first(), slice.last()) {
            let is_last = all_records.last().map(|r| r.index == last.index).unwrap_or(true);
            (first.index, last.index, is_last)
        } else {
            (from_index, from_index, true)
        };

        let chunk = CatchUpChunk {
            start_index: start,
            end_index: end,
            records_count: count,
            is_last_chunk: is_last,
        };

        (slice, chunk)
    }

    pub fn apply_catch_up_chunk(&self, records: &[ReplayableWalRecord]) -> Result<u64, String> {
        let mut guard = self.engine.write();
        guard.replay_records(records).map_err(|e| format!("{:?}", e))
    }
}
