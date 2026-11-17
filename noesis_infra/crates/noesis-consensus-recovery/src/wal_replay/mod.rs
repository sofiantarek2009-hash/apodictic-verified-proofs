use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ReplayError {
    #[error("Corrupted WAL entry at index {0}: checksum mismatch")]
    ChecksumMismatch(u64),
    #[error("Non-monotonic WAL index sequence: expected {expected}, got {got}")]
    SequenceGap { expected: u64, got: u64 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReplayableWalRecord {
    pub term: u64,
    pub index: u64,
    pub payload: Vec<u8>,
    pub checksum: u32,
}

pub struct WalReplayEngine {
    state: HashMap<String, Vec<u8>>,
    last_applied_index: u64,
    last_applied_term: u64,
}

impl WalReplayEngine {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
            last_applied_index: 0,
            last_applied_term: 0,
        }
    }

    pub fn replay_records(&mut self, records: &[ReplayableWalRecord]) -> Result<u64, ReplayError> {
        for record in records {
            let expected_next = self.last_applied_index + 1;
            if self.last_applied_index > 0 && record.index != expected_next {
                return Err(ReplayError::SequenceGap {
                    expected: expected_next,
                    got: record.index,
                });
            }

            let computed_crc = crc32fast::hash(&record.payload);
            if computed_crc != record.checksum {
                return Err(ReplayError::ChecksumMismatch(record.index));
            }

            // Apply mutation into local state machine
            if let Ok(key_val) = serde_json::from_slice::<HashMap<String, String>>(&record.payload) {
                for (k, v) in key_val {
                    self.state.insert(k, v.into_bytes());
                }
            }

            self.last_applied_index = record.index;
            self.last_applied_term = record.term;
        }

        Ok(self.last_applied_index)
    }

    pub fn last_index(&self) -> u64 {
        self.last_applied_index
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.state.get(key).map(|v| v.as_slice())
    }
}
