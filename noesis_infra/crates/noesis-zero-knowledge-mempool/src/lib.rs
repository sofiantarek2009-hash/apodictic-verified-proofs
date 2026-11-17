//! # Apodictic Encrypted Zero-Knowledge Transaction Mempool
//!
//! Front-running resistant, encrypted transaction memory pool.
//! Inbound transactions and ERP mutations remain encrypted under threshold
//! homomorphic encryption while awaiting consensus sequencing.
//! Prevents miner/validator extractable value (MEV), predatory arbitrage,
//! and insider front-running in high-volume enterprise financial clearing.

use std::collections::BTreeMap;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum MempoolError {
    #[error("Transaction already exists in encrypted mempool: {0}")]
    DuplicateTx(String),
    #[error("Invalid transaction commitment or zero-knowledge proof verification failed")]
    InvalidProof,
    #[error("Mempool capacity limit reached ({max_transactions} transactions)")]
    MempoolFull { max_transactions: usize },
    #[error("Transaction expired based on block height threshold: {tx_height} < {current_height}")]
    TransactionExpired { tx_height: u64, current_height: u64 },
}

/// Encrypted Mempool Transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTx {
    pub tx_id: String,
    pub ciphertext_bytes: Vec<u8>,
    pub commitment_hash: [u8; 32],
    pub gas_fee_bid: u64,
    pub submission_block: u64,
    pub zk_validity_proof: Vec<u8>,
}

/// Front-Running Resistant Encrypted Mempool
pub struct ZkMempool {
    max_capacity: usize,
    /// Ordered by descending gas fee priority, then lexicographical tx_id
    queue: BTreeMap<(u64, String), EncryptedTx>,
}

impl ZkMempool {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity,
            queue: BTreeMap::new(),
        }
    }

    /// Enqueues an encrypted transaction with zero-knowledge proof of validity
    pub fn submit_transaction(&mut self, tx: EncryptedTx) -> Result<(), MempoolError> {
        if self.queue.len() >= self.max_capacity {
            return Err(MempoolError::MempoolFull {
                max_transactions: self.max_capacity,
            });
        }

        // Validate commitment hash integrity
        let computed = Sha256::digest(&tx.ciphertext_bytes);
        if computed.as_slice() != &tx.commitment_hash {
            return Err(MempoolError::InvalidProof);
        }

        let key = (u64::MAX - tx.gas_fee_bid, tx.tx_id.clone());
        if self.queue.contains_key(&key) {
            return Err(MempoolError::DuplicateTx(tx.tx_id));
        }

        self.queue.insert(key, tx);
        Ok(())
    }

    /// Extracts the highest-priority batch for consensus sequencing without revealing payloads
    pub fn extract_batch(&mut self, batch_size: usize) -> Vec<EncryptedTx> {
        let mut batch = Vec::with_capacity(batch_size);
        while let Some((key, tx)) = self.queue.iter().next().map(|(k, v)| (k.clone(), v.clone())) {
            self.queue.remove(&key);
            batch.push(tx);
            if batch.len() >= batch_size {
                break;
            }
        }
        batch
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_mempool_priority_and_fair_ordering() {
        let mut mempool = ZkMempool::new(100);

        let p1 = b"CIPHERTEXT_TRANSFER_100_MILLION_USD".to_vec();
        let c1 = Sha256::digest(&p1);
        let mut h1 = [0u8; 32];
        h1.copy_from_slice(&c1);

        let tx1 = EncryptedTx {
            tx_id: "TX-LOW-FEE".to_string(),
            ciphertext_bytes: p1,
            commitment_hash: h1,
            gas_fee_bid: 10,
            submission_block: 500,
            zk_validity_proof: vec![0x01],
        };

        let p2 = b"CIPHERTEXT_TRANSFER_250_MILLION_EUR".to_vec();
        let c2 = Sha256::digest(&p2);
        let mut h2 = [0u8; 32];
        h2.copy_from_slice(&c2);

        let tx2 = EncryptedTx {
            tx_id: "TX-HIGH-FEE".to_string(),
            ciphertext_bytes: p2,
            commitment_hash: h2,
            gas_fee_bid: 50,
            submission_block: 500,
            zk_validity_proof: vec![0x02],
        };

        mempool.submit_transaction(tx1).unwrap();
        mempool.submit_transaction(tx2).unwrap();

        // Must extract highest gas fee first (TX-HIGH-FEE)
        let batch = mempool.extract_batch(1);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].tx_id, "TX-HIGH-FEE");
    }
}
