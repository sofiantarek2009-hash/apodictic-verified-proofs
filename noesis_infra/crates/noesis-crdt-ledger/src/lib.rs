//! # Apodictic Conflict-Free Replicated Financial Ledger (P-Counter CRDT)
//!
//! State-based Conflict-Free Replicated Data Type (CRDT) for multi-region active-active
//! treasury deployments. Guarantees deterministic Strong Eventual Consistency (SEC)
//! across partitioned datacenters without distributed lock contention.
//! Uses join-semilattices with mathematically proven commutativity, associativity, and idempotence.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum CrdtError {
    #[error("Actor ID mismatch or unauthorized replica mutation: {0}")]
    UnauthorizedActor(String),
    #[error("Non-monotonic decrement attempted on Positive-Counter state")]
    NonMonotonicMutation,
    #[error("Serialization / merge conflict error: {0}")]
    MergeConflict(String),
}

/// Positive-Counter (P-Counter) CRDT for distributed credit accumulations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PCounter {
    pub actor_increments: HashMap<String, u64>,
}

impl PCounter {
    pub fn new() -> Self {
        Self {
            actor_increments: HashMap::new(),
        }
    }

    /// Increments the balance on a specific replica node
    pub fn increment(&mut self, actor_id: &str, amount: u64) {
        let entry = self.actor_increments.entry(actor_id.to_string()).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    /// Evaluates current total value across all known replica states
    pub fn value(&self) -> u64 {
        self.actor_increments.values().sum()
    }

    /// Join-semilattice merge operator: LUB(A, B) = max(A.p_i, B.p_i)
    /// Deterministic, commutative, associative, and idempotent
    pub fn merge(&mut self, other: &Self) {
        for (actor, &other_val) in &other.actor_increments {
            let entry = self.actor_increments.entry(actor.clone()).or_insert(0);
            if other_val > *entry {
                *entry = other_val;
            }
        }
    }
}

/// PN-Counter CRDT (Positive-Negative Counter) supporting both deposits and withdrawals
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PNCounter {
    pub p_credits: PCounter,
    pub n_debits: PCounter,
}

impl PNCounter {
    pub fn new() -> Self {
        Self {
            p_credits: PCounter::new(),
            n_debits: PCounter::new(),
        }
    }

    pub fn deposit(&mut self, actor_id: &str, amount: u64) {
        self.p_credits.increment(actor_id, amount);
    }

    pub fn withdraw(&mut self, actor_id: &str, amount: u64) {
        self.n_debits.increment(actor_id, amount);
    }

    /// Net current balance: Total Credits - Total Debits
    pub fn balance(&self) -> i64 {
        self.p_credits.value() as i64 - self.n_debits.value() as i64
    }

    /// Replicated Join operation
    pub fn merge(&mut self, other: &Self) {
        self.p_credits.merge(&other.p_credits);
        self.n_debits.merge(&other.n_debits);
    }
}

/// Multi-Region Replicated Enterprise Account Balance CRDT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicatedAccountLedger {
    pub account_id: String,
    pub currency: String,
    pub counter: PNCounter,
    pub version_vector: HashMap<String, u64>,
}

impl ReplicatedAccountLedger {
    pub fn new(account_id: &str, currency: &str) -> Self {
        Self {
            account_id: account_id.to_string(),
            currency: currency.to_string(),
            counter: PNCounter::new(),
            version_vector: HashMap::new(),
        }
    }

    pub fn apply_credit(&mut self, replica_id: &str, amount: u64) {
        self.counter.deposit(replica_id, amount);
        let v = self.version_vector.entry(replica_id.to_string()).or_insert(0);
        *v += 1;
    }

    pub fn apply_debit(&mut self, replica_id: &str, amount: u64) {
        self.counter.withdraw(replica_id, amount);
        let v = self.version_vector.entry(replica_id.to_string()).or_insert(0);
        *v += 1;
    }

    /// Merges remote replica state asynchronously without distributed coordination locks
    pub fn merge_replica(&mut self, remote: &Self) {
        if self.account_id != remote.account_id || self.currency != remote.currency {
            return;
        }

        self.counter.merge(&remote.counter);

        for (node, &remote_v) in &remote.version_vector {
            let local_v = self.version_vector.entry(node.clone()).or_insert(0);
            if remote_v > *local_v {
                *local_v = remote_v;
            }
        }
    }

    pub fn effective_balance(&self) -> i64 {
        self.counter.balance()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crdt_three_datacenter_convergence() {
        // DC1: US-East
        let mut dc_us_east = ReplicatedAccountLedger::new("ACC-9042", "USD");
        // DC2: EU-Central
        let mut dc_eu_central = ReplicatedAccountLedger::new("ACC-9042", "USD");
        // DC3: AP-East
        let mut dc_ap_east = ReplicatedAccountLedger::new("ACC-9042", "USD");

        // Concurrent operations during network partition
        dc_us_east.apply_credit("us-east-node1", 500_000);
        dc_eu_central.apply_credit("eu-central-node1", 300_000);
        dc_ap_east.apply_debit("ap-east-node1", 150_000);

        // Partition heals: Gossip gossip reconciliation
        dc_us_east.merge_replica(&dc_eu_central);
        dc_eu_central.merge_replica(&dc_ap_east);
        dc_ap_east.merge_replica(&dc_us_east);

        // Final full mesh sync
        dc_us_east.merge_replica(&dc_ap_east);
        dc_eu_central.merge_replica(&dc_us_east);

        // All three datacenters must reach the exact same mathematical balance (500k + 300k - 150k = 650k)
        assert_eq!(dc_us_east.effective_balance(), 650_000);
        assert_eq!(dc_eu_central.effective_balance(), 650_000);
        assert_eq!(dc_ap_east.effective_balance(), 650_000);
    }
}
