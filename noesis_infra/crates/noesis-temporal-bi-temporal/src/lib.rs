//! # Apodictic SQL:2011 Bi-Temporal Time-Travel Accounting Database Engine
//!
//! True dual-timeline relational storage separating:
//! 1. Valid Time (Business Time): When an economic transaction physically occurred.
//! 2. System Time (Transaction Time): When the transaction was recorded in the database.
//! Enables retroactive accounting adjustments, restatements, and statutory
//! audits without rewriting history, preserving absolute legal non-repudiation.

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum BiTemporalError {
    #[error("Invalid time interval: start ({start_ms}) > end ({end_ms})")]
    InvalidInterval { start_ms: u64, end_ms: u64 },
    #[error("System time is strictly monotonic and cannot be modified retroactively")]
    ImmutableSystemTimeViolation,
    #[error("Entity not found: {0}")]
    EntityNotFound(String),
}

/// Time interval [start, end)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimePeriod {
    pub start_ms: u64,
    pub end_ms: u64, // u64::MAX represents infinity / currently valid
}

impl TimePeriod {
    pub fn new(start: u64, end: u64) -> Result<Self, BiTemporalError> {
        if start > end {
            return Err(BiTemporalError::InvalidInterval {
                start_ms: start,
                end_ms: end,
            });
        }
        Ok(Self { start_ms: start, end_ms: end })
    }

    pub fn contains(&self, timestamp: u64) -> bool {
        timestamp >= self.start_ms && timestamp < self.end_ms
    }
}

/// Bi-Temporal Versioned Record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiTemporalRecord<T: Clone> {
    pub entity_id: String,
    pub data: T,
    /// When the event physically held in the real world
    pub valid_time: TimePeriod,
    /// When the event was written to the ledger (immutable append-only)
    pub system_time: TimePeriod,
}

/// Bi-Temporal Ledger Table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiTemporalTable<T: Clone> {
    pub table_name: String,
    records: Vec<BiTemporalRecord<T>>,
}

impl<T: Clone> BiTemporalTable<T> {
    pub fn new(table_name: &str) -> Self {
        Self {
            table_name: table_name.to_string(),
            records: Vec::new(),
        }
    }

    /// Records an initial fact with valid time and current system time
    pub fn insert_fact(
        &mut self,
        entity_id: &str,
        data: T,
        valid_start: u64,
        valid_end: u64,
        now_system_time: u64,
    ) -> Result<(), BiTemporalError> {
        let valid_time = TimePeriod::new(valid_start, valid_end)?;
        let system_time = TimePeriod::new(now_system_time, u64::MAX)?;

        self.records.push(BiTemporalRecord {
            entity_id: entity_id.to_string(),
            data,
            valid_time,
            system_time,
        });

        Ok(())
    }

    /// Performs retroactive adjustment: Closes previous system time and appends updated record
    pub fn retroactive_adjustment(
        &mut self,
        entity_id: &str,
        new_data: T,
        effective_valid_start: u64,
        effective_valid_end: u64,
        adjustment_timestamp: u64,
    ) -> Result<(), BiTemporalError> {
        // 1. Close system time of existing active records for this entity
        for rec in self.records.iter_mut() {
            if rec.entity_id == entity_id && rec.system_time.end_ms == u64::MAX {
                rec.system_time.end_ms = adjustment_timestamp;
            }
        }

        // 2. Insert new version reflecting retroactive business validity
        let valid_time = TimePeriod::new(effective_valid_start, effective_valid_end)?;
        let system_time = TimePeriod::new(adjustment_timestamp, u64::MAX)?;

        self.records.push(BiTemporalRecord {
            entity_id: entity_id.to_string(),
            data: new_data,
            valid_time,
            system_time,
        });

        Ok(())
    }

    /// Point-in-time time-travel query: "What did we know as of system_time T_sys about business state at valid_time T_val?"
    pub fn as_of(&self, entity_id: &str, valid_time: u64, system_time: u64) -> Option<&T> {
        for rec in self.records.iter().rev() {
            if rec.entity_id == entity_id
                && rec.valid_time.contains(valid_time)
                && rec.system_time.contains(system_time)
            {
                return Some(&rec.data);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct AccountBalance {
        amount_cents: i64,
        currency: String,
    }

    #[test]
    fn test_bi_temporal_retroactive_audit_restatement() {
        let mut table = BiTemporalTable::<AccountBalance>::new("general_ledger_balances");

        // Day 1 (T=100 sys): Record balance of $10,000 for Q1 (T=10 to T=50 valid)
        table.insert_fact(
            "ACC-100",
            AccountBalance { amount_cents: 10_000_00, currency: "USD".to_string() },
            10,
            50,
            100,
        ).unwrap();

        // Query as of Day 2 (T=150 sys) for Q1 (T=25 valid) -> Should see $10,000
        let val_day2 = table.as_of("ACC-100", 25, 150).unwrap();
        assert_eq!(val_day2.amount_cents, 10_000_00);

        // Day 3 (T=200 sys): Audit discovers missing invoice, retroactively rests balance for Q1 to $12,500
        table.retroactive_adjustment(
            "ACC-100",
            AccountBalance { amount_cents: 12_500_00, currency: "USD".to_string() },
            10,
            50,
            200,
        ).unwrap();

        // Time travel verification:
        // 1. What did we know on Day 2? Exactly $10,000 (Immutable audit trail preserved)
        let audit_query = table.as_of("ACC-100", 25, 150).unwrap();
        assert_eq!(audit_query.amount_cents, 10_000_00);

        // 2. What do we know now on Day 4 (T=250 sys)? Restated to $12,500
        let current_query = table.as_of("ACC-100", 25, 250).unwrap();
        assert_eq!(current_query.amount_cents, 12_500_00);
    }
}
