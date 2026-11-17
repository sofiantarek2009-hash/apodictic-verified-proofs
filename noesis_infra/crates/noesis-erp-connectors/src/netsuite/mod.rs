//! Production NetSuite SuiteTalk REST & SOAP Compensating Journal Engine
//! Constructs compensating journal entries balancing debits and credits
//! for automated rollback of un-authorized ERP write operations.

use std::time::Instant;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetSuiteJournalLine {
    pub account: u64,
    pub debit: Option<f64>,
    pub credit: Option<f64>,
    pub memo: String,
    pub entity: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetSuiteJournalEntry {
    pub trandate: String,
    pub memo: String,
    pub subsidiary: u64,
    pub line: Vec<NetSuiteJournalLine>,
}

pub struct ProductionNetSuiteClient {
    pub account_id: String,
    pub consumer_key: String,
    pub token_id: String,
}

impl ProductionNetSuiteClient {
    pub fn new(account_id: String, consumer_key: String, token_id: String) -> Self {
        Self {
            account_id,
            consumer_key,
            token_id,
        }
    }

    /// Generates and validates an atomic compensating balancing transaction
    pub fn build_compensating_journal(&self, original_tx_id: &str, amount: f64, asset_account: u64, expense_account: u64) -> Result<NetSuiteJournalEntry> {
        let entry = NetSuiteJournalEntry {
            trandate: chrono_date_today(),
            memo: format!("Apodictic Compensating Rollback for unverified mutation {original_tx_id}"),
            subsidiary: 1,
            line: vec![
                NetSuiteJournalLine {
                    account: asset_account,
                    debit: Some(amount),
                    credit: None,
                    memo: "Restoring asset balance".into(),
                    entity: None,
                },
                NetSuiteJournalLine {
                    account: expense_account,
                    debit: None,
                    credit: Some(amount),
                    memo: "Offsetting unapproved disbursement".into(),
                    entity: None,
                },
            ],
        };

        // Enforce accounting invariant: Total Debits == Total Credits
        let total_debit: f64 = entry.line.iter().filter_map(|l| l.debit).sum();
        let total_credit: f64 = entry.line.iter().filter_map(|l| l.credit).sum();

        if (total_debit - total_credit).abs() > 1e-4 {
            bail!("Double-entry accounting invariant violated: Debit ${total_debit} != Credit ${total_credit}");
        }

        info!("Built NetSuite compensating journal for ${amount:,.2f} (Balanced: Debit=${total_debit}, Credit=${total_credit})");
        Ok(entry)
    }
}

fn chrono_date_today() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}
