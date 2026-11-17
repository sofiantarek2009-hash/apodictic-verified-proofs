use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub invariant_name: String,
    pub entity_id: u64,
    pub expected: String,
    pub actual: String,
    pub timestamp_unix: u64,
}

pub struct InvariantChecker {
    account_balances: HashMap<u64, i64>,
    total_system_debits: i64,
    total_system_credits: i64,
}

impl InvariantChecker {
    pub fn new() -> Self {
        Self {
            account_balances: HashMap::new(),
            total_system_debits: 0,
            total_system_credits: 0,
        }
    }

    pub fn set_balance(&mut self, entity_id: u64, balance: i64) {
        self.account_balances.insert(entity_id, balance);
    }

    pub fn record_transaction(&mut self, debit_entity: u64, credit_entity: u64, amount: i64) -> Result<(), InvariantViolation> {
        let deb_bal = self.account_balances.get(&debit_entity).cloned().unwrap_or(0);
        if deb_bal - amount < 0 {
            return Err(InvariantViolation {
                invariant_name: "NonNegativeSolvency".into(),
                entity_id: debit_entity,
                expected: "balance - amount >= 0".into(),
                actual: format!("{} - {} = {}", deb_bal, amount, deb_bal - amount),
                timestamp_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
        }

        self.account_balances.insert(debit_entity, deb_bal - amount);
        let cred_bal = self.account_balances.get(&credit_entity).cloned().unwrap_or(0);
        self.account_balances.insert(credit_entity, cred_bal + amount);

        self.total_system_debits += amount;
        self.total_system_credits += amount;

        Ok(())
    }

    pub fn check_conservation_invariant(&self) -> Result<(), InvariantViolation> {
        if self.total_system_debits != self.total_system_credits {
            return Err(InvariantViolation {
                invariant_name: "DoubleEntryConservation".into(),
                entity_id: 0,
                expected: "total_debits == total_credits".into(),
                actual: format!("debits: {}, credits: {}", self.total_system_debits, self.total_system_credits),
                timestamp_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
        }
        Ok(())
    }
}
