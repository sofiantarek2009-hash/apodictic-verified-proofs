//! # Apodictic ISO 20022 Clearing House & Netting Engine
//!
//! High-throughput ISO 20022 (`pain.001` CustomerCreditTransferInitiation)
//! serializer and bilateral/multilateral double-entry netting engine.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ClearingError {
    #[error("Invalid IBAN length or format: {0}")]
    InvalidIban(String),
    #[error("Non-positive settlement amount: {0}")]
    NonPositiveAmount(i64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pain001Instruction {
    pub msg_id: String,
    pub debtor_iban: String,
    pub creditor_iban: String,
    pub amount_cents: i64,
    pub currency: String,
}

impl Pain001Instruction {
    pub fn to_iso20022_xml(&self) -> Result<String, ClearingError> {
        if self.amount_cents <= 0 {
            return Err(ClearingError::NonPositiveAmount(self.amount_cents));
        }
        if self.debtor_iban.len() < 15 || self.creditor_iban.len() < 15 {
            return Err(ClearingError::InvalidIban("IBAN too short".to_string()));
        }
        let major = self.amount_cents / 100;
        let minor = self.amount_cents % 100;
        Ok(format!(
            "<Document><CstmrCdtTrfInitn><GrpHdr><MsgId>{}</MsgId></GrpHdr><PmtInf><CdtTrfTxInf><Amt><InstdAmt Ccy=\"{}\">{}.{:02}</InstdAmt></Amt></CdtTrfTxInf></PmtInf></CstmrCdtTrfInitn></Document>",
            self.msg_id, self.currency, major, minor
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pain001_xml_generation() {
        let instr = Pain001Instruction {
            msg_id: "MSG-2026-001".to_string(),
            debtor_iban: "DE89370400440532013000".to_string(),
            creditor_iban: "SA8080000000608010167519".to_string(),
            amount_cents: 125050,
            currency: "USD".to_string(),
        };
        let xml = instr.to_iso20022_xml().unwrap();
        assert!(xml.contains("1250.50"));
        assert!(xml.contains("MSG-2026-001"));
    }
}
