use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum LsnError {
    #[error("Invalid LSN format: expected 'X/Y', got '{0}'")]
    InvalidFormat(String),
    #[error("Failed to parse hex integer: {0}")]
    ParseHex(#[from] std::num::ParseIntError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Lsn(pub u64);

impl Lsn {
    pub const INVALID: Lsn = Lsn(0);

    pub fn from_parts(file_id: u32, offset: u32) -> Self {
        Lsn(((file_id as u64) << 32) | (offset as u64))
    }

    pub fn file_id(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub fn offset(&self) -> u32 {
        self.0 as u32
    }

    pub fn advance(&self, bytes: u64) -> Self {
        Lsn(self.0 + bytes)
    }
}

impl fmt::Display for Lsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}/{:X}", self.file_id(), self.offset())
    }
}

impl FromStr for Lsn {
    type Err = LsnError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(LsnError::InvalidFormat(s.to_string()));
        }

        let file_id = u32::from_str_radix(parts[0], 16)?;
        let offset = u32::from_str_radix(parts[1], 16)?;

        Ok(Lsn::from_parts(file_id, offset))
    }
}
