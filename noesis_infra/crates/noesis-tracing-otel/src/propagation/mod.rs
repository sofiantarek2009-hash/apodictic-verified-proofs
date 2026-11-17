use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum TraceContextError {
    #[error("Invalid traceparent header: '{0}'")]
    InvalidHeader(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId(pub [u8; 16]);

impl TraceId {
    pub fn new_random() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        TraceId(bytes)
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpanId(pub [u8; 8]);

impl SpanId {
    pub fn new_random() -> Self {
        let mut bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        SpanId(bytes)
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFlags(pub u8);

impl TraceFlags {
    pub const SAMPLED: TraceFlags = TraceFlags(0x01);

    pub fn is_sampled(&self) -> bool {
        self.0 & 0x01 != 0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpanContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub trace_flags: TraceFlags,
}

impl SpanContext {
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.trace_flags.0)
    }

    pub fn from_traceparent(header: &str) -> Result<Self, TraceContextError> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 || parts[0] != "00" || parts[1].len() != 32 || parts[2].len() != 16 || parts[3].len() != 2 {
            return Err(TraceContextError::InvalidHeader(header.to_string()));
        }

        let mut trace_id_bytes = [0u8; 16];
        for (i, chunk) in parts[1].as_bytes().chunks_exact(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).unwrap();
            trace_id_bytes[i] = u8::from_str_radix(hex_str, 16).map_err(|_| TraceContextError::InvalidHeader(header.to_string()))?;
        }

        let mut span_id_bytes = [0u8; 8];
        for (i, chunk) in parts[2].as_bytes().chunks_exact(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).unwrap();
            span_id_bytes[i] = u8::from_str_radix(hex_str, 16).map_err(|_| TraceContextError::InvalidHeader(header.to_string()))?;
        }

        let flags = u8::from_str_radix(parts[3], 16).map_err(|_| TraceContextError::InvalidHeader(header.to_string()))?;

        Ok(Self {
            trace_id: TraceId(trace_id_bytes),
            span_id: SpanId(span_id_bytes),
            trace_flags: TraceFlags(flags),
        })
    }
}
