use bytes::{Buf, Bytes, BytesMut};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum RespError {
    #[error("Incomplete RESP frame")]
    Incomplete,
    #[error("Protocol error: {0}")]
    Protocol(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RespValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Bytes>),
    Array(Option<Vec<RespValue>>),
    Null,
    Boolean(bool),
    Double(f64),
    Map(Vec<(RespValue, RespValue)>),
    Set(Vec<RespValue>),
}

pub struct RespParser;

impl RespParser {
    pub fn parse(buf: &mut BytesMut) -> Result<RespValue, RespError> {
        if buf.is_empty() {
            return Err(RespError::Incomplete);
        }

        let prefix = buf[0];
        match prefix {
            b'+' => Self::parse_simple_string(buf),
            b'-' => Self::parse_error(buf),
            b':' => Self::parse_integer(buf),
            b'$' => Self::parse_bulk_string(buf),
            b'*' => Self::parse_array(buf),
            b'_' => {
                // RESP3 Null
                if buf.len() < 3 {
                    return Err(RespError::Incomplete);
                }
                if &buf[1..3] == b"\r\n" {
                    buf.advance(3);
                    Ok(RespValue::Null)
                } else {
                    Err(RespError::Protocol("Invalid Null frame".into()))
                }
            }
            b'#' => {
                // RESP3 Boolean
                if buf.len() < 4 {
                    return Err(RespError::Incomplete);
                }
                let val = match buf[1] {
                    b't' => true,
                    b'f' => false,
                    _ => return Err(RespError::Protocol("Invalid boolean format".into())),
                };
                buf.advance(4);
                Ok(RespValue::Boolean(val))
            }
            _ => Err(RespError::Protocol(format!("Unsupported prefix byte: {}", prefix as char))),
        }
    }

    fn find_crlf(buf: &[u8]) -> Option<usize> {
        for i in 0..buf.len().saturating_sub(1) {
            if buf[i] == b'\r' && buf[i + 1] == b'\n' {
                return Some(i);
            }
        }
        None
    }

    fn parse_simple_string(buf: &mut BytesMut) -> Result<RespValue, RespError> {
        let crlf = Self::find_crlf(buf).ok_or(RespError::Incomplete)?;
        let line = &buf[1..crlf];
        let s = String::from_utf8_lossy(line).to_string();
        buf.advance(crlf + 2);
        Ok(RespValue::SimpleString(s))
    }

    fn parse_error(buf: &mut BytesMut) -> Result<RespValue, RespError> {
        let crlf = Self::find_crlf(buf).ok_or(RespError::Incomplete)?;
        let line = &buf[1..crlf];
        let s = String::from_utf8_lossy(line).to_string();
        buf.advance(crlf + 2);
        Ok(RespValue::Error(s))
    }

    fn parse_integer(buf: &mut BytesMut) -> Result<RespValue, RespError> {
        let crlf = Self::find_crlf(buf).ok_or(RespError::Incomplete)?;
        let line = std::str::from_utf8(&buf[1..crlf])
            .map_err(|_| RespError::Protocol("Invalid integer utf8".into()))?;
        let num: i64 = line.parse().map_err(|_| RespError::Protocol("Failed to parse integer".into()))?;
        buf.advance(crlf + 2);
        Ok(RespValue::Integer(num))
    }

    fn parse_bulk_string(buf: &mut BytesMut) -> Result<RespValue, RespError> {
        let crlf = Self::find_crlf(buf).ok_or(RespError::Incomplete)?;
        let len_str = std::str::from_utf8(&buf[1..crlf])
            .map_err(|_| RespError::Protocol("Invalid bulk string length utf8".into()))?;
        let len: i64 = len_str.parse().map_err(|_| RespError::Protocol("Failed to parse length".into()))?;

        if len == -1 {
            buf.advance(crlf + 2);
            return Ok(RespValue::BulkString(None));
        }

        let total_needed = crlf + 2 + len as usize + 2;
        if buf.len() < total_needed {
            return Err(RespError::Incomplete);
        }

        buf.advance(crlf + 2);
        let data = buf.split_to(len as usize).freeze();
        buf.advance(2); // advance CRLF
        Ok(RespValue::BulkString(Some(data)))
    }

    fn parse_array(buf: &mut BytesMut) -> Result<RespValue, RespError> {
        let crlf = Self::find_crlf(buf).ok_or(RespError::Incomplete)?;
        let len_str = std::str::from_utf8(&buf[1..crlf])
            .map_err(|_| RespError::Protocol("Invalid array length utf8".into()))?;
        let len: i64 = len_str.parse().map_err(|_| RespError::Protocol("Failed to parse array length".into()))?;

        if len == -1 {
            buf.advance(crlf + 2);
            return Ok(RespValue::Array(None));
        }

        buf.advance(crlf + 2);
        let mut items = Vec::with_capacity(len as usize);
        for _ in 0..len {
            items.push(Self::parse(buf)?);
        }

        Ok(RespValue::Array(Some(items)))
    }

    pub fn serialize(val: &RespValue) -> Vec<u8> {
        let mut out = Vec::new();
        match val {
            RespValue::SimpleString(s) => {
                out.extend_from_slice(format!("+{}\r\n", s).as_bytes());
            }
            RespValue::Error(e) => {
                out.extend_from_slice(format!("-{}\r\n", e).as_bytes());
            }
            RespValue::Integer(i) => {
                out.extend_from_slice(format!(":{}\r\n", i).as_bytes());
            }
            RespValue::BulkString(None) => {
                out.extend_from_slice(b"$-1\r\n");
            }
            RespValue::BulkString(Some(b)) => {
                out.extend_from_slice(format!("${}\r\n", b.len()).as_bytes());
                out.extend_from_slice(b);
                out.extend_from_slice(b"\r\n");
            }
            RespValue::Array(None) => {
                out.extend_from_slice(b"*-1\r\n");
            }
            RespValue::Array(Some(items)) => {
                out.extend_from_slice(format!("*{}\r\n", items.len()).as_bytes());
                for item in items {
                    out.extend_from_slice(&Self::serialize(item));
                }
            }
            RespValue::Null => {
                out.extend_from_slice(b"_\r\n");
            }
            RespValue::Boolean(b) => {
                if *b {
                    out.extend_from_slice(b"#t\r\n");
                } else {
                    out.extend_from_slice(b"#f\r\n");
                }
            }
            _ => {
                out.extend_from_slice(b"+OK\r\n");
            }
        }
        out
    }
}
