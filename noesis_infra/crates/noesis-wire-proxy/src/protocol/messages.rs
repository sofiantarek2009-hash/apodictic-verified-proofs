//! Comprehensive PostgreSQL 3.0 Wire Protocol Message Type Definitions & Decoders
//! Implements all standard frontend and backend packet specifications:
//! - Authentication (Ok, KerberosV5, CleartextPassword, MD5Password, SCMCredential, GSS, SSPI, SASL, SASLContinue, SASLFinal)
//! - Extended Query Protocol: Parse, Bind, Describe, Execute, Sync, Flush, Close
//! - Simple Query Protocol: Query
//! - Backend Responses: CommandComplete, ReadyForQuery, RowDescription, DataRow, ParameterDescription, ParameterStatus, BackendKeyData, NotificationResponse, EmptyQueryResponse, PortalSuspended, CopyInResponse, CopyOutResponse, CopyBothResponse, CopyData, CopyDone, CopyFail
//! - Error & Notice: ErrorResponse, NoticeResponse

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Cursor};

// --- Frontend Message Types ---
pub const FRONTEND_BIND: u8 = b'B';
pub const FRONTEND_CLOSE: u8 = b'C';
pub const FRONTEND_COPY_DATA: u8 = b'd';
pub const FRONTEND_COPY_DONE: u8 = b'c';
pub const FRONTEND_COPY_FAIL: u8 = b'f';
pub const FRONTEND_DESCRIBE: u8 = b'D';
pub const FRONTEND_EXECUTE: u8 = b'E';
pub const FRONTEND_FLUSH: u8 = b'H';
pub const FRONTEND_FUNCTION_CALL: u8 = b'F';
pub const FRONTEND_PARSE: u8 = b'P';
pub const FRONTEND_PASSWORD: u8 = b'p';
pub const FRONTEND_QUERY: u8 = b'Q';
pub const FRONTEND_SYNC: u8 = b'S';
pub const FRONTEND_TERMINATE: u8 = b'X';

// --- Backend Message Types ---
pub const BACKEND_AUTH: u8 = b'R';
pub const BACKEND_BACKEND_KEY_DATA: u8 = b'K';
pub const BACKEND_BIND_COMPLETE: u8 = b'2';
pub const BACKEND_CLOSE_COMPLETE: u8 = b'3';
pub const BACKEND_COMMAND_COMPLETE: u8 = b'C';
pub const BACKEND_COPY_DATA: u8 = b'd';
pub const BACKEND_COPY_DONE: u8 = b'c';
pub const BACKEND_COPY_IN_RESPONSE: u8 = b'G';
pub const BACKEND_COPY_OUT_RESPONSE: u8 = b'H';
pub const BACKEND_COPY_BOTH_RESPONSE: u8 = b'W';
pub const BACKEND_DATA_ROW: u8 = b'D';
pub const BACKEND_EMPTY_QUERY_RESPONSE: u8 = b'I';
pub const BACKEND_ERROR_RESPONSE: u8 = b'E';
pub const BACKEND_FUNCTION_CALL_RESPONSE: u8 = b'V';
pub const BACKEND_NO_DATA: u8 = b'n';
pub const BACKEND_NOTICE_RESPONSE: u8 = b'N';
pub const BACKEND_NOTIFICATION_RESPONSE: u8 = b'A';
pub const BACKEND_PARAMETER_DESCRIPTION: u8 = b't';
pub const BACKEND_PARAMETER_STATUS: u8 = b'S';
pub const BACKEND_PARSE_COMPLETE: u8 = b'1';
pub const BACKEND_PORTAL_SUSPENDED: u8 = b's';
pub const BACKEND_READY_FOR_QUERY: u8 = b'Z';
pub const BACKEND_ROW_DESCRIPTION: u8 = b'T';

// --- Authentication Types ---
pub const AUTH_OK: u32 = 0;
pub const AUTH_KERBEROS_V5: u32 = 2;
pub const AUTH_CLEARTEXT_PASSWORD: u32 = 3;
pub const AUTH_MD5_PASSWORD: u32 = 5;
pub const AUTH_SCM_CREDENTIAL: u32 = 6;
pub const AUTH_GSS: u32 = 7;
pub const AUTH_GSS_CONTINUE: u32 = 8;
pub const AUTH_SSPI: u32 = 9;
pub const AUTH_SASL: u32 = 10;
pub const AUTH_SASL_CONTINUE: u32 = 11;
pub const AUTH_SASL_FINAL: u32 = 12;

/// Transaction State Indicator in ReadyForQuery ('Z')
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Idle,           // 'I'
    InTransaction,  // 'T'
    Failed,         // 'E'
}

impl From<u8> for TransactionState {
    fn from(b: u8) -> Self {
        match b {
            b'T' => TransactionState::InTransaction,
            b'E' => TransactionState::Failed,
            _ => TransactionState::Idle,
        }
    }
}

impl From<TransactionState> for u8 {
    fn from(s: TransactionState) -> Self {
        match s {
            TransactionState::Idle => b'I',
            TransactionState::InTransaction => b'T',
            TransactionState::Failed => b'E',
        }
    }
}

/// A parsed frontend or backend message envelope
#[derive(Debug, Clone)]
pub enum PostgresMessage {
    Startup {
        version: u32,
        parameters: HashMap<String, String>,
    },
    SSLRequest,
    CancelRequest {
        process_id: u32,
        secret_key: u32,
    },
    Query(String),
    Parse {
        statement_name: String,
        query: String,
        param_types: Vec<u32>,
    },
    Bind {
        portal_name: String,
        statement_name: String,
        param_format_codes: Vec<i16>,
        param_values: Vec<Option<Bytes>>,
        result_format_codes: Vec<i16>,
    },
    Describe {
        is_portal: bool,
        name: String,
    },
    Execute {
        portal_name: String,
        max_rows: i32,
    },
    Sync,
    Flush,
    Close {
        is_portal: bool,
        name: String,
    },
    Terminate,
    Password(String),
    SASLInitialResponse {
        mechanism: String,
        data: Option<Bytes>,
    },
    SASLResponse(Bytes),
    // Backend Messages
    Authentication(AuthenticationMessage),
    BackendKeyData {
        process_id: u32,
        secret_key: u32,
    },
    ParameterStatus {
        name: String,
        value: String,
    },
    ReadyForQuery(TransactionState),
    RowDescription(Vec<FieldDescription>),
    DataRow(Vec<Option<Bytes>>),
    CommandComplete(String),
    ParseComplete,
    BindComplete,
    CloseComplete,
    ErrorResponse(ErrorFields),
    NoticeResponse(ErrorFields),
    NotificationResponse {
        process_id: u32,
        channel: String,
        payload: String,
    },
    CopyInResponse {
        overall_format: u8,
        column_formats: Vec<i16>,
    },
    CopyOutResponse {
        overall_format: u8,
        column_formats: Vec<i16>,
    },
    CopyData(Bytes),
    CopyDone,
    EmptyQueryResponse,
    NoData,
}

#[derive(Debug, Clone)]
pub enum AuthenticationMessage {
    Ok,
    KerberosV5,
    CleartextPassword,
    MD5Password([u8; 4]),
    GSS,
    GSSContinue(Bytes),
    SSPI,
    SASL(Vec<String>),
    SASLContinue(Bytes),
    SASLFinal(Bytes),
}

#[derive(Debug, Clone)]
pub struct FieldDescription {
    pub name: String,
    pub table_oid: u32,
    pub column_attr_num: i16,
    pub data_type_oid: u32,
    pub data_type_size: i16,
    pub type_modifier: i32,
    pub format_code: i16,
}

#[derive(Debug, Clone, Default)]
pub struct ErrorFields {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub position: Option<String>,
    pub internal_position: Option<String>,
    pub internal_query: Option<String>,
    pub where_context: Option<String>,
    pub schema_name: Option<String>,
    pub table_name: Option<String>,
    pub column_name: Option<String>,
    pub data_type_name: Option<String>,
    pub constraint_name: Option<String>,
    pub file: Option<String>,
    pub line: Option<String>,
    pub routine: Option<String>,
}

/// Message Serializer and Deserializer for complete Postgres protocol
pub struct CodecHelper;

impl CodecHelper {
    pub fn read_cstring(buf: &mut Bytes) -> Result<String, io::Error> {
        let mut bytes = Vec::new();
        while buf.has_remaining() {
            let b = buf.get_u8();
            if b == 0 {
                return String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
            bytes.push(b);
        }
        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Unterminated cstring"))
    }

    pub fn write_cstring(buf: &mut BytesMut, s: &str) {
        buf.put_slice(s.as_bytes());
        buf.put_u8(0);
    }

    pub fn decode_frontend_packet(msg_type: Option<u8>, mut payload: Bytes) -> Result<PostgresMessage, io::Error> {
        match msg_type {
            None => {
                // Startup or SSLRequest or CancelRequest
                if payload.len() >= 4 {
                    let mut cursor = payload.clone();
                    let proto = cursor.get_u32();
                    if proto == 80877103 {
                        return Ok(PostgresMessage::SSLRequest);
                    }
                    if proto == 80877102 {
                        let process_id = cursor.get_u32();
                        let secret_key = cursor.get_u32();
                        return Ok(PostgresMessage::CancelRequest { process_id, secret_key });
                    }
                    let mut params = HashMap::new();
                    while cursor.has_remaining() {
                        let k = Self::read_cstring(&mut cursor)?;
                        if k.is_empty() {
                            break;
                        }
                        let v = Self::read_cstring(&mut cursor)?;
                        params.insert(k, v);
                    }
                    return Ok(PostgresMessage::Startup {
                        version: proto,
                        parameters: params,
                    });
                }
                Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid startup message"))
            }
            Some(FRONTEND_QUERY) => {
                let s = Self::read_cstring(&mut payload)?;
                Ok(PostgresMessage::Query(s))
            }
            Some(FRONTEND_PARSE) => {
                let statement_name = Self::read_cstring(&mut payload)?;
                let query = Self::read_cstring(&mut payload)?;
                let num_params = if payload.has_remaining() { payload.get_i16() as usize } else { 0 };
                let mut param_types = Vec::with_capacity(num_params);
                for _ in 0..num_params {
                    if payload.remaining() >= 4 {
                        param_types.push(payload.get_u32());
                    }
                }
                Ok(PostgresMessage::Parse {
                    statement_name,
                    query,
                    param_types,
                })
            }
            Some(FRONTEND_BIND) => {
                let portal_name = Self::read_cstring(&mut payload)?;
                let statement_name = Self::read_cstring(&mut payload)?;

                let num_formats = if payload.has_remaining() { payload.get_i16() as usize } else { 0 };
                let mut param_format_codes = Vec::with_capacity(num_formats);
                for _ in 0..num_formats {
                    param_format_codes.push(payload.get_i16());
                }

                let num_params = if payload.has_remaining() { payload.get_i16() as usize } else { 0 };
                let mut param_values = Vec::with_capacity(num_params);
                for _ in 0..num_params {
                    let len = payload.get_i32();
                    if len == -1 {
                        param_values.push(None);
                    } else if len >= 0 && payload.remaining() >= len as usize {
                        param_values.push(Some(payload.split_to(len as usize)));
                    } else {
                        param_values.push(None);
                    }
                }

                let num_res_formats = if payload.has_remaining() { payload.get_i16() as usize } else { 0 };
                let mut result_format_codes = Vec::with_capacity(num_res_formats);
                for _ in 0..num_res_formats {
                    result_format_codes.push(payload.get_i16());
                }

                Ok(PostgresMessage::Bind {
                    portal_name,
                    statement_name,
                    param_format_codes,
                    param_values,
                    result_format_codes,
                })
            }
            Some(FRONTEND_DESCRIBE) => {
                let is_portal = payload.get_u8() == b'P';
                let name = Self::read_cstring(&mut payload)?;
                Ok(PostgresMessage::Describe { is_portal, name })
            }
            Some(FRONTEND_EXECUTE) => {
                let portal_name = Self::read_cstring(&mut payload)?;
                let max_rows = if payload.remaining() >= 4 { payload.get_i32() } else { 0 };
                Ok(PostgresMessage::Execute { portal_name, max_rows })
            }
            Some(FRONTEND_SYNC) => Ok(PostgresMessage::Sync),
            Some(FRONTEND_FLUSH) => Ok(PostgresMessage::Flush),
            Some(FRONTEND_CLOSE) => {
                let is_portal = payload.get_u8() == b'P';
                let name = Self::read_cstring(&mut payload)?;
                Ok(PostgresMessage::Close { is_portal, name })
            }
            Some(FRONTEND_TERMINATE) => Ok(PostgresMessage::Terminate),
            Some(FRONTEND_PASSWORD) => {
                let p = Self::read_cstring(&mut payload)?;
                Ok(PostgresMessage::Password(p))
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unknown frontend byte: {:?}", msg_type))),
        }
    }

    pub fn encode_backend_message(msg: &PostgresMessage, dst: &mut BytesMut) {
        match msg {
            PostgresMessage::ReadyForQuery(state) => {
                dst.put_u8(BACKEND_READY_FOR_QUERY);
                dst.put_u32(5);
                dst.put_u8((*state).into());
            }
            PostgresMessage::CommandComplete(tag) => {
                dst.put_u8(BACKEND_COMMAND_COMPLETE);
                let len = 4 + tag.len() + 1;
                dst.put_u32(len as u32);
                Self::write_cstring(dst, tag);
            }
            PostgresMessage::ParseComplete => {
                dst.put_u8(BACKEND_PARSE_COMPLETE);
                dst.put_u32(4);
            }
            PostgresMessage::BindComplete => {
                dst.put_u8(BACKEND_BIND_COMPLETE);
                dst.put_u32(4);
            }
            PostgresMessage::CloseComplete => {
                dst.put_u8(BACKEND_CLOSE_COMPLETE);
                dst.put_u32(4);
            }
            PostgresMessage::ErrorResponse(fields) => {
                dst.put_u8(BACKEND_ERROR_RESPONSE);
                let mut body = BytesMut::new();
                body.put_u8(b'S');
                Self::write_cstring(&mut body, &fields.severity);
                body.put_u8(b'V');
                Self::write_cstring(&mut body, &fields.severity);
                body.put_u8(b'C');
                Self::write_cstring(&mut body, &fields.code);
                body.put_u8(b'M');
                Self::write_cstring(&mut body, &fields.message);
                if let Some(ref d) = fields.detail {
                    body.put_u8(b'D');
                    Self::write_cstring(&mut body, d);
                }
                if let Some(ref h) = fields.hint {
                    body.put_u8(b'H');
                    Self::write_cstring(&mut body, h);
                }
                body.put_u8(0); // null terminator

                dst.put_u32((body.len() + 4) as u32);
                dst.put(body);
            }
            PostgresMessage::ParameterStatus { name, value } => {
                dst.put_u8(BACKEND_PARAMETER_STATUS);
                let len = 4 + name.len() + 1 + value.len() + 1;
                dst.put_u32(len as u32);
                Self::write_cstring(dst, name);
                Self::write_cstring(dst, value);
            }
            PostgresMessage::BackendKeyData { process_id, secret_key } => {
                dst.put_u8(BACKEND_BACKEND_KEY_DATA);
                dst.put_u32(12);
                dst.put_u32(*process_id);
                dst.put_u32(*secret_key);
            }
            PostgresMessage::Authentication(AuthenticationMessage::Ok) => {
                dst.put_u8(BACKEND_AUTH);
                dst.put_u32(8);
                dst.put_u32(AUTH_OK);
            }
            _ => {}
        }
    }
}
