use crate::lsn::Lsn;
use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogicalDecodingError {
    #[error("Incomplete CDC replication message")]
    IncompleteMessage,
    #[error("Unknown replication message tag: {0}")]
    UnknownTag(u8),
    #[error("Invalid tuple data")]
    InvalidTupleData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TupleValue {
    Null,
    Text(String),
    UnchangedToast,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelationColumn {
    pub flags: u8,
    pub name: String,
    pub type_id: u32,
    pub type_modifier: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelationMessage {
    pub relation_id: u32,
    pub namespace: String,
    pub name: String,
    pub replica_identity: u8,
    pub columns: Vec<RelationColumn>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeginMessage {
    pub final_lsn: Lsn,
    pub commit_timestamp: i64,
    pub xid: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitMessage {
    pub flags: u8,
    pub commit_lsn: Lsn,
    pub end_lsn: Lsn,
    pub commit_timestamp: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InsertMutation {
    pub relation_id: u32,
    pub new_tuple: Vec<TupleValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateMutation {
    pub relation_id: u32,
    pub old_tuple: Option<Vec<TupleValue>>,
    pub new_tuple: Vec<TupleValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeleteMutation {
    pub relation_id: u32,
    pub old_tuple: Vec<TupleValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogicalReplicationMessage {
    Begin(BeginMessage),
    Commit(CommitMessage),
    Relation(RelationMessage),
    Insert(InsertMutation),
    Update(UpdateMutation),
    Delete(DeleteMutation),
    Type { type_id: u32, namespace: String, name: String },
}

pub struct PgOutputParser;

impl PgOutputParser {
    pub fn parse_message(buf: &[u8]) -> Result<LogicalReplicationMessage, LogicalDecodingError> {
        if buf.is_empty() {
            return Err(LogicalDecodingError::IncompleteMessage);
        }

        let tag = buf[0];
        match tag {
            b'B' => Self::parse_begin(&buf[1..]),
            b'C' => Self::parse_commit(&buf[1..]),
            b'R' => Self::parse_relation(&buf[1..]),
            b'I' => Self::parse_insert(&buf[1..]),
            b'U' => Self::parse_update(&buf[1..]),
            b'D' => Self::parse_delete(&buf[1..]),
            _ => Err(LogicalDecodingError::UnknownTag(tag)),
        }
    }

    fn parse_begin(data: &[u8]) -> Result<LogicalReplicationMessage, LogicalDecodingError> {
        if data.len() < 20 {
            return Err(LogicalDecodingError::IncompleteMessage);
        }
        let final_lsn = Lsn(BigEndian::read_u64(&data[0..8]));
        let commit_ts = BigEndian::read_i64(&data[8..16]);
        let xid = BigEndian::read_u32(&data[16..20]);

        Ok(LogicalReplicationMessage::Begin(BeginMessage {
            final_lsn,
            commit_timestamp: commit_ts,
            xid,
        }))
    }

    fn parse_commit(data: &[u8]) -> Result<LogicalReplicationMessage, LogicalDecodingError> {
        if data.len() < 25 {
            return Err(LogicalDecodingError::IncompleteMessage);
        }
        let flags = data[0];
        let commit_lsn = Lsn(BigEndian::read_u64(&data[1..9]));
        let end_lsn = Lsn(BigEndian::read_u64(&data[9..17]));
        let commit_ts = BigEndian::read_i64(&data[17..25]);

        Ok(LogicalReplicationMessage::Commit(CommitMessage {
            flags,
            commit_lsn,
            end_lsn,
            commit_timestamp: commit_ts,
        }))
    }

    fn parse_relation(data: &[u8]) -> Result<LogicalReplicationMessage, LogicalDecodingError> {
        if data.len() < 6 {
            return Err(LogicalDecodingError::IncompleteMessage);
        }
        let rel_id = BigEndian::read_u32(&data[0..4]);
        let mut idx = 4;

        let ns_end = data[idx..].iter().position(|&b| b == 0).ok_or(LogicalDecodingError::IncompleteMessage)?;
        let namespace = String::from_utf8_lossy(&data[idx..idx + ns_end]).to_string();
        idx += ns_end + 1;

        let name_end = data[idx..].iter().position(|&b| b == 0).ok_or(LogicalDecodingError::IncompleteMessage)?;
        let name = String::from_utf8_lossy(&data[idx..idx + name_end]).to_string();
        idx += name_end + 1;

        let replica_identity = data[idx];
        idx += 1;

        let num_cols = BigEndian::read_u16(&data[idx..idx + 2]) as usize;
        idx += 2;

        let mut columns = Vec::with_capacity(num_cols);
        for _ in 0..num_cols {
            let flags = data[idx];
            idx += 1;
            let col_name_end = data[idx..].iter().position(|&b| b == 0).ok_or(LogicalDecodingError::IncompleteMessage)?;
            let col_name = String::from_utf8_lossy(&data[idx..idx + col_name_end]).to_string();
            idx += col_name_end + 1;

            let type_id = BigEndian::read_u32(&data[idx..idx + 4]);
            let type_mod = BigEndian::read_i32(&data[idx + 4..idx + 8]);
            idx += 8;

            columns.push(RelationColumn {
                flags,
                name: col_name,
                type_id,
                type_modifier: type_mod,
            });
        }

        Ok(LogicalReplicationMessage::Relation(RelationMessage {
            relation_id: rel_id,
            namespace,
            name,
            replica_identity,
            columns,
        }))
    }

    fn parse_insert(data: &[u8]) -> Result<LogicalReplicationMessage, LogicalDecodingError> {
        if data.len() < 5 {
            return Err(LogicalDecodingError::IncompleteMessage);
        }
        let rel_id = BigEndian::read_u32(&data[0..4]);
        let tuple_type = data[4];
        if tuple_type != b'N' {
            return Err(LogicalDecodingError::InvalidTupleData);
        }

        let (new_tuple, _) = Self::parse_tuple(&data[5..])?;
        Ok(LogicalReplicationMessage::Insert(InsertMutation {
            relation_id: rel_id,
            new_tuple,
        }))
    }

    fn parse_update(data: &[u8]) -> Result<LogicalReplicationMessage, LogicalDecodingError> {
        if data.len() < 5 {
            return Err(LogicalDecodingError::IncompleteMessage);
        }
        let rel_id = BigEndian::read_u32(&data[0..4]);
        let mut idx = 4;
        let mut old_tuple = None;

        if data[idx] == b'K' || data[idx] == b'O' {
            idx += 1;
            let (tuple, consumed) = Self::parse_tuple(&data[idx..])?;
            old_tuple = Some(tuple);
            idx += consumed;
        }

        if data[idx] != b'N' {
            return Err(LogicalDecodingError::InvalidTupleData);
        }
        idx += 1;
        let (new_tuple, _) = Self::parse_tuple(&data[idx..])?;

        Ok(LogicalReplicationMessage::Update(UpdateMutation {
            relation_id: rel_id,
            old_tuple,
            new_tuple,
        }))
    }

    fn parse_delete(data: &[u8]) -> Result<LogicalReplicationMessage, LogicalDecodingError> {
        if data.len() < 5 {
            return Err(LogicalDecodingError::IncompleteMessage);
        }
        let rel_id = BigEndian::read_u32(&data[0..4]);
        let tuple_type = data[4];
        if tuple_type != b'K' && tuple_type != b'O' {
            return Err(LogicalDecodingError::InvalidTupleData);
        }

        let (old_tuple, _) = Self::parse_tuple(&data[5..])?;
        Ok(LogicalReplicationMessage::Delete(DeleteMutation {
            relation_id: rel_id,
            old_tuple,
        }))
    }

    fn parse_tuple(data: &[u8]) -> Result<(Vec<TupleValue>, usize), LogicalDecodingError> {
        if data.len() < 2 {
            return Err(LogicalDecodingError::IncompleteMessage);
        }
        let num_cols = BigEndian::read_u16(&data[0..2]) as usize;
        let mut idx = 2;
        let mut tuple = Vec::with_capacity(num_cols);

        for _ in 0..num_cols {
            if idx >= data.len() {
                return Err(LogicalDecodingError::IncompleteMessage);
            }
            let col_type = data[idx];
            idx += 1;

            match col_type {
                b'n' => tuple.push(TupleValue::Null),
                b'u' => tuple.push(TupleValue::UnchangedToast),
                b't' => {
                    let len = BigEndian::read_u32(&data[idx..idx + 4]) as usize;
                    idx += 4;
                    let text = String::from_utf8_lossy(&data[idx..idx + len]).to_string();
                    idx += len;
                    tuple.push(TupleValue::Text(text));
                }
                _ => return Err(LogicalDecodingError::InvalidTupleData),
            }
        }

        Ok((tuple, idx))
    }
}
