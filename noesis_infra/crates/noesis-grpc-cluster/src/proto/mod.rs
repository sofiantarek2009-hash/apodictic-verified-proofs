use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("Varint decoding overflow")]
    VarintOverflow,
    #[error("Buffer truncated")]
    BufferTruncated,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterNodeInfo {
    pub node_id: u64,
    pub address: String,
    pub grpc_port: u16,
    pub raft_port: u16,
    pub is_leader: bool,
    pub term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsensusVoteRequest {
    pub term: u64,
    pub candidate_id: u64,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsensusVoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplicationAppendRequest {
    pub term: u64,
    pub leader_id: u64,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<Vec<u8>>,
    pub leader_commit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplicationAppendResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
}

pub struct GrpcFrameCodec;

impl GrpcFrameCodec {
    // gRPC frame prefix: 1 compressed flag byte + 4 message length bytes (BigEndian)
    pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Bytes, ProtoError> {
        let payload = serde_json::to_vec(msg).map_err(|e| ProtoError::Serialization(e.to_string()))?;
        let mut frame = BytesMut::with_capacity(5 + payload.len());
        frame.put_u8(0); // uncompressed
        frame.put_u32(payload.len() as u32);
        frame.put_slice(&payload);
        Ok(frame.freeze())
    }

    pub fn decode_frame<T: for<'de> Deserialize<'de>>(buf: &mut BytesMut) -> Result<Option<T>, ProtoError> {
        if buf.len() < 5 {
            return Ok(None);
        }

        let _compressed = buf[0];
        let len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;

        if buf.len() < 5 + len {
            return Ok(None);
        }

        buf.advance(5);
        let payload = buf.split_to(len);
        let msg = serde_json::from_slice(&payload).map_err(|e| ProtoError::Serialization(e.to_string()))?;

        Ok(Some(msg))
    }
}
