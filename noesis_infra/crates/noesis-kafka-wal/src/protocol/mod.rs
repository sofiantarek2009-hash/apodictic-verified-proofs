use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc32fast::Hasher;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalProtocolError {
    #[error("Message truncated")]
    TruncatedMessage,
    #[error("CRC32 mismatch: expected {expected:#x}, got {computed:#x}")]
    CrcMismatch { expected: u32, computed: u32 },
    #[error("Unsupported magic byte: {0}")]
    UnsupportedMagic(i8),
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecordHeader {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub offset: i64,
    pub timestamp: i64,
    pub key: Option<Vec<u8>>,
    pub value: Vec<u8>,
    pub headers: Vec<RecordHeader>,
}

pub struct RecordBatch {
    pub base_offset: i64,
    pub batch_length: i32,
    pub partition_leader_epoch: i32,
    pub magic: i8,
    pub crc: u32,
    pub attributes: i16,
    pub last_offset_delta: i32,
    pub first_timestamp: i64,
    pub max_timestamp: i64,
    pub producer_id: i64,
    pub producer_epoch: i16,
    pub base_sequence: i32,
    pub records: Vec<Record>,
}

impl RecordBatch {
    pub fn new(base_offset: i64, producer_id: i64, records: Vec<Record>) -> Self {
        let max_ts = records.iter().map(|r| r.timestamp).max().unwrap_or(0);
        let first_ts = records.first().map(|r| r.timestamp).unwrap_or(0);
        let last_offset_delta = records.len().saturating_sub(1) as i32;

        Self {
            base_offset,
            batch_length: 0,
            partition_leader_epoch: 0,
            magic: 2, // Kafka RecordBatch v2
            crc: 0,
            attributes: 0,
            last_offset_delta,
            first_timestamp: first_ts,
            max_timestamp: max_ts,
            producer_id,
            producer_epoch: 0,
            base_sequence: 0,
            records,
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut body = BytesMut::with_capacity(1024);
        body.put_i16(self.attributes);
        body.put_i32(self.last_offset_delta);
        body.put_i64(self.first_timestamp);
        body.put_i64(self.max_timestamp);
        body.put_i64(self.producer_id);
        body.put_i16(self.producer_epoch);
        body.put_i32(self.base_sequence);
        body.put_i32(self.records.len() as i32);

        for r in &self.records {
            let offset_delta = (r.offset - self.base_offset) as i32;
            body.put_i32(offset_delta);
            body.put_i64(r.timestamp);
            if let Some(ref k) = r.key {
                body.put_i32(k.len() as i32);
                body.put_slice(k);
            } else {
                body.put_i32(-1);
            }
            body.put_i32(r.value.len() as i32);
            body.put_slice(&r.value);
            body.put_i32(r.headers.len() as i32);
            for h in &r.headers {
                body.put_i32(h.key.len() as i32);
                body.put_slice(h.key.as_bytes());
                body.put_i32(h.value.len() as i32);
                body.put_slice(&h.value);
            }
        }

        let mut crc_hasher = Hasher::new();
        crc_hasher.update(&body);
        let computed_crc = crc_hasher.finalize();

        let mut frame = BytesMut::with_capacity(64 + body.len());
        frame.put_i64(self.base_offset);
        let batch_len = (49 + body.len()) as i32;
        frame.put_i32(batch_len);
        frame.put_i32(self.partition_leader_epoch);
        frame.put_i8(self.magic);
        frame.put_u32(computed_crc);
        frame.put_slice(&body);

        frame.freeze()
    }

    pub fn decode(mut src: &[u8]) -> Result<Self, WalProtocolError> {
        if src.len() < 49 {
            return Err(WalProtocolError::TruncatedMessage);
        }

        let base_offset = BigEndian::read_i64(&src[0..8]);
        let batch_length = BigEndian::read_i32(&src[8..12]);
        let partition_leader_epoch = BigEndian::read_i32(&src[12..16]);
        let magic = src[16] as i8;
        if magic != 2 {
            return Err(WalProtocolError::UnsupportedMagic(magic));
        }
        let stored_crc = BigEndian::read_u32(&src[17..21]);

        let body = &src[21..];
        let mut crc_hasher = Hasher::new();
        crc_hasher.update(body);
        let computed_crc = crc_hasher.finalize();

        if stored_crc != computed_crc {
            return Err(WalProtocolError::CrcMismatch {
                expected: stored_crc,
                computed: computed_crc,
            });
        }

        let attributes = BigEndian::read_i16(&body[0..2]);
        let last_offset_delta = BigEndian::read_i32(&body[2..6]);
        let first_timestamp = BigEndian::read_i64(&body[6..14]);
        let max_timestamp = BigEndian::read_i64(&body[14..22]);
        let producer_id = BigEndian::read_i64(&body[22..30]);
        let producer_epoch = BigEndian::read_i16(&body[30..32]);
        let base_sequence = BigEndian::read_i32(&body[32..36]);
        let record_count = BigEndian::read_i32(&body[36..40]) as usize;

        let mut offset_idx = 40;
        let mut records = Vec::with_capacity(record_count);

        for _ in 0..record_count {
            if offset_idx + 12 > body.len() {
                break;
            }
            let offset_delta = BigEndian::read_i32(&body[offset_idx..offset_idx + 4]);
            let timestamp = BigEndian::read_i64(&body[offset_idx + 4..offset_idx + 12]);
            offset_idx += 12;

            let key_len = BigEndian::read_i32(&body[offset_idx..offset_idx + 4]);
            offset_idx += 4;
            let key = if key_len >= 0 {
                let k = body[offset_idx..offset_idx + key_len as usize].to_vec();
                offset_idx += key_len as usize;
                Some(k)
            } else {
                None
            };

            let val_len = BigEndian::read_i32(&body[offset_idx..offset_idx + 4]) as usize;
            offset_idx += 4;
            let val = body[offset_idx..offset_idx + val_len].to_vec();
            offset_idx += val_len;

            let header_count = BigEndian::read_i32(&body[offset_idx..offset_idx + 4]) as usize;
            offset_idx += 4;
            let mut headers = Vec::with_capacity(header_count);

            for _ in 0..header_count {
                let hkey_len = BigEndian::read_i32(&body[offset_idx..offset_idx + 4]) as usize;
                offset_idx += 4;
                let hkey = String::from_utf8_lossy(&body[offset_idx..offset_idx + hkey_len]).to_string();
                offset_idx += hkey_len;

                let hval_len = BigEndian::read_i32(&body[offset_idx..offset_idx + 4]) as usize;
                offset_idx += 4;
                let hval = body[offset_idx..offset_idx + hval_len].to_vec();
                offset_idx += hval_len;

                headers.push(RecordHeader { key: hkey, value: hval });
            }

            records.push(Record {
                offset: base_offset + offset_delta as i64,
                timestamp,
                key,
                value: val,
                headers,
            });
        }

        Ok(Self {
            base_offset,
            batch_length,
            partition_leader_epoch,
            magic,
            crc: stored_crc,
            attributes,
            last_offset_delta,
            first_timestamp,
            max_timestamp,
            producer_id,
            producer_epoch,
            base_sequence,
            records,
        })
    }
}
