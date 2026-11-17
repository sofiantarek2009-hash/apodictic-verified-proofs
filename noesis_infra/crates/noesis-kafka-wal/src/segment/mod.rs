use crate::protocol::{Record, RecordBatch, WalProtocolError};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SegmentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] WalProtocolError),
    #[error("Segment capacity exceeded")]
    SegmentFull,
}

#[derive(Debug, Clone, Copy)]
pub struct IndexEntry {
    pub relative_offset: u32,
    pub physical_position: u32,
}

pub struct LogSegment {
    pub base_offset: i64,
    pub next_offset: i64,
    pub max_size_bytes: usize,
    pub current_size_bytes: usize,
    log_path: PathBuf,
    index_path: PathBuf,
    log_file: File,
    index_file: File,
    index: Vec<IndexEntry>,
}

impl LogSegment {
    pub fn open(dir: &Path, base_offset: i64, max_size_bytes: usize) -> Result<Self, SegmentError> {
        let log_name = format!("{:020}.log", base_offset);
        let idx_name = format!("{:020}.index", base_offset);
        let log_path = dir.join(log_name);
        let index_path = dir.join(idx_name);

        let mut log_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&log_path)?;

        let mut index_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&index_path)?;

        let current_size_bytes = log_file.metadata()?.len() as usize;

        // Read existing index entries (8 bytes each: 4 bytes rel_offset, 4 bytes physical_pos)
        let mut idx_bytes = Vec::new();
        index_file.read_to_end(&mut idx_bytes)?;
        let mut index = Vec::new();
        for chunk in idx_bytes.chunks_exact(8) {
            let rel_offset = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
            let physical_pos = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
            index.push(IndexEntry {
                relative_offset: rel_offset,
                physical_position: physical_pos,
            });
        }

        let next_offset = if let Some(last) = index.last() {
            base_offset + last.relative_offset as i64 + 1
        } else {
            base_offset
        };

        Ok(Self {
            base_offset,
            next_offset,
            max_size_bytes,
            current_size_bytes,
            log_path,
            index_path,
            log_file,
            index_file,
            index,
        })
    }

    pub fn append(&mut self, batch: &RecordBatch) -> Result<u64, SegmentError> {
        let encoded = batch.encode();
        if self.current_size_bytes + encoded.len() > self.max_size_bytes {
            return Err(SegmentError::SegmentFull);
        }

        let physical_pos = self.current_size_bytes as u32;
        let relative_offset = (batch.base_offset - self.base_offset) as u32;

        self.log_file.seek(SeekFrom::End(0))?;
        self.log_file.write_all(&encoded)?;
        self.log_file.sync_data()?;

        let mut idx_buf = [0u8; 8];
        idx_buf[0..4].copy_from_slice(&relative_offset.to_be_bytes());
        idx_buf[4..8].copy_from_slice(&physical_pos.to_be_bytes());

        self.index_file.seek(SeekFrom::End(0))?;
        self.index_file.write_all(&idx_buf)?;
        self.index_file.sync_data()?;

        self.index.push(IndexEntry {
            relative_offset,
            physical_position: physical_pos,
        });

        self.current_size_bytes += encoded.len();
        self.next_offset = batch.base_offset + batch.records.len() as i64;

        Ok(self.next_offset as u64)
    }

    pub fn read_batch_at(&mut self, physical_pos: u32) -> Result<RecordBatch, SegmentError> {
        self.log_file.seek(SeekFrom::Start(physical_pos as u64))?;
        let mut header = [0u8; 49];
        self.log_file.read_exact(&mut header)?;
        let batch_len = i32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;

        let mut full_buf = vec![0u8; batch_len + 12];
        full_buf[0..49].copy_from_slice(&header);
        self.log_file.read_exact(&mut full_buf[49..batch_len + 12])?;

        let batch = RecordBatch::decode(&full_buf)?;
        Ok(batch)
    }

    pub fn lookup_offset(&self, target_offset: i64) -> Option<u32> {
        if target_offset < self.base_offset {
            return None;
        }
        let target_rel = (target_offset - self.base_offset) as u32;

        // Binary search for closest index entry <= target_rel
        match self.index.binary_search_by_key(&target_rel, |entry| entry.relative_offset) {
            Ok(idx) => Some(self.index[idx].physical_position),
            Err(idx) => {
                if idx == 0 {
                    Some(0)
                } else {
                    Some(self.index[idx - 1].physical_position)
                }
            }
        }
    }
}
