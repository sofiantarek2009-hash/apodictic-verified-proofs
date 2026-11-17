//! Raft Chunked State Machine Snapshot Streaming Protocol (InstallSnapshot RPC)
//! Allows followers that lag far behind the commit index to receive a complete
//! binary state machine snapshot without replaying millions of historical WAL entries.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};

pub const SNAPSHOT_CHUNK_SIZE: usize = 1024 * 1024; // 1 MB chunks

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotChunk {
    pub term: u64,
    pub leader_id: String,
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub byte_offset: u64,
    pub data: Bytes,
    pub done: bool,
}

pub struct SnapshotStreamer {
    snapshot_path: PathBuf,
    file_size: u64,
    current_offset: u64,
    last_included_index: u64,
    last_included_term: u64,
}

impl SnapshotStreamer {
    pub fn open<P: AsRef<Path>>(path: P, last_included_index: u64, last_included_term: u64) -> Result<Self> {
        let p = path.as_ref().to_path_buf();
        let meta = std::fs::metadata(&p).context("Failed to get snapshot metadata")?;
        let file_size = meta.len();

        Ok(Self {
            snapshot_path: p,
            file_size,
            current_offset: 0,
            last_included_index,
            last_included_term,
        })
    }

    pub fn next_chunk(&mut self, term: u64, leader_id: &str) -> Result<Option<InstallSnapshotChunk>> {
        if self.current_offset >= self.file_size {
            return Ok(None);
        }

        let mut f = File::open(&self.snapshot_path)?;
        f.seek(SeekFrom::Start(self.current_offset))?;

        let remaining = (self.file_size - self.current_offset) as usize;
        let read_len = remaining.min(SNAPSHOT_CHUNK_SIZE);

        let mut buf = vec![0u8; read_len];
        f.read_exact(&mut buf)?;

        let byte_offset = self.current_offset;
        self.current_offset += read_len as u64;
        let done = self.current_offset >= self.file_size;

        Ok(Some(InstallSnapshotChunk {
            term,
            leader_id: leader_id.to_string(),
            last_included_index: self.last_included_index,
            last_included_term: self.last_included_term,
            byte_offset,
            data: Bytes::from(buf),
            done,
        }))
    }
}
