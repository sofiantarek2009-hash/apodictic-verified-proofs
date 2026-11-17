//! Production Version Edit & Manifest Journal for Apodictic LSM-DB
//! Implements LevelDB/RocksDB-style MANIFEST persistence:
//! - Atomically records added and deleted SSTable files per level
//! - Comparator name and log number tracking
//! - WAL sequence number checkpoints
//! - Binary log record formatting with CRC32 verification

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc32fast::Hasher;
use parking_lot::Mutex;
use tracing::info;

pub const MANIFEST_MAGIC: u64 = 0x4d414e4946455354; // "MANIFEST"

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEdit {
    AddFile {
        level: u32,
        file_number: u64,
        file_size: u64,
        smallest_key: Bytes,
        largest_key: Bytes,
    },
    DeleteFile {
        level: u32,
        file_number: u64,
    },
}

#[derive(Debug, Clone, Default)]
pub struct VersionEdit {
    pub comparator_name: Option<String>,
    pub log_number: Option<u64>,
    pub prev_log_number: Option<u64>,
    pub next_file_number: Option<u64>,
    pub last_sequence: Option<u64>,
    pub edits: Vec<FileEdit>,
}

impl VersionEdit {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u64(MANIFEST_MAGIC);

        if let Some(ref comp) = self.comparator_name {
            buf.put_u8(1);
            buf.put_u16(comp.len() as u16);
            buf.put_slice(comp.as_bytes());
        }

        if let Some(log_num) = self.log_number {
            buf.put_u8(2);
            buf.put_u64(log_num);
        }

        if let Some(next_file) = self.next_file_number {
            buf.put_u8(3);
            buf.put_u64(next_file);
        }

        if let Some(last_seq) = self.last_sequence {
            buf.put_u8(4);
            buf.put_u64(last_seq);
        }

        for edit in &self.edits {
            match edit {
                FileEdit::AddFile { level, file_number, file_size, smallest_key, largest_key } => {
                    buf.put_u8(5);
                    buf.put_u32(*level);
                    buf.put_u64(*file_number);
                    buf.put_u64(*file_size);
                    buf.put_u32(smallest_key.len() as u32);
                    buf.put_slice(smallest_key);
                    buf.put_u32(largest_key.len() as u32);
                    buf.put_slice(largest_key);
                }
                FileEdit::DeleteFile { level, file_number } => {
                    buf.put_u8(6);
                    buf.put_u32(*level);
                    buf.put_u64(*file_number);
                }
            }
        }
        buf.freeze()
    }
}

pub struct ManifestWriter {
    file: Mutex<File>,
    manifest_number: u64,
}

impl ManifestWriter {
    pub fn open<P: AsRef<Path>>(dir: P, manifest_number: u64) -> Result<Self> {
        let path = dir.as_ref().join(format!("MANIFEST-{:06}", manifest_number));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .context("Failed to open MANIFEST file")?;

        Ok(Self {
            file: Mutex::new(file),
            manifest_number,
        })
    }

    pub fn log_edit(&self, edit: &VersionEdit) -> Result<()> {
        let record = edit.encode();
        let mut hasher = Hasher::new();
        hasher.update(&record);
        let checksum = hasher.finalize();

        let mut file = self.file.lock();
        file.write_all(&checksum.to_be_bytes())?;
        file.write_all(&(record.len() as u32).to_be_bytes())?;
        file.write_all(&record)?;
        file.sync_data()?;
        Ok(())
    }
}
