//! Production Block-Based SSTable (Sorted String Table) Format
//! Layout:
//! - Data Blocks (Key-Value pairs with 4KB prefix compression)
//! - Filter Block (Dynamic Bloom Filter with 1% false positive rate)
//! - Index Block (Sparse primary index of first keys per block)
//! - Meta Index Block
//! - Footer (Magic number 0xdb4775248b80fb57, Index handle, Meta handle)

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc32fast::Hasher;
use memmap2::Mmap;

pub const SSTABLE_MAGIC: u64 = 0xdb4775248b80fb57;
pub const BLOCK_SIZE_TARGET: usize = 4096;

#[derive(Debug, Clone)]
pub struct BlockHandle {
    pub offset: u64,
    pub size: u64,
}

pub struct BlockBuilder {
    buffer: BytesMut,
    restarts: Vec<u32>,
    counter: usize,
    last_key: Bytes,
}

impl BlockBuilder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(BLOCK_SIZE_TARGET),
            restarts: vec![0],
            counter: 0,
            last_key: Bytes::new(),
        }
    }

    pub fn add(&mut self, key: &[u8], value: &[u8]) {
        // Calculate shared prefix with last key
        let mut shared = 0;
        if self.counter < 16 {
            while shared < self.last_key.len() && shared < key.len() && self.last_key[shared] == key[shared] {
                shared += 1;
            }
        } else {
            self.restarts.push(self.buffer.len() as u32);
            self.counter = 0;
        }

        let non_shared = key.len() - shared;
        self.buffer.put_u32(shared as u32);
        self.buffer.put_u32(non_shared as u32);
        self.buffer.put_u32(value.len() as u32);
        self.buffer.put_slice(&key[shared..]);
        self.buffer.put_slice(value);

        self.last_key = Bytes::copy_from_slice(key);
        self.counter += 1;
    }

    pub fn finish(mut self) -> Bytes {
        for restart in &self.restarts {
            self.buffer.put_u32(*restart);
        }
        self.buffer.put_u32(self.restarts.len() as u32);
        self.buffer.freeze()
    }

    pub fn estimated_size(&self) -> usize {
        self.buffer.len() + self.restarts.len() * 4 + 4
    }
}

pub struct SsTableWriter {
    file: File,
    offset: u64,
    data_block: BlockBuilder,
    index_block: BlockBuilder,
    first_key_in_block: Option<Bytes>,
    bloom_keys: Vec<Vec<u8>>,
}

impl SsTableWriter {
    pub fn create<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::create(path)?;
        Ok(Self {
            file,
            offset: 0,
            data_block: BlockBuilder::new(),
            index_block: BlockBuilder::new(),
            first_key_in_block: None,
            bloom_keys: Vec::new(),
        })
    }

    pub fn append(&mut self, key: &[u8], value: &[u8]) -> std::io::Result<()> {
        if self.first_key_in_block.is_none() {
            self.first_key_in_block = Some(Bytes::copy_from_slice(key));
        }

        self.data_block.add(key, value);
        self.bloom_keys.push(key.to_vec());

        if self.data_block.estimated_size() >= BLOCK_SIZE_TARGET {
            self.flush_data_block()?;
        }
        Ok(())
    }

    fn flush_data_block(&mut self) -> std::io::Result<()> {
        let block_bytes = std::mem::replace(&mut self.data_block, BlockBuilder::new()).finish();
        let handle = self.write_raw_block(&block_bytes)?;

        if let Some(first_key) = self.first_key_in_block.take() {
            let mut handle_bytes = BytesMut::new();
            handle_bytes.put_u64(handle.offset);
            handle_bytes.put_u64(handle.size);
            self.index_block.add(&first_key, &handle_bytes);
        }
        Ok(())
    }

    fn write_raw_block(&mut self, data: &[u8]) -> std::io::Result<BlockHandle> {
        let offset = self.offset;
        self.file.write_all(data)?;

        // Write CRC32 checksum
        let mut hasher = Hasher::new();
        hasher.update(data);
        let checksum = hasher.finalize();
        self.file.write_all(&checksum.to_be_bytes())?;

        let size = (data.len() + 4) as u64;
        self.offset += size;

        Ok(BlockHandle { offset, size })
    }

    pub fn finalize(mut self) -> std::io::Result<()> {
        if self.first_key_in_block.is_some() {
            self.flush_data_block()?;
        }

        // 1. Write Filter Block (Bloom filter)
        let filter_bytes = crate::bloom::BloomFilter::build_filter(&self.bloom_keys, 10);
        let filter_handle = self.write_raw_block(&filter_bytes)?;

        // 2. Write Index Block
        let index_bytes = std::mem::replace(&mut self.index_block, BlockBuilder::new()).finish();
        let index_handle = self.write_raw_block(&index_bytes)?;

        // 3. Write Footer
        let mut footer = BytesMut::with_capacity(48);
        footer.put_u64(filter_handle.offset);
        footer.put_u64(filter_handle.size);
        footer.put_u64(index_handle.offset);
        footer.put_u64(index_handle.size);
        footer.put_u64(SSTABLE_MAGIC);
        self.file.write_all(&footer)?;
        self.file.sync_data()?;

        Ok(())
    }
}
