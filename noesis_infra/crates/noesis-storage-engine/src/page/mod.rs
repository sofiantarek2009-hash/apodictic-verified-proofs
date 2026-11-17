//! Page format and disk layout for Apodictic Enterprise Storage Engine
//! Page size: 4096 bytes (4KB aligned)
//! Header layout:
//! - PageLSN: 8 bytes (Log Sequence Number for ARIES recovery)
//! - PageType: 2 bytes (0=Empty, 1=BTreeInternal, 2=BTreeLeaf, 3=SlottedData, 4=Overflow)
//! - FreeSpaceOffset: 2 bytes (Offset to free space boundary)
//! - SlotCount: 2 bytes (Number of slotted records on this page)
//! - Checksum: 4 bytes (CRC32C hardware checksum)
//! - Reserved: 14 bytes (Zeroed alignment pad)
//! Total header: 32 bytes

use std::fmt;
use std::io::{self, Cursor};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_HEADER_SIZE: usize = 32;
pub const MAX_SLOTS_PER_PAGE: usize = (PAGE_SIZE - PAGE_HEADER_SIZE) / 4; // Slot pointer is 4 bytes (offset: u16, length: u16)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PageType {
    Empty = 0,
    BTreeInternal = 1,
    BTreeLeaf = 2,
    SlottedData = 3,
    Overflow = 4,
    FreeList = 5,
}

impl From<u16> for PageType {
    fn from(val: u16) -> Self {
        match val {
            1 => PageType::BTreeInternal,
            2 => PageType::BTreeLeaf,
            3 => PageType::SlottedData,
            4 => PageType::Overflow,
            5 => PageType::FreeList,
            _ => PageType::Empty,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PageId(pub u64);

impl fmt::Display for PageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PageId({})", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotPointer {
    pub offset: u16,
    pub length: u16,
}

pub struct Page {
    pub data: [u8; PAGE_SIZE],
}

impl Page {
    pub fn new() -> Self {
        Self {
            data: [0u8; PAGE_SIZE],
        }
    }

    pub fn init(&mut self, page_type: PageType) {
        self.data = [0u8; PAGE_SIZE];
        self.set_page_lsn(0);
        self.set_page_type(page_type);
        self.set_free_space_offset(PAGE_SIZE as u16);
        self.set_slot_count(0);
        self.set_checksum(0);
    }

    pub fn page_lsn(&self) -> u64 {
        BigEndian::read_u64(&self.data[0..8])
    }

    pub fn set_page_lsn(&mut self, lsn: u64) {
        BigEndian::write_u64(&mut self.data[0..8], lsn);
    }

    pub fn page_type(&self) -> PageType {
        PageType::from(BigEndian::read_u16(&self.data[8..10]))
    }

    pub fn set_page_type(&mut self, pt: PageType) {
        BigEndian::write_u16(&mut self.data[8..10], pt as u16);
    }

    pub fn free_space_offset(&self) -> u16 {
        BigEndian::read_u16(&self.data[10..12])
    }

    pub fn set_free_space_offset(&mut self, offset: u16) {
        BigEndian::write_u16(&mut self.data[10..12], offset);
    }

    pub fn slot_count(&self) -> u16 {
        BigEndian::read_u16(&self.data[12..14])
    }

    pub fn set_slot_count(&mut self, count: u16) {
        BigEndian::write_u16(&mut self.data[12..14], count);
    }

    pub fn checksum(&self) -> u32 {
        BigEndian::read_u32(&self.data[14..18])
    }

    pub fn set_checksum(&mut self, crc: u32) {
        BigEndian::write_u32(&mut self.data[14..18], crc);
    }

    pub fn compute_crc32(&self) -> u32 {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&self.data[0..14]); // LSN, PageType, FreeOffset, SlotCount
        hasher.update(&self.data[18..PAGE_SIZE]); // Body without checksum field
        hasher.finalize()
    }

    pub fn verify_checksum(&self) -> bool {
        self.checksum() == self.compute_crc32()
    }

    pub fn update_checksum(&mut self) {
        let crc = self.compute_crc32();
        self.set_checksum(crc);
    }

    pub fn get_slot(&self, slot_idx: u16) -> Option<SlotPointer> {
        if slot_idx >= self.slot_count() {
            return None;
        }
        let pos = PAGE_HEADER_SIZE + (slot_idx as usize * 4);
        let offset = BigEndian::read_u16(&self.data[pos..pos + 2]);
        let length = BigEndian::read_u16(&self.data[pos + 2..pos + 4]);
        Some(SlotPointer { offset, length })
    }

    pub fn insert_record(&mut self, record_data: &[u8]) -> Option<u16> {
        let rec_len = record_data.len();
        if rec_len > PAGE_SIZE - PAGE_HEADER_SIZE - 4 {
            return None; // Exceeds single page capacity
        }

        let slot_cnt = self.slot_count() as usize;
        let slot_end = PAGE_HEADER_SIZE + ((slot_cnt + 1) * 4);
        let current_free = self.free_space_offset() as usize;

        if current_free < slot_end || current_free - slot_end < rec_len {
            return None; // Page full, requires split
        }

        let new_offset = (current_free - rec_len) as u16;
        self.data[new_offset as usize..current_free].copy_from_slice(record_data);
        self.set_free_space_offset(new_offset);

        let slot_pos = PAGE_HEADER_SIZE + (slot_cnt * 4);
        BigEndian::write_u16(&mut self.data[slot_pos..slot_pos + 2], new_offset);
        BigEndian::write_u16(&mut self.data[slot_pos + 2..slot_pos + 4], rec_len as u16);
        self.set_slot_count((slot_cnt + 1) as u16);

        Some(slot_cnt as u16)
    }

    pub fn get_record(&self, slot_idx: u16) -> Option<&[u8]> {
        let slot = self.get_slot(slot_idx)?;
        if slot.length == 0 {
            return None; // Tombstone or empty slot
        }
        let start = slot.offset as usize;
        let end = start + slot.length as usize;
        if end > PAGE_SIZE {
            return None;
        }
        Some(&self.data[start..end])
    }
}
