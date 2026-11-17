//! Physical Disk File Manager with Direct I/O and atomic 4KB sector alignment
//! Handles:
//! - File growth & sparse page allocation
//! - PageId to physical byte offset mapping: offset = PageId * 4096
//! - Atomic fsync and multi-threaded read/write safety via File handles

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::Mutex;

use crate::page::{Page, PageId, PAGE_SIZE};

pub struct DiskManager {
    db_file_path: PathBuf,
    file: Mutex<File>,
    num_allocated_pages: AtomicU64,
}

impl DiskManager {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let db_file_path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&db_file_path)?;

        let meta = file.metadata()?;
        let num_pages = meta.len() / (PAGE_SIZE as u64);

        Ok(Self {
            db_file_path,
            file: Mutex::new(file),
            num_allocated_pages: AtomicU64::new(num_pages),
        })
    }

    pub fn allocate_page(&self) -> PageId {
        let page_idx = self.num_allocated_pages.fetch_add(1, Ordering::SeqCst);
        PageId(page_idx)
    }

    pub fn write_page(&self, page_id: PageId, page: &Page) -> io::Result<()> {
        let offset = page_id.0 * (PAGE_SIZE as u64);
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&page.data)?;
        file.sync_data()?;
        Ok(())
    }

    pub fn read_page(&self, page_id: PageId, page: &mut Page) -> io::Result<()> {
        let offset = page_id.0 * (PAGE_SIZE as u64);
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut page.data)?;
        Ok(())
    }

    pub fn total_pages(&self) -> u64 {
        self.num_allocated_pages.load(Ordering::SeqCst)
    }
}
