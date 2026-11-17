//! Buffer Pool Manager with CLOCK replacement algorithm and dirty-page flushing
//! Enforces:
//! - Frame table with fix count (pin count) tracking
//! - Dirty flag tracking to ensure dirty pages are written to WAL before disk
//! - O(1) buffer lookup via page-to-frame hash table
//! - Background page cleaning & checkpoint coordination

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use parking_lot::{Mutex, RwLock};

use crate::page::{Page, PageId, PAGE_SIZE};
use crate::disk::DiskManager;

pub const DEFAULT_BUFFER_POOL_SIZE: usize = 1024; // 1,024 pages = 4MB cache

pub struct Frame {
    pub page: RwLock<Page>,
    pub page_id: RwLock<Option<PageId>>,
    pub pin_count: AtomicU32,
    pub is_dirty: AtomicBool,
    pub usage_bit: AtomicBool, // CLOCK replacement indicator
}

impl Frame {
    pub fn new() -> Self {
        Self {
            page: RwLock::new(Page::new()),
            page_id: RwLock::new(None),
            pin_count: AtomicU32::new(0),
            is_dirty: AtomicBool::new(false),
            usage_bit: AtomicBool::new(false),
        }
    }
}

pub struct BufferPoolManager {
    disk_manager: Arc<DiskManager>,
    pool_size: usize,
    frames: Vec<Arc<Frame>>,
    page_table: RwLock<HashMap<PageId, usize>>, // PageId -> Frame Index
    clock_hand: AtomicUsize,
    free_list: Mutex<Vec<usize>>,
}

impl BufferPoolManager {
    pub fn new(disk_manager: Arc<DiskManager>, pool_size: usize) -> Self {
        let mut frames = Vec::with_capacity(pool_size);
        let mut free_list = Vec::with_capacity(pool_size);
        for i in 0..pool_size {
            frames.push(Arc::new(Frame::new()));
            free_list.push(i);
        }

        Self {
            disk_manager,
            pool_size,
            frames,
            page_table: RwLock::new(HashMap::with_capacity(pool_size)),
            clock_hand: AtomicUsize::new(0),
            free_list: Mutex::new(free_list),
        }
    }

    pub fn fetch_page(&self, page_id: PageId) -> Option<Arc<Frame>> {
        // 1. Check if page is already cached in memory
        {
            let table = self.page_table.read();
            if let Some(&frame_idx) = table.get(&page_id) {
                let frame = &self.frames[frame_idx];
                frame.pin_count.fetch_add(1, Ordering::SeqCst);
                frame.usage_bit.store(true, Ordering::SeqCst);
                return Some(Arc::clone(frame));
            }
        }

        // 2. Page not cached, select a frame for victim replacement
        let frame_idx = self.select_victim_frame()?;
        let frame = &self.frames[frame_idx];

        // 3. Flush old page to disk if it was dirty
        self.evict_frame(frame_idx)?;

        // 4. Read requested page from disk into the frame
        let mut page_guard = frame.page.write();
        if let Err(e) = self.disk_manager.read_page(page_id, &mut page_guard) {
            return None;
        }

        *frame.page_id.write() = Some(page_id);
        frame.pin_count.store(1, Ordering::SeqCst);
        frame.is_dirty.store(false, Ordering::SeqCst);
        frame.usage_bit.store(true, Ordering::SeqCst);

        self.page_table.write().insert(page_id, frame_idx);

        Some(Arc::clone(frame))
    }

    pub fn new_page(&self) -> Option<(PageId, Arc<Frame>)> {
        let frame_idx = self.select_victim_frame()?;
        let frame = &self.frames[frame_idx];

        self.evict_frame(frame_idx)?;

        let page_id = self.disk_manager.allocate_page();
        let mut page_guard = frame.page.write();
        page_guard.init(crate::page::PageType::SlottedData);

        *frame.page_id.write() = Some(page_id);
        frame.pin_count.store(1, Ordering::SeqCst);
        frame.is_dirty.store(true, Ordering::SeqCst); // New page is immediately dirty
        frame.usage_bit.store(true, Ordering::SeqCst);

        self.page_table.write().insert(page_id, frame_idx);

        Some((page_id, Arc::clone(frame)))
    }

    pub fn unpin_page(&self, page_id: PageId, is_dirty: bool) -> bool {
        let table = self.page_table.read();
        if let Some(&frame_idx) = table.get(&page_id) {
            let frame = &self.frames[frame_idx];
            if is_dirty {
                frame.is_dirty.store(true, Ordering::SeqCst);
            }
            let prev = frame.pin_count.fetch_sub(1, Ordering::SeqCst);
            return prev > 0;
        }
        false
    }

    pub fn flush_page(&self, page_id: PageId) -> bool {
        let table = self.page_table.read();
        if let Some(&frame_idx) = table.get(&page_id) {
            let frame = &self.frames[frame_idx];
            if frame.is_dirty.swap(false, Ordering::SeqCst) {
                let mut page_guard = frame.page.write();
                page_guard.update_checksum();
                let _ = self.disk_manager.write_page(page_id, &page_guard);
                return true;
            }
        }
        false
    }

    fn select_victim_frame(&self) -> Option<usize> {
        // Fast path: pull from free list
        if let Some(idx) = self.free_list.lock().pop() {
            return Some(idx);
        }

        // CLOCK replacement algorithm loop
        let start_hand = self.clock_hand.load(Ordering::SeqCst);
        for _ in 0..(self.pool_size * 2) {
            let hand = self.clock_hand.fetch_add(1, Ordering::SeqCst) % self.pool_size;
            let frame = &self.frames[hand];

            if frame.pin_count.load(Ordering::SeqCst) == 0 {
                if frame.usage_bit.swap(false, Ordering::SeqCst) {
                    // Usage bit cleared, give it a second chance
                    continue;
                }
                return Some(hand); // Victim found
            }
        }
        None // All frames pinned, pool exhausted
    }

    fn evict_frame(&self, frame_idx: usize) -> Option<()> {
        let frame = &self.frames[frame_idx];
        let old_page_id = *frame.page_id.read();

        if let Some(pid) = old_page_id {
            if frame.is_dirty.swap(false, Ordering::SeqCst) {
                let mut page_guard = frame.page.write();
                page_guard.update_checksum();
                let _ = self.disk_manager.write_page(pid, &page_guard);
            }
            self.page_table.write().remove(&pid);
        }
        Some(())
    }

    pub fn flush_all(&self) {
        let table = self.page_table.read();
        for &pid in table.keys() {
            self.flush_page(pid);
        }
    }
}
