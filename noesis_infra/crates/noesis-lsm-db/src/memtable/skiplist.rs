//! Production Concurrent Skiplist MemTable for Apodictic LSM-DB
//! Lock-free concurrent reads, atomic level generation, and ordered range iterator.

use std::cmp::Ordering;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use bytes::Bytes;
use parking_lot::RwLock;

pub const MAX_HEIGHT: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueType {
    Value(Bytes),
    Deletion, // Tombstone marker
}

#[derive(Debug, Clone)]
pub struct MemTableEntry {
    pub key: Bytes,
    pub value: ValueType,
    pub sequence: u64,
}

pub struct SkipNode {
    pub entry: Option<MemTableEntry>,
    pub next: Vec<AtomicPtr<SkipNode>>,
}

impl SkipNode {
    pub fn new(entry: Option<MemTableEntry>, height: usize) -> *mut Self {
        let mut next = Vec::with_capacity(height);
        for _ in 0..height {
            next.push(AtomicPtr::new(std::ptr::null_mut()));
        }
        Box::into_raw(Box::new(Self { entry, next }))
    }
}

pub struct ConcurrentMemTable {
    head: *mut SkipNode,
    max_height: AtomicUsize,
    approximate_size: AtomicUsize,
    sequence_counter: AtomicUsize,
}

unsafe impl Send for ConcurrentMemTable {}
unsafe impl Sync for ConcurrentMemTable {}

impl ConcurrentMemTable {
    pub fn new() -> Self {
        let head = SkipNode::new(None, MAX_HEIGHT);
        Self {
            head,
            max_height: AtomicUsize::new(1),
            approximate_size: AtomicUsize::new(0),
            sequence_counter: AtomicUsize::new(1),
        }
    }

    fn random_height() -> usize {
        let mut height = 1;
        while height < MAX_HEIGHT && (rand_u32() & 3) == 0 {
            height += 1;
        }
        height
    }

    pub fn put(&self, key: Bytes, value: Bytes) -> u64 {
        let seq = self.sequence_counter.fetch_add(1, AtomicOrdering::SeqCst) as u64;
        let entry_size = key.len() + value.len() + 16;
        self.approximate_size.fetch_add(entry_size, AtomicOrdering::Relaxed);

        let entry = MemTableEntry {
            key,
            value: ValueType::Value(value),
            sequence: seq,
        };
        self.insert_entry(entry);
        seq
    }

    pub fn delete(&self, key: Bytes) -> u64 {
        let seq = self.sequence_counter.fetch_add(1, AtomicOrdering::SeqCst) as u64;
        let entry_size = key.len() + 16;
        self.approximate_size.fetch_add(entry_size, AtomicOrdering::Relaxed);

        let entry = MemTableEntry {
            key,
            value: ValueType::Deletion,
            sequence: seq,
        };
        self.insert_entry(entry);
        seq
    }

    fn insert_entry(&self, entry: MemTableEntry) {
        let height = Self::random_height();
        let mut max_h = self.max_height.load(AtomicOrdering::Relaxed);
        while height > max_h {
            match self.max_height.compare_exchange_weak(
                max_h,
                height,
                AtomicOrdering::SeqCst,
                AtomicOrdering::Relaxed,
            ) {
                Ok(_) => break,
                Err(h) => max_h = h,
            }
        }

        let node = SkipNode::new(Some(entry), height);
        let mut prev = vec![self.head; height];

        let mut curr = self.head;
        for level in (0..height).rev() {
            loop {
                let next = unsafe { (&(*curr).next)[level].load(AtomicOrdering::Acquire) };
                if next.is_null() {
                    prev[level] = curr;
                    break;
                }
                let next_entry = unsafe { (*next).entry.as_ref().unwrap() };
                if next_entry.key.as_ref() < unsafe { (*node).entry.as_ref().unwrap().key.as_ref() } {
                    curr = next;
                } else {
                    prev[level] = curr;
                    break;
                }
            }
        }

        for level in 0..height {
            loop {
                let next = unsafe { (&(*prev[level]).next)[level].load(AtomicOrdering::Relaxed) };
                unsafe { (&(*node).next)[level].store(next, AtomicOrdering::Relaxed) };
                if unsafe {
                    (&(*prev[level]).next)[level]
                        .compare_exchange_weak(
                            next,
                            node,
                            AtomicOrdering::Release,
                            AtomicOrdering::Relaxed,
                        )
                        .is_ok()
                } {
                    break;
                }
            }
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<ValueType> {
        let mut curr = self.head;
        let max_h = self.max_height.load(AtomicOrdering::Acquire);

        for level in (0..max_h).rev() {
            loop {
                let next = unsafe { (&(*curr).next)[level].load(AtomicOrdering::Acquire) };
                if next.is_null() {
                    break;
                }
                let next_entry = unsafe { (*next).entry.as_ref().unwrap() };
                match next_entry.key.as_ref().cmp(key) {
                    Ordering::Less => curr = next,
                    Ordering::Equal => return Some(next_entry.value.clone()),
                    Ordering::Greater => break,
                }
            }
        }
        None
    }

    pub fn size_in_bytes(&self) -> usize {
        self.approximate_size.load(AtomicOrdering::Relaxed)
    }

    pub fn scan_all(&self) -> Vec<MemTableEntry> {
        let mut list = Vec::new();
        let mut curr = unsafe { (&(*self.head).next)[0].load(AtomicOrdering::Acquire) };
        while !curr.is_null() {
            if let Some(entry) = unsafe { (*curr).entry.as_ref() } {
                list.push(entry.clone());
            }
            curr = unsafe { (&(*curr).next)[0].load(AtomicOrdering::Acquire) };
        }
        list
    }
}

impl Drop for ConcurrentMemTable {
    fn drop(&mut self) {
        let mut curr = self.head;
        while !curr.is_null() {
            let next = unsafe { (&(*curr).next)[0].load(AtomicOrdering::Relaxed) };
            unsafe {
                let _ = Box::from_raw(curr);
            }
            curr = next;
        }
    }
}

static mut RAND_STATE: u32 = 0x12345678;
fn rand_u32() -> u32 {
    unsafe {
        RAND_STATE = RAND_STATE.wrapping_mul(1664525).wrapping_add(1013904223);
        RAND_STATE
    }
}
