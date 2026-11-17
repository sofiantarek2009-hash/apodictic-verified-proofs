use parking_lot::Mutex;
use std::collections::HashSet;
use std::time::{Duration, Instant};

pub struct AdvisoryMigrationLock {
    held_locks: Mutex<HashSet<u64>>,
}

impl AdvisoryMigrationLock {
    pub fn new() -> Self {
        Self {
            held_locks: Mutex::new(HashSet::new()),
        }
    }

    pub fn acquire_lock(&self, lock_id: u64, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let mut guard = self.held_locks.lock();
            if !guard.contains(&lock_id) {
                guard.insert(lock_id);
                return true;
            }
            drop(guard);
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    pub fn release_lock(&self, lock_id: u64) -> bool {
        let mut guard = self.held_locks.lock();
        guard.remove(&lock_id)
    }

    pub fn is_locked(&self, lock_id: u64) -> bool {
        self.held_locks.lock().contains(&lock_id)
    }
}
