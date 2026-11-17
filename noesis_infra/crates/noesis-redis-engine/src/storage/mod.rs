use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct StoredItem {
    value: Bytes,
    expires_at: Option<Instant>,
}

pub struct RedisStore {
    data: RwLock<HashMap<String, StoredItem>>,
}

impl RedisStore {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }

    pub fn set(&self, key: String, value: Bytes, ttl: Option<Duration>) {
        let expires_at = ttl.map(|d| Instant::now() + d);
        let mut guard = self.data.write();
        guard.insert(key, StoredItem { value, expires_at });
    }

    pub fn get(&self, key: &str) -> Option<Bytes> {
        let mut guard = self.data.write();
        if let Some(item) = guard.get(key) {
            if let Some(exp) = item.expires_at {
                if Instant::now() >= exp {
                    guard.remove(key);
                    return None;
                }
            }
            return Some(item.value.clone());
        }
        None
    }

    pub fn del(&self, key: &str) -> bool {
        let mut guard = self.data.write();
        guard.remove(key).is_some()
    }

    pub fn set_nx_px(&self, key: String, value: Bytes, ttl: Duration) -> bool {
        let mut guard = self.data.write();
        if let Some(item) = guard.get(&key) {
            if let Some(exp) = item.expires_at {
                if Instant::now() < exp {
                    return false; // Active lock exists
                }
            } else {
                return false;
            }
        }

        let expires_at = Some(Instant::now() + ttl);
        guard.insert(key, StoredItem { value, expires_at });
        true
    }

    pub fn release_lock(&self, key: &str, expected_token: &[u8]) -> bool {
        let mut guard = self.data.write();
        if let Some(item) = guard.get(key) {
            if item.value.as_ref() == expected_token {
                guard.remove(key);
                return true;
            }
        }
        false
    }
}
