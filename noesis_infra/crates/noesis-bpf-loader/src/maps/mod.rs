use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BpfMapType {
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PerCpuHash = 5,
    PerCpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHashMap = 9,
    LruPerCpuHashMap = 10,
    LpmTrie = 11,
    ArrayOfMaps = 12,
    HashOfMaps = 13,
    DevMap = 14,
    SockMap = 15,
    CpuMap = 16,
    XskMap = 17,
    SockHash = 18,
    CgroupStorage = 19,
    ReusePortSockArray = 20,
    RingBuf = 27,
}

#[derive(Debug, Clone)]
pub struct BpfMapDef {
    pub name: String,
    pub map_type: BpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

pub struct UserspaceBpfMap {
    pub def: BpfMapDef,
    storage: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    lookup_count: AtomicU64,
    update_count: AtomicU64,
    delete_count: AtomicU64,
}

impl UserspaceBpfMap {
    pub fn new(def: BpfMapDef) -> Self {
        Self {
            def,
            storage: RwLock::new(HashMap::new()),
            lookup_count: AtomicU64::new(0),
            update_count: AtomicU64::new(0),
            delete_count: AtomicU64::new(0),
        }
    }

    pub fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.lookup_count.fetch_add(1, Ordering::Relaxed);
        let guard = self.storage.read();
        guard.get(key).cloned()
    }

    pub fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), &'static str> {
        if key.len() != self.def.key_size as usize {
            return Err("Invalid key size");
        }
        if value.len() != self.def.value_size as usize {
            return Err("Invalid value size");
        }

        let mut guard = self.storage.write();
        let exists = guard.contains_key(key);

        // BPF_NOEXIST = 1, BPF_EXIST = 2
        if flags == 1 && exists {
            return Err("Element already exists (BPF_NOEXIST)");
        }
        if flags == 2 && !exists {
            return Err("Element does not exist (BPF_EXIST)");
        }
        if guard.len() >= self.def.max_entries as usize && !exists {
            return Err("BPF map capacity exceeded");
        }

        guard.insert(key.to_vec(), value.to_vec());
        self.update_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), &'static str> {
        let mut guard = self.storage.write();
        if guard.remove(key).is_some() {
            self.delete_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err("Key not found")
        }
    }

    pub fn entries(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let guard = self.storage.read();
        guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}
