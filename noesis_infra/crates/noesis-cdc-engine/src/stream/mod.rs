use crate::logical_decoding::{LogicalReplicationMessage, PgOutputParser};
use crate::lsn::Lsn;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct CdcConsumerSession {
    slot_name: String,
    confirmed_flush_lsn: AtomicU64,
    restart_lsn: AtomicU64,
    handlers: Arc<RwLock<Vec<Box<dyn Fn(&LogicalReplicationMessage) + Send + Sync>>>>,
}

impl CdcConsumerSession {
    pub fn new(slot_name: &str, initial_lsn: Lsn) -> Self {
        Self {
            slot_name: slot_name.to_string(),
            confirmed_flush_lsn: AtomicU64::new(initial_lsn.0),
            restart_lsn: AtomicU64::new(initial_lsn.0),
            handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn register_handler<F>(&self, handler: F)
    where
        F: Fn(&LogicalReplicationMessage) + Send + Sync + 'static,
    {
        let mut guard = self.handlers.write();
        guard.push(Box::new(handler));
    }

    pub fn process_wal_chunk(&self, chunk: &[u8], next_lsn: Lsn) -> Result<(), &'static str> {
        let msg = PgOutputParser::parse_message(chunk).map_err(|_| "Failed to decode WAL chunk")?;

        let handlers = self.handlers.read();
        for h in handlers.iter() {
            h(&msg);
        }

        self.confirmed_flush_lsn.store(next_lsn.0, Ordering::Release);
        Ok(())
    }

    pub fn current_flush_lsn(&self) -> Lsn {
        Lsn(self.confirmed_flush_lsn.load(Ordering::Acquire))
    }
}
