use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::HashMap;
use tokio::sync::broadcast;

pub struct PubSubManager {
    channels: RwLock<HashMap<String, broadcast::Sender<Bytes>>>,
}

impl PubSubManager {
    pub fn new() -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
        }
    }

    pub fn subscribe(&self, channel: &str) -> broadcast::Receiver<Bytes> {
        let mut guard = self.channels.write();
        let sender = guard.entry(channel.to_string()).or_insert_with(|| {
            let (tx, _) = broadcast::channel(1024);
            tx
        });
        sender.subscribe()
    }

    pub fn publish(&self, channel: &str, message: Bytes) -> usize {
        let guard = self.channels.read();
        if let Some(sender) = guard.get(channel) {
            sender.send(message).unwrap_or(0)
        } else {
            0
        }
    }
}
