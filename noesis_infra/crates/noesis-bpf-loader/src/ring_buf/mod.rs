use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
pub const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
pub const BPF_RINGBUF_HDR_SZ: usize = 8;

#[repr(C)]
pub struct BpfRingBufHdr {
    pub len: u32,
    pub pg_off: u32,
}

pub struct RingBufferConsumer {
    buffer: Vec<u8>,
    capacity: usize,
    mask: usize,
    consumer_pos: AtomicU64,
    producer_pos: Arc<AtomicU64>,
}

impl RingBufferConsumer {
    pub fn new(capacity_power_of_two: usize) -> (Self, Arc<AtomicU64>) {
        assert!(capacity_power_of_two.is_power_of_two(), "Capacity must be power of two");
        let producer = Arc::new(AtomicU64::new(0));
        let consumer = Self {
            buffer: vec![0u8; capacity_power_of_two * 2],
            capacity: capacity_power_of_two,
            mask: capacity_power_of_two - 1,
            consumer_pos: AtomicU64::new(0),
            producer_pos: Arc::clone(&producer),
        };
        (consumer, producer)
    }

    pub fn poll<F>(&mut self, mut callback: F) -> usize
    where
        F: FnMut(&[u8]),
    {
        let mut count = 0;
        let mut cons = self.consumer_pos.load(Ordering::Acquire);
        let prod = self.producer_pos.load(Ordering::Acquire);

        while cons < prod {
            let offset = (cons as usize) & self.mask;
            let hdr_bytes = &self.buffer[offset..offset + BPF_RINGBUF_HDR_SZ];
            let raw_len = u32::from_ne_bytes(hdr_bytes[0..4].try_into().unwrap());

            if raw_len & BPF_RINGBUF_BUSY_BIT != 0 {
                // Event still being written by eBPF program
                break;
            }

            let len = (raw_len & !BPF_RINGBUF_DISCARD_BIT) as usize;
            let total_record_len = (BPF_RINGBUF_HDR_SZ + len + 7) & !7;

            if raw_len & BPF_RINGBUF_DISCARD_BIT == 0 {
                let data_offset = offset + BPF_RINGBUF_HDR_SZ;
                let payload = &self.buffer[data_offset..data_offset + len];
                callback(payload);
                count += 1;
            }

            cons += total_record_len as u64;
            self.consumer_pos.store(cons, Ordering::Release);
        }

        count
    }

    pub fn write_sample(&mut self, payload: &[u8]) -> Result<(), &'static str> {
        let len = payload.len();
        let total_record_len = (BPF_RINGBUF_HDR_SZ + len + 7) & !7;
        let prod = self.producer_pos.load(Ordering::Acquire);
        let cons = self.consumer_pos.load(Ordering::Acquire);

        if (prod - cons) as usize + total_record_len > self.capacity {
            return Err("Ring buffer overflow / backpressure");
        }

        let offset = (prod as usize) & self.mask;
        let len_u32 = len as u32;
        self.buffer[offset..offset + 4].copy_from_slice(&len_u32.to_ne_bytes());
        self.buffer[offset + 4..offset + 8].copy_from_slice(&0u32.to_ne_bytes());
        self.buffer[offset + BPF_RINGBUF_HDR_SZ..offset + BPF_RINGBUF_HDR_SZ + len].copy_from_slice(payload);

        self.producer_pos.store(prod + total_record_len as u64, Ordering::Release);
        Ok(())
    }
}
