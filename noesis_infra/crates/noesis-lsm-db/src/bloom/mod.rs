//! Production Space-Optimal Bloom Filter
//! Calculates optimal bit arrays and hash count to achieve <1% false positive rate.

use bytes::{BufMut, Bytes, BytesMut};

pub struct BloomFilter;

impl BloomFilter {
    pub fn build_filter(keys: &[Vec<u8>], bits_per_key: usize) -> Bytes {
        let mut bits = keys.len() * bits_per_key;
        if bits < 64 {
            bits = 64;
        }

        let bytes = (bits + 7) / 8;
        let bits = bytes * 8;

        let mut filter = vec![0u8; bytes];
        let k = ((bits_per_key as f64) * 0.69).round() as u8;
        let k = k.clamp(1, 30);

        for key in keys {
            let mut h = Self::bloom_hash(key);
            let delta = (h >> 17) | (h << 15);
            for _ in 0..k {
                let bit_pos = (h % (bits as u32)) as usize;
                filter[bit_pos / 8] |= 1 << (bit_pos % 8);
                h = h.wrapping_add(delta);
            }
        }

        // Append K as footer byte
        let mut res = BytesMut::from(&filter[..]);
        res.put_u8(k);
        res.freeze()
    }

    pub fn key_may_match(key: &[u8], filter: &[u8]) -> bool {
        if filter.len() < 2 {
            return false;
        }

        let k = filter[filter.len() - 1];
        if k > 30 {
            return true;
        }

        let bits = (filter.len() - 1) * 8;
        let mut h = Self::bloom_hash(key);
        let delta = (h >> 17) | (h << 15);

        for _ in 0..k {
            let bit_pos = (h % (bits as u32)) as usize;
            if (filter[bit_pos / 8] & (1 << (bit_pos % 8))) == 0 {
                return false;
            }
            h = h.wrapping_add(delta);
        }
        true
    }

    fn bloom_hash(data: &[u8]) -> u32 {
        let seed = 0xbc9f1d34u32;
        let m = 0xc6a4a793u32;
        let mut h = seed ^ ((data.len() as u32).wrapping_mul(m));

        let mut chunks = data.chunks_exact(4);
        while let Some(chunk) = chunks.next() {
            let mut w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            h = h.wrapping_add(w);
            h = h.wrapping_mul(m);
            h ^= h >> 16;
        }

        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut w = 0u32;
            for (i, &b) in rem.iter().enumerate() {
                w |= (b as u32) << (i * 8);
            }
            h = h.wrapping_add(w);
            h = h.wrapping_mul(m);
            h ^= h >> 16;
        }
        h
    }
}
