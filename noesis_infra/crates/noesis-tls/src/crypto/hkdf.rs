//! HKDF (HMAC-based Extract-and-Expand Key Derivation Function) & Key Schedule for TLS 1.3
//! Implements RFC 5869 & RFC 8446 Section 7:
//! - Early Secret, Handshake Secret, Master Secret
//! - HKDF-Extract(salt, IKM)
//! - HKDF-Expand-Label(Secret, Label, Context, Length)

use sha2::{Digest, Sha256};
use bytes::{BufMut, Bytes, BytesMut};

pub struct HkdfSha256;

impl HkdfSha256 {
    pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let block_size = 64;
        let mut k_pad = [0u8; 64];

        if key.len() > block_size {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let h = hasher.finalize();
            k_pad[..32].copy_from_slice(&h);
        } else {
            k_pad[..key.len()].copy_from_slice(key);
        }

        let mut i_key_pad = [0u8; 64];
        let mut o_key_pad = [0u8; 64];
        for i in 0..64 {
            i_key_pad[i] = k_pad[i] ^ 0x36;
            o_key_pad[i] = k_pad[i] ^ 0x5c;
        }

        let mut inner = Sha256::new();
        inner.update(&i_key_pad);
        inner.update(data);
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(&o_key_pad);
        outer.update(&inner_hash);
        outer.finalize().into()
    }

    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let default_salt = [0u8; 32];
        let s = if salt.is_empty() { &default_salt } else { salt };
        Self::hmac(s, ikm)
    }

    pub fn expand(prk: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
        let mut okm = Vec::with_capacity(okm_len);
        let mut prev = Vec::new();
        let mut round = 1u8;

        while okm.len() < okm_len {
            let mut msg = Vec::new();
            msg.extend_from_slice(&prev);
            msg.extend_from_slice(info);
            msg.push(round);

            let tag = Self::hmac(prk, &msg);
            let needed = okm_len - okm.len();
            let take = needed.min(32);
            okm.extend_from_slice(&tag[..take]);

            prev = tag.to_vec();
            round += 1;
        }
        okm
    }

    pub fn expand_label(secret: &[u8], label: &str, context: &[u8], length: u16) -> Vec<u8> {
        let mut hkdf_label = BytesMut::new();
        hkdf_label.put_u16(length);

        let full_label = format!("tls13 {label}");
        hkdf_label.put_u8(full_label.len() as u8);
        hkdf_label.put_slice(full_label.as_bytes());

        hkdf_label.put_u8(context.len() as u8);
        hkdf_label.put_slice(context);

        Self::expand(secret, &hkdf_label, length as usize)
    }
}
