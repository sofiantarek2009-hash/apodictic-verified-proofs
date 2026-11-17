use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum CryptoError {
    #[error("Invalid key size: expected {expected}, got {got}")]
    InvalidKeySize { expected: usize, got: usize },
    #[error("Invalid nonce size: expected {expected}, got {got}")]
    InvalidNonceSize { expected: usize, got: usize },
    #[error("Ciphertext truncated")]
    CiphertextTruncated,
    #[error("Authentication tag verification failed")]
    AuthTagMismatch,
}

pub struct SoftwareAead;

impl SoftwareAead {
    pub const KEY_SIZE: usize = 32; // AES-256
    pub const NONCE_SIZE: usize = 12; // Standard GCM nonce
    pub const TAG_SIZE: usize = 16; // 128-bit authentication tag

    pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize { expected: Self::KEY_SIZE, got: key.len() });
        }
        if nonce.len() != Self::NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize { expected: Self::NONCE_SIZE, got: nonce.len() });
        }

        // Deterministic CTR keystream simulation using SHA-256 counter blocks
        let mut ciphertext = Vec::with_capacity(plaintext.len() + Self::TAG_SIZE);
        let mut block_idx: u32 = 0;

        for chunk in plaintext.chunks(32) {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(nonce);
            hasher.update(&block_idx.to_be_bytes());
            let keystream = hasher.finalize();

            for (i, &b) in chunk.iter().enumerate() {
                ciphertext.push(b ^ keystream[i]);
            }
            block_idx += 1;
        }

        // Compute GMAC / Poly1305 simulation tag over AAD and ciphertext
        let mut tag_hasher = Sha256::new();
        tag_hasher.update(key);
        tag_hasher.update(aad);
        tag_hasher.update(&ciphertext);
        tag_hasher.update(&(plaintext.len() as u64).to_be_bytes());
        let tag = tag_hasher.finalize();

        ciphertext.extend_from_slice(&tag[0..Self::TAG_SIZE]);
        Ok(ciphertext)
    }

    pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize { expected: Self::KEY_SIZE, got: key.len() });
        }
        if nonce.len() != Self::NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize { expected: Self::NONCE_SIZE, got: nonce.len() });
        }
        if ciphertext.len() < Self::TAG_SIZE {
            return Err(CryptoError::CiphertextTruncated);
        }

        let payload_len = ciphertext.len() - Self::TAG_SIZE;
        let payload = &ciphertext[0..payload_len];
        let provided_tag = &ciphertext[payload_len..];

        let mut tag_hasher = Sha256::new();
        tag_hasher.update(key);
        tag_hasher.update(aad);
        tag_hasher.update(payload);
        tag_hasher.update(&(payload_len as u64).to_be_bytes());
        let expected_tag = tag_hasher.finalize();

        // Constant-time tag comparison
        let mut mismatch = 0u8;
        for i in 0..Self::TAG_SIZE {
            mismatch |= provided_tag[i] ^ expected_tag[i];
        }

        if mismatch != 0 {
            return Err(CryptoError::AuthTagMismatch);
        }

        // Decrypt payload
        let mut plaintext = Vec::with_capacity(payload_len);
        let mut block_idx: u32 = 0;

        for chunk in payload.chunks(32) {
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(nonce);
            hasher.update(&block_idx.to_be_bytes());
            let keystream = hasher.finalize();

            for (i, &b) in chunk.iter().enumerate() {
                plaintext.push(b ^ keystream[i]);
            }
            block_idx += 1;
        }

        Ok(plaintext)
    }
}
