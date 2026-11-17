use crate::aead::{CryptoError, SoftwareAead};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use parking_lot::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterKeyMetadata {
    pub key_id: String,
    pub version: u32,
    pub is_enabled: bool,
    pub created_at_unix: u64,
}

pub struct HsmClient {
    keys: RwLock<HashMap<String, (MasterKeyMetadata, Vec<u8>)>>,
}

impl HsmClient {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn generate_master_key(&self, key_id: &str) -> MasterKeyMetadata {
        let mut raw_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw_key);

        let meta = MasterKeyMetadata {
            key_id: key_id.to_string(),
            version: 1,
            is_enabled: true,
            created_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let mut guard = self.keys.write();
        guard.insert(key_id.to_string(), (meta.clone(), raw_key));
        meta
    }

    pub fn wrap_key(&self, master_key_id: &str, plaintext_data_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let guard = self.keys.read();
        let (_meta, master_raw) = guard.get(master_key_id)
            .ok_or_else(|| CryptoError::InvalidKeySize { expected: 32, got: 0 })?;

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let mut ciphertext = SoftwareAead::encrypt(master_raw, &nonce, plaintext_data_key, master_key_id.as_bytes())?;
        let mut wrapped = Vec::with_capacity(12 + ciphertext.len());
        wrapped.extend_from_slice(&nonce);
        wrapped.append(&mut ciphertext);
        Ok(wrapped)
    }

    pub fn unwrap_key(&self, master_key_id: &str, wrapped_data_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if wrapped_data_key.len() < 12 + 16 {
            return Err(CryptoError::CiphertextTruncated);
        }
        let guard = self.keys.read();
        let (_meta, master_raw) = guard.get(master_key_id)
            .ok_or_else(|| CryptoError::InvalidKeySize { expected: 32, got: 0 })?;

        let nonce = &wrapped_data_key[0..12];
        let ciphertext = &wrapped_data_key[12..];

        SoftwareAead::decrypt(master_raw, nonce, ciphertext, master_key_id.as_bytes())
    }
}
