use crate::aead::{CryptoError, SoftwareAead};
use crate::hsm::HsmClient;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub master_key_id: String,
    pub encrypted_data_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct EnvelopeEncryptionEngine {
    hsm: Arc<HsmClient>,
    master_key_id: String,
}

impl EnvelopeEncryptionEngine {
    pub fn new(hsm: Arc<HsmClient>, master_key_id: &str) -> Self {
        Self {
            hsm,
            master_key_id: master_key_id.to_string(),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedEnvelope, CryptoError> {
        // 1. Generate unique 256-bit ephemeral data key
        let mut data_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data_key);

        // 2. Wrap data key using Master Key in HSM
        let encrypted_data_key = self.hsm.wrap_key(&self.master_key_id, &data_key)?;

        // 3. Encrypt payload using ephemeral data key
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = SoftwareAead::encrypt(&data_key, &nonce, plaintext, aad)?;

        Ok(EncryptedEnvelope {
            master_key_id: self.master_key_id.clone(),
            encrypted_data_key,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    pub fn decrypt(&self, envelope: &EncryptedEnvelope, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // 1. Unwrap ephemeral data key from HSM
        let data_key = self.hsm.unwrap_key(&envelope.master_key_id, &envelope.encrypted_data_key)?;

        // 2. Decrypt ciphertext using unwrapped data key
        SoftwareAead::decrypt(&data_key, &envelope.nonce, &envelope.ciphertext, aad)
    }
}
