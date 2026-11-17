//! Enterprise SCRAM-SHA-256 Authentication Protocol for PostgreSQL
//! Implements RFC 5802 & RFC 7677 for SASL Authentication:
//! - ClientFirstMessage: n,,n=username,r=nonce
//! - ServerFirstMessage: r=combined_nonce,s=salt,i=iterations
//! - ClientFinalMessage: c=channel_binding,r=combined_nonce,p=client_proof
//! - Hi(password, salt, iterations) PBKDF2 calculation
//! - ClientKey, StoredKey, ServerKey, ClientSignature verification

use sha2::{Digest, Sha256};
use bytes::{Bytes, BytesMut};

pub struct ScramSha256;

impl ScramSha256 {
    pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut u = crate::crypto::hkdf::HkdfSha256::hmac(password, &[salt, &[0, 0, 0, 1]].concat());
        let mut result = u;

        for _ in 1..iterations {
            u = crate::crypto::hkdf::HkdfSha256::hmac(password, &u);
            for j in 0..32 {
                result[j] ^= u[j];
            }
        }
        result
    }

    pub fn compute_client_proof(salted_password: &[u8; 32], auth_message: &str) -> [u8; 32] {
        // ClientKey = HMAC(SaltedPassword, "Client Key")
        let client_key = crate::crypto::hkdf::HkdfSha256::hmac(salted_password, b"Client Key");
        
        // StoredKey = SHA256(ClientKey)
        let mut hasher = Sha256::new();
        hasher.update(&client_key);
        let stored_key: [u8; 32] = hasher.finalize().into();

        // ClientSignature = HMAC(StoredKey, AuthMessage)
        let client_signature = crate::crypto::hkdf::HkdfSha256::hmac(&stored_key, auth_message.as_bytes());

        // ClientProof = ClientKey XOR ClientSignature
        let mut client_proof = [0u8; 32];
        for i in 0..32 {
            client_proof[i] = client_key[i] ^ client_signature[i];
        }
        client_proof
    }
}
