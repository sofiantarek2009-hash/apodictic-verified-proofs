//! # Apodictic TEE Attestation Engine
//!
//! Cryptographic measurement and hardware attestation verification for
//! confidential computing enclaves (AWS Nitro Enclaves, Intel SGX, AMD SEV-SNP).
//! Verifies PCR0/PCR1/PCR2 hashes and cryptographic attestation documents
//! before any decrypted financial transaction or Z3 AST proof is accepted.

use sha2::{Digest, Sha256, Sha384};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum AttestationError {
    #[error("Invalid measurement digest length: expected {expected}, got {actual}")]
    InvalidDigestLength { expected: usize, actual: usize },
    #[error("Platform Configuration Register mismatch: register {pcr_index}")]
    PcrMismatch { pcr_index: u32 },
    #[error("Invalid root certificate authority signature or untrusted signing key")]
    UntrustedSigner,
    #[error("Hardware attestation document expired or timestamp skew exceeded: {delta_seconds}s")]
    TimestampExpired { delta_seconds: i64 },
    #[error("Nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch { expected: String, actual: String },
    #[error("Serialization / Deserialization error: {0}")]
    SerializationError(String),
}

/// Supported Confidential Enclave architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveHardwareType {
    AwsNitroEnclave,
    IntelSgx,
    AmdSevSnp,
}

/// Hardware Platform Configuration Registers (PCRs)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformConfigurationRegisters {
    /// PCR0: SHA-384 hash of the kernel, cmdline, and initrd
    pub pcr0: Vec<u8>,
    /// PCR1: SHA-384 hash of OS image / enclave application image
    pub pcr1: Vec<u8>,
    /// PCR2: SHA-384 hash of application configuration and policies
    pub pcr2: Vec<u8>,
}

impl PlatformConfigurationRegisters {
    pub fn new(pcr0: Vec<u8>, pcr1: Vec<u8>, pcr2: Vec<u8>) -> Result<Self, AttestationError> {
        if pcr0.len() != 48 || pcr1.len() != 48 || pcr2.len() != 48 {
            return Err(AttestationError::InvalidDigestLength {
                expected: 48,
                actual: pcr0.len(),
            });
        }
        Ok(Self { pcr0, pcr1, pcr2 })
    }

    /// Computes the composite hash of the measured enclave state
    pub fn composite_hash(&self) -> Vec<u8> {
        let mut hasher = Sha384::new();
        hasher.update(&self.pcr0);
        hasher.update(&self.pcr1);
        hasher.update(&self.pcr2);
        hasher.finalize().to_vec()
    }
}

/// Raw Hardware Attestation Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub hardware_type: EnclaveHardwareType,
    pub module_id: String,
    pub timestamp_utc_ms: u64,
    pub pcrs: PlatformConfigurationRegisters,
    pub certificate_der: Vec<u8>,
    pub signature_bytes: Vec<u8>,
    pub user_data_sha256: Vec<u8>,
    pub nonce: String,
}

/// Expected reference golden measurements authorized for production execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEnclavePolicy {
    pub allowed_pcr0_hashes: Vec<Vec<u8>>,
    pub allowed_pcr1_hashes: Vec<Vec<u8>>,
    pub allowed_pcr2_hashes: Vec<Vec<u8>>,
    pub trusted_ca_fingerprints: Vec<Vec<u8>>,
    pub max_allowed_clock_skew_seconds: i64,
}

impl GoldenEnclavePolicy {
    pub fn is_pcr0_valid(&self, pcr0: &[u8]) -> bool {
        self.allowed_pcr0_hashes.iter().any(|h| h.as_slice() == pcr0)
    }

    pub fn is_pcr1_valid(&self, pcr1: &[u8]) -> bool {
        self.allowed_pcr1_hashes.iter().any(|h| h.as_slice() == pcr1)
    }

    pub fn is_pcr2_valid(&self, pcr2: &[u8]) -> bool {
        self.allowed_pcr2_hashes.iter().any(|h| h.as_slice() == pcr2)
    }
}

/// High-performance Hardware Attestation Verifier
pub struct HardwareAttestationVerifier {
    policy: GoldenEnclavePolicy,
}

impl HardwareAttestationVerifier {
    pub fn new(policy: GoldenEnclavePolicy) -> Self {
        Self { policy }
    }

    /// Verifies hardware attestation document against golden policy and nonce
    pub fn verify_attestation(
        &self,
        doc: &AttestationDocument,
        expected_nonce: &str,
        current_timestamp_utc_ms: u64,
        expected_payload: Option<&[u8]>,
    ) -> Result<bool, AttestationError> {
        // 1. Verify Nonce freshness
        if doc.nonce != expected_nonce {
            return Err(AttestationError::NonceMismatch {
                expected: expected_nonce.to_string(),
                actual: doc.nonce.clone(),
            });
        }

        // 2. Verify clock skew / freshness
        let delta_ms = (current_timestamp_utc_ms as i64 - doc.timestamp_utc_ms as i64).abs();
        let delta_seconds = delta_ms / 1000;
        if delta_seconds > self.policy.max_allowed_clock_skew_seconds {
            return Err(AttestationError::TimestampExpired { delta_seconds });
        }

        // 3. Verify PCR0 (Linux Kernel & Boot measurements)
        if !self.policy.is_pcr0_valid(&doc.pcrs.pcr0) {
            return Err(AttestationError::PcrMismatch { pcr_index: 0 });
        }

        // 4. Verify PCR1 (Enclave Application image hash)
        if !self.policy.is_pcr1_valid(&doc.pcrs.pcr1) {
            return Err(AttestationError::PcrMismatch { pcr_index: 1 });
        }

        // 5. Verify PCR2 (Security & Solvency Policy hash)
        if !self.policy.is_pcr2_valid(&doc.pcrs.pcr2) {
            return Err(AttestationError::PcrMismatch { pcr_index: 2 });
        }

        // 6. Verify User Data bind (Hash of public key / session payload)
        if let Some(payload) = expected_payload {
            let mut hasher = Sha256::new();
            hasher.update(payload);
            let expected_user_hash = hasher.finalize().to_vec();
            if expected_user_hash != doc.user_data_sha256 {
                return Err(AttestationError::UntrustedSigner);
            }
        }

        // 7. Verify Certificate Trust Chain
        let cert_hash = Sha256::digest(&doc.certificate_der).to_vec();
        if !self.policy.trusted_ca_fingerprints.iter().any(|f| f == &cert_hash) {
            return Err(AttestationError::UntrustedSigner);
        }

        // 8. Signature authenticity check (Simulated ECDSA P-384 hardware verification)
        if doc.signature_bytes.is_empty() {
            return Err(AttestationError::UntrustedSigner);
        }

        Ok(true)
    }

    /// Evaluates if an enclave session can be authorized for zero-trust PII decryption
    pub fn authorize_enclave_channel(
        &self,
        enclave_doc: &AttestationDocument,
        session_challenge: &str,
        now_ms: u64,
    ) -> Result<String, AttestationError> {
        self.verify_attestation(enclave_doc, session_challenge, now_ms, None)?;
        
        let token = format!(
            "APODICTIC-ENCLAVE-SESSION:{}:{}",
            enclave_doc.module_id,
            hex_encode(&enclave_doc.pcrs.composite_hash())
        );
        Ok(token)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pcr(byte_val: u8) -> Vec<u8> {
        vec![byte_val; 48]
    }

    #[test]
    fn test_valid_attestation() {
        let pcr0 = dummy_pcr(0xAA);
        let pcr1 = dummy_pcr(0xBB);
        let pcr2 = dummy_pcr(0xCC);

        let cert = vec![0x30, 0x82, 0x01, 0x00];
        let cert_fingerprint = Sha256::digest(&cert).to_vec();

        let policy = GoldenEnclavePolicy {
            allowed_pcr0_hashes: vec![pcr0.clone()],
            allowed_pcr1_hashes: vec![pcr1.clone()],
            allowed_pcr2_hashes: vec![pcr2.clone()],
            trusted_ca_fingerprints: vec![cert_fingerprint],
            max_allowed_clock_skew_seconds: 60,
        };

        let verifier = HardwareAttestationVerifier::new(policy);
        let pcrs = PlatformConfigurationRegisters::new(pcr0, pcr1, pcr2).unwrap();

        let doc = AttestationDocument {
            hardware_type: EnclaveHardwareType::AwsNitroEnclave,
            module_id: "nitro-enclave-us-east-1-0492".to_string(),
            timestamp_utc_ms: 1794769200000,
            pcrs,
            certificate_der: cert,
            signature_bytes: vec![0xFF; 64],
            user_data_sha256: vec![],
            nonce: "challenge-nonce-9941".to_string(),
        };

        let result = verifier.verify_attestation(
            &doc,
            "challenge-nonce-9941",
            1794769205000,
            None,
        );
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_pcr_mismatch() {
        let pcr0 = dummy_pcr(0xAA);
        let pcr1 = dummy_pcr(0xBB);
        let pcr2 = dummy_pcr(0xCC);
        let forged_pcr0 = dummy_pcr(0x99);

        let cert = vec![0x30, 0x82, 0x01, 0x00];
        let cert_fingerprint = Sha256::digest(&cert).to_vec();

        let policy = GoldenEnclavePolicy {
            allowed_pcr0_hashes: vec![pcr0],
            allowed_pcr1_hashes: vec![pcr1.clone()],
            allowed_pcr2_hashes: vec![pcr2.clone()],
            trusted_ca_fingerprints: vec![cert_fingerprint],
            max_allowed_clock_skew_seconds: 60,
        };

        let verifier = HardwareAttestationVerifier::new(policy);
        let pcrs = PlatformConfigurationRegisters::new(forged_pcr0, pcr1, pcr2).unwrap();

        let doc = AttestationDocument {
            hardware_type: EnclaveHardwareType::AwsNitroEnclave,
            module_id: "nitro-enclave-rogue".to_string(),
            timestamp_utc_ms: 1794769200000,
            pcrs,
            certificate_der: cert,
            signature_bytes: vec![0xFF; 64],
            user_data_sha256: vec![],
            nonce: "fresh-nonce".to_string(),
        };

        let result = verifier.verify_attestation(
            &doc,
            "fresh-nonce",
            1794769205000,
            None,
        );
        assert_eq!(result, Err(AttestationError::PcrMismatch { pcr_index: 0 }));
    }
}
