//! Noesis Rust Systems Kernel — Annotated Excerpts from Verified Workspace Crates
//! Repository Paths Referenced:
//!   1. noesis_infra/crates/noesis-wire-proxy/src/lib.rs      (PG 3.0 WireCodec & SQLSTATE 40001)
//!   2. noesis_infra/crates/noesis-jailer/src/lib.rs          (24-Syscall Seccomp-BPF & Firecracker Config)
//!   3. noesis_infra/crates/noesis-sovereign-audit-vault/src/lib.rs (SEC 17a-4 WORM Forward Hash Chain)
//!   4. noesis_infra/crates/noesis-merkle-trie/src/lib.rs     (Hexary Merkle-Patricia Inclusion/Exclusion Proofs)

// ============================================================================
// EXCERPT 1: PostgreSQL 3.0 Wire Protocol Codec (noesis-wire-proxy/src/lib.rs)
// ============================================================================
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const MSG_QUERY: u8 = b'Q';
pub const MSG_PARSE: u8 = b'P';
pub const MSG_ERROR_RESPONSE: u8 = b'E';
pub const MSG_READY_FOR_QUERY: u8 = b'Z';
pub const SQLSTATE_SOLVENCY_INVARIANT_BREACH: &str = "40001";
pub const SQLSTATE_UNBOUNDED_DESTRUCTIVE_MUTATION: &str = "42501";

pub struct WireCodec;

impl WireCodec {
    pub fn encode_error_response(message: &str, sqlstate: &str, detail: Option<&str>) -> Bytes {
        let mut buf = BytesMut::with_capacity(256);
        buf.put_u8(MSG_ERROR_RESPONSE);

        let mut body = BytesMut::new();
        body.put_u8(b'S'); body.put_slice(b"ERROR\0");
        body.put_u8(b'V'); body.put_slice(b"ERROR\0");
        body.put_u8(b'C'); body.put_slice(sqlstate.as_bytes()); body.put_u8(0);
        body.put_u8(b'M'); body.put_slice(message.as_bytes()); body.put_u8(0);
        if let Some(d) = detail {
            body.put_u8(b'D'); body.put_slice(d.as_bytes()); body.put_u8(0);
        }
        body.put_u8(0);

        let length = (body.len() + 4) as u32;
        buf.put_u32(length);
        buf.put(body);
        buf.freeze()
    }
}

// ============================================================================
// EXCERPT 2: 24-Syscall Seccomp-BPF Enclave Allowlist (noesis-jailer/src/lib.rs)
// ============================================================================
pub const ALLOWED_SYSCALLS: &[i64] = &[
    0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 24, 28, 39, 60, 228, 231, 318, 332,
];

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// ============================================================================
// EXCERPT 3: SEC 17a-4 WORM Hash Chaining (noesis-sovereign-audit-vault/src/lib.rs)
// ============================================================================
// Each block binds: sequence_num || previous_hash || sha256(payload_bytes) || timestamp_utc_ms || legal_hold_until_ms
// verify_integrity() re-hashes BOTH payload_bytes -> payload_hash AND block header -> entry_hash from genesis to tip.

// ============================================================================
// EXCERPT 4: Hexary Merkle-Patricia Proof Structure (noesis-merkle-trie/src/lib.rs)
// ============================================================================
// Supports both cryptographic INCLUSION proofs (exists == true, value == Some(bal))
// and EXCLUSION proofs (exists == false, value == None) to prove unrecorded off-book liabilities do not exist.
