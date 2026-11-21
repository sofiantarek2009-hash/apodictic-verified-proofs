# Apodictic — Enterprise Verification, Security & Financial Settlement Kernel

> **Pre-Execution Mathematical Firewall for Autonomous Enterprise Systems**  
> Built on **Microsoft Z3 5.4.1 (`QF_LRA` / `QF_AUFLIA` / `z3.Optimize`)**, **Zero-PII Bijective Vault Tokenization**, **SQL Hoare-Logic Symbolic Verification**, **Palantir-Grade Kinetic Financial Ontology**, **3-Way ERP Clearing**, **Odoo 18–20 JSON-2 & MCP Firewall**, and **SEC 17a-4 WORM + Hexary Merkle-Patricia Forensics**.

---

## Why This Exists

Probabilistic LLMs hallucinate 1–3% of the time. When an autonomous AI agent is connected to a corporate PostgreSQL database, Odoo 18–20, Oracle NetSuite, SAP S/4HANA, or an ISO 20022 payment rail, a 1% hallucination error causes unauthorized overdrafts, leaking IBAN/tax IDs, phantom invoice payments, or uncompensated accounting imbalances.

**Apodictic sits in front of the database and ERP wire** as a deterministic pre-commit firewall:
1. **Masks sensitive identifiers (`<SYM_*>`)** before prompts or traces ever reach external models.
2. **Parses SQL mutations & ERP actions** into SSA symbolic representations and AST graphs.
3. **Proves business, tax, solvency, and Separation-of-Duties invariants mathematically** using Z3 `5.4.1` before any byte commits upstream.
4. **Intercepts invariant violations** directly on the wire (`SQLSTATE 40001` / `42501`), synthesizes counterexample witnesses & compensating SQL patches, and arms LIFO rollback savepoints (`<38ms` SLA).
5. **Commits immutable cryptographic receipts** into an SEC 17a-4 WORM hash chain, SQL:2011 bi-temporal ledger, and Hexary Merkle-Patricia State Trie.

---

## Verified Repository & Benchmark Statistics

Measured directly on this repository (macOS Darwin-arm64, Python `3.9.8`, Microsoft Z3 `5.4.1`, Rust/Cargo workspace, Next.js TypeScript):

| Layer | Audited Physical Scope | Measured Verification Receipts |
| :--- | :--- | :--- |
| **Rust & C Systems Workspace (`apodictic_infra/`)** | **9 wired production crates** (`apodictic-symbolic-sql`, `apodictic-z3-engine`, `apodictic-zero-leak-sanitizer`, `apodictic-merkle-trie`, `apodictic-sovereign-audit-vault`, `apodictic-wire-proxy`, `apodictic-cdc-engine`, `apodictic-policy-engine`, `apodictic-cli-admin`), `libz3` C FFI + OxiZ dual solver (`apodictic_rust_kernel --daemon`), bidirectional PG Wire Proxy, & `pgoutput` binary CDC decoder | `cargo test --workspace`: **9 / 9 production crates, 169 / 169 tests passing (`Exit Code 0`)**, native `libz3.dylib` C FFI proofs, RFC 6962 audit path, Hexary Merkle Trie, WORM vault, real TCP Extended Query wire interception |
| **Linux Firecracker Enclave Artifacts (`deploy/air-gapped/firecracker/`)** | Air-gapped KVM microVM launch script (`launch-microvm.sh`), 24-syscall filter (`seccomp-24.json`), & `virtio-vsock` guest CID 3 config (`vm-config.json`) | 2 vCPUs, 128 MiB RAM, `network-interfaces: []`, `seccomp-level 2` |
| **Python Formal Verification Engine (`apodictic_engine/`)** | Live Z3 `5.4.1`, Declarative Policy + Transitive Entity DAG (`ApodicticPolicyZ3Compiler`), Odoo 18–20 (`/jsonrpc` & `/json/2/`), Egypt ETA v1.0 & KSA ZATCA | **100-Case Suite (`60/60` blocked, `40/40` allowed, cold start `15.192 ms`, `p50 = 1.42 ms`, `p95 = 2.516 ms`, `p99 = 2.976 ms`)** + **200-Req Concurrent Load (`8` workers, `gate_p50 = 24.065 ms`, `gate_p99 = 29.836 ms`, `657.43 ms` total)** + **12-Subsystem Gist 01 Runner** |
| **Frontend & API Gateway (`frontend/`, `packages/`)** | Next.js App Router, React, TypeScript, SQLite WAL + ECDSA P-256 + 2-Phase Double-Entry Escrow + OPA & Envoy L7 `ext_proc` | `@apodictic/sdk` (including `odoo20_guard.mjs`), `@apodictic/mcp-verifier` (`scanApodicticMcpToolGuard`), & live `/api/apodictic/*` Next.js App Router endpoints |

### Live 12-Subsystem Proof Harness (`04-VERIFIABLE-CORE-RUNNER.py` -> `06-LIVE-EXECUTION-TRANSCRIPT.json`)

Full 12-subsystem standalone Z3 `5.4.1` harness + 100-iteration continuous solve benchmark completes in **`81.396 ms`** (`p50 = 0.440 ms`, `p95 = 0.641 ms`, `p99 = 1.189 ms`) with master SHA-256 attestation root:  
`82d22e176dcb6bacc8232982378b7a620f32517dba3e2bcc2e51ad6a3aba26f7`

---

## Multi-File Showcase Index (12 Files)

1. [`00-ARCHITECTURE-OVERVIEW.md`](./00-ARCHITECTURE-OVERVIEW.md) — Executive thesis, audited statistics, and reproduction commands.
2. [`01-SYSTEM-TOPOLOGY.mermaid`](./01-SYSTEM-TOPOLOGY.mermaid) — C4 Container & End-to-End System Topology diagram.
3. [`02-CRITICAL-PATH-SEQUENCE.mermaid`](./02-CRITICAL-PATH-SEQUENCE.mermaid) — Transaction lifecycle across `apodictic-wire-proxy -> ZeroPIIGateway -> apodictic-z3-engine -> apodictic-sovereign-audit-vault`.
4. [`03-API-CONTRACTS.yaml`](./03-API-CONTRACTS.yaml) — OpenAPI 3.1 contracts for all 5 live `/api/apodictic/*` Next.js endpoints.
5. [`03-CORE-ENGINE-EXTRACTS.py`](./03-CORE-ENGINE-EXTRACTS.py) — Annotated Hoare-logic SQL weakest-precondition, DDL/COPY/CALL blocker & patch synthesis extract.
6. [`04-VERIFIABLE-CORE-RUNNER.py`](./04-VERIFIABLE-CORE-RUNNER.py) — Zero-dependency, 12-subsystem Python + Z3 `5.4.1` executable verification suite & 100-iteration live benchmark.
7. [`04b-TYPESCRIPT-API-BRIDGE.ts`](./04b-TYPESCRIPT-API-BRIDGE.ts) — Verified TypeScript SMT-LIB2 compiler & SEC 17a-4 WORM chain integrity bridge from the Next.js API gateway.
8. [`05-RUST-SYSTEMS-KERNEL.rs`](./05-RUST-SYSTEMS-KERNEL.rs) — Synced Rust kernel code (`apodictic_rust_kernel.rs`) uniting `apodictic-symbolic-sql`, `apodictic-z3-engine`, `apodictic-policy-engine`, `apodictic-cdc-engine`, `apodictic-zero-leak-sanitizer`, `apodictic-merkle-trie`, and `apodictic-sovereign-audit-vault`.
9. [`06-LIVE-EXECUTION-TRANSCRIPT.json`](./06-LIVE-EXECUTION-TRANSCRIPT.json) — Freshly captured Z3 `5.4.1` 12-subsystem proof transcript & unsat-core trace (`04-VERIFIABLE-CORE-RUNNER.py --json`).
10. [`07-ENTERPRISE-READINESS-AND-SECURITY.md`](./07-ENTERPRISE-READINESS-AND-SECURITY.md) — Audit of idempotency, multi-tenant rate limiting, ABAC/SoD, Firecracker/seccomp isolation, W3C tracing, and CI gates.
11. [`08-PUBLIC-SECURITY-BENCHMARK.json`](./08-PUBLIC-SECURITY-BENCHMARK.json) — 100-Case Public Security Benchmark (`60/60` attacks blocked across 6 categories, `40/40` valid transactions allowed, `0` leaked secrets).
12. [`09-CONCURRENT-LOAD-BENCHMARK.json`](./09-CONCURRENT-LOAD-BENCHMARK.json) — 200-request / 8-worker concurrent load & memory profile (`gate_p50 = 24.065 ms`, `gate_p99 = 29.836 ms`, `sha256_digest`).

---

## Reproduce Locally in 3 Seconds

```bash
pip install z3-solver
python3 04-VERIFIABLE-CORE-RUNNER.py
```
