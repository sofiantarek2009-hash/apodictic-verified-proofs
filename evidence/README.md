# Apodictic Reproducible Evidence Package (v3.10.1)

This directory contains **23 cryptographically sealed, machine-readable verification receipts** generated on `Darwin arm64 / Python 3.9.8 / Node.js v22 / Z3 5.4.1 / Rust 1.100.0`:

- `pg17-concurrency-receipt.json` — **16-worker concurrency & trigger catch proof**: live TCP Rust `apodictic_pg_proxy` (`3` allow, `13` rejected via SQLSTATE `40001`, `0` overdrafts, WAL report verified in `86 ms`) + embedded PostgreSQL 18.7 (`@electric-sql/pglite`) `SAVEPOINT ... ROLLBACK TO SAVEPOINT` catching `16/16` hidden PL/pgSQL `AFTER UPDATE` fee-drain triggers (`0` corrupted rows).
- `self-heal-benchmark.json` — **100-case counterfactual repair benchmark**: `100/100 (100%)` 1-shot guided Z3 `Optimize` SQL repair vs `0%` blind 1-shot (`1%` blind 3-shot), with `15/15` SQL-embedded negative literal attacks safely clamped to `$0`.
- `odoo20-mcp-advisory-readonly-poc.md` — **Odoo 20 Advisory Readonly MCP PoC**: reproducible proof-of-concept demonstrating UI-only `Readonly` flag bypasses over `/json/2/` and blocking via `wrap-odoo --mode observe|enforce`.
- `rust-workspace-receipt.txt` — Verbatim `cargo test --workspace` execution output across all 9 crates in `apodictic_infra` (`176 / 176` passing tests, including multi-table `BEGIN`/`COMMIT`/`ROLLBACK` stateful proofs for `stock_quant`, `account_move_line`, and `product_pricelist_item`, `--mode observe|enforce`, `--savepoint-mode`, and Ed25519 tokens).
- `vitest-verification-receipt.txt` — Verbatim `npx vitest run` execution output across all `9` TypeScript/API test files (`47 / 47` passing tests, including Hosted MCP `/api/mcp`, Ed25519 single-use HITL approvals, Zod Policy IR + Z3 deadlock checks, PGlite shadow execution, SPIFFE SVID 401, and Odoo 20 invariants).
- `crash-matrix.csv` — 4-point `SIGKILL` crash consistency matrix (`before_verification`, `after_verification_before_commit`, `during_tx_before_commit`, `after_commit_before_response`).
- `mutation-testing.json` — Security-critical Z3 constraint mutation suite (`4/4` mutants killed, `100%`).
- `confusion-matrix.json` — `10,000`-case unique adversarial suite confusion matrix (`TP=7,500`, `TN=2,500`, `FP=0`, `FN=0`).
- `benchmark.json` — Multi-suite latency & v3.10.1 execution receipt (`P50/P95/P99`).
- `limitations.md` — Explicit scope, updated PostgreSQL 18.7 / live TCP 16-worker receipts, enforcement boundaries, and remaining external infrastructure validation requirements.
- `manifest.sha256` — SHA-256 checksums sealing all `23` artifact files in this evidence package (`23/23 OK`).

Public Proof Links:
- Public Proof Repo: `https://github.com/sofiantarek2009-hash/apodictic-verified-proofs`
- v3.10.1 Proof Pack Gist (#11): `https://gist.github.com/sofiantarek2009-hash/592c0ebdb0255ba88172f5ecbfbf4bc3`
- npm Packages: `apodictic-sdk@3.10.1` · `apodictic-mcp-verifier@3.10.1`
