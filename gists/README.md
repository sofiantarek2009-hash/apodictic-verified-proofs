# Apodictic — Verifiable Architecture & Executable Domain Proofs

> Every one of our **10 verified proof bundles** contains **zero mock stubs**, **zero marketing fluff**, **zero credentials**, and at least one **standalone executable Python + Microsoft Z3 (`5.4.1`) verification script** alongside protocol/sequence diagrams. All suites are backed by our **9 Rust crates** (`169` Rust workspace tests passing across `apodictic_infra` via `cargo test --workspace`), our Python formal verification engine (`apodictic_engine/`, `66` tests), and TypeScript/Next.js verification gateways (`packages/`, `frontend/`).

---

## Bundle Index (Publishable as Secret Gists via `bash gists/publish_all_gists.sh`)

| # | Track | Directory | What It Proves Live |
| :--- | :--- | :--- | :--- |
| **1** | Core Architecture & Rust Kernel | [`01-apodictic-main-architecture-showcase/`](./01-apodictic-main-architecture-showcase/) | 12-file C4 topology, PG 3.0 wire proxy, synced 9-crate Rust kernel (`apodictic_rust_kernel.rs`), TypeScript SMT-LIB2 bridge, OpenAPI 3.1, 12-subsystem Z3 runner & SHA-256 transcript (`81.396 ms`), 100-case & 200-req benchmarks |
| **2** | Critical Path & Multi-ERP | [`02-critical-path-multi-erp-lifecycle/`](./02-critical-path-multi-erp-lifecycle/) | Byte-level PG 3.0 wire -> Zero-PII -> Z3 -> WORM Vault lifecycle across Postgres, Odoo 18, NetSuite, SAP S/4HANA 3-Way Match & ISO 20022 (`pain.001` + Merkle exclusion) |
| **3** | Non-Technical Safety Net | [`03-nontech-ai-financial-safety-net/`](./03-nontech-ai-financial-safety-net/) | Executive explanation + runnable idempotent Zero-PII leakage check (`0` exposed secret bytes) & symbolic Z3 `$20,000` payroll reserve cap veto |
| **4** | Non-Technical ERP Autopilot | [`04-nontech-erp-autopilot/`](./04-nontech-erp-autopilot/) | Plain-English finance overview + runnable Z3 3-Way Match, Subset-Sum lump-sum wire clearing (`$84,975`), & Basel III LCR ceiling (`$1,150,000`) |
| **5** | Non-Technical 1-Second Audit | [`05-nontech-audit-in-one-second/`](./05-nontech-audit-in-one-second/) | Dual-timeline audit time travel (`$1.00M` March view vs `$1.15M` Q3 restatement), runnable `$0.01` WORM tamper detector, RFC 6962 inclusion/exclusion proofs, & smurfing alert |
| **6** | Domain Secret: ERP Split-Brain | [`06-domain-secrets-erp-split-brain/`](./06-domain-secrets-erp-split-brain/) | Why naive idempotency corrupts posted ERPs & how Z3 solves FX drift revaluation (`49.20 -> 49.35 EGP/USD`) + idempotent saga retries |
| **7** | Domain Secret: MENA E-Invoicing | [`07-domain-secrets-mena-einvoicing-tax/`](./07-domain-secrets-mena-einvoicing-tax/) | Egypt ETA compound `T2 -> T1` tax base, payment-time `T4` WHT (`Net` only), & ZATCA `BR-CO-14` halala UBL XML parity via `z3.Optimize()` |
| **8** | Domain Secret: Stateful Agent Defense | [`08-domain-secrets-multi-turn-smurfing-defense/`](./08-domain-secrets-multi-turn-smurfing-defense/) | Stopping indirect OCR invoice prompt injections, Mod-97 spaced/lowercase IBAN detection, & 4-session 24h sliding-window smurfing below `$50k` caps |
| **9** | Live Odoo 18–20 + Egypt ETA Pipeline | [`09-live-odoo-eta-invoice-pipeline/`](./09-live-odoo-eta-invoice-pipeline/) | Full stateful TCP HTTP Odoo 18–20 (`/jsonrpc` & `/json/2/`) + canonical ETA v1.0 SHA-256 (excluding `signatures`) + `T4` WHT + `account.move.reversal` + OCR quarantine + idempotency |
| **10** | Odoo 20 JSON-2 & MCP Agentic ERP Firewall | [`10-odoo20-mcp-json2-firewall/`](./10-odoo20-mcp-json2-firewall/) | Live `/json/2/` + `/doc-bearer/` OpenAPI schema gate, `bearer_scope='mcp'` escalation & removed `db` RPC block, `hard_lock_date`/`inalterable_hash`, `field_diff` WORM chain, & Z3 multi-row `account.move.line` conservation |

---

## Publishing as Secret Gists

GitHub Secret Gists are **unlisted** (excluded from search engines, Discover feeds, and public profiles) while remaining directly readable by reviewers with the exact URL:

```bash
chmod +x gists/publish_all_gists.sh
bash gists/publish_all_gists.sh
```

> Always test each emitted Secret Gist URL in a logged-out incognito browser window before sharing.
