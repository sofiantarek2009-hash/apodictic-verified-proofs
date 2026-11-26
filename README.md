# Apodictic — Public Verification Harness, SDKs & CI Attestations (v3.10.1)

> **Public verification suite, open-source SDKs (`apodictic-sdk@3.10.1`, `apodictic-mcp-verifier@3.10.1`), sealed 23-artifact evidence package, and GitHub Actions CI attestations for [Apodictic](https://www.apodictic.dev).**
>
> The Apodictic enterprise core (`apodictic_engine/`, `apodictic_infra/` 9-crate Rust workspace with `176/176` unit tests, and enterprise ERP adapters) enforces deterministic SQL/ERP/MCP formal verification via Microsoft Z3 `5.4.1`, pure-Rust OxiZ `0.3.4`, and embedded PostgreSQL (`@electric-sql/pglite` & native TCP `pgwire` `SAVEPOINT` mode). This public repository contains all **10 standalone executable Z3 `5.4.1` & Odoo 18–20 proof bundles**, our **v3.10.1 Proof Pack** (**Gist 11**), all **23 SHA-256 sealed receipts** (`manifest.sha256`), our public **`apodictic-sdk@3.10.1`** & **`apodictic-mcp-verifier@3.10.1`** npm packages, and reproducible concurrency & self-heal benchmarks.

## Instant Zero-Python Verification Demo & Odoo 20 Proxy (`npx`)

Run the 3-scenario formal verification demo (WASM PostgreSQL + Z3 5.4.1 WebAssembly) or wrap an Odoo 18–20 server in shadow `observe` mode on any machine with Node.js `>=22.5`:

```bash
npx apodictic-mcp-verifier demo
npx apodictic-mcp-verifier wrap-odoo --mode observe --port 8070 --upstream http://127.0.0.1:8069
```

## Verify All 23 Sealed Evidence Artifacts (`manifest.sha256`)

```bash
(cd evidence && shasum -a 256 -c manifest.sha256) # macOS
# or: (cd evidence && sha256sum -c manifest.sha256) # Linux
```

Key v3.10.1 receipts inside [`./evidence/`](./evidence):
- [`evidence/pg17-concurrency-receipt.json`](./evidence/pg17-concurrency-receipt.json) — **16-worker live TCP Rust `apodictic_pg_proxy`** (`3` allowed / `13` blocked via `SQLSTATE 40001` / `0` overdrafts / `$30,000` final balance / WORM WAL verified in `86 ms`) + **PostgreSQL 18.7 (`@electric-sql/pglite`) `SAVEPOINT ... ROLLBACK TO SAVEPOINT`** catching **`16/16`** hidden PL/pgSQL `AFTER UPDATE` fee-drain triggers (`0` corrupted rows).
- [`evidence/self-heal-benchmark.json`](./evidence/self-heal-benchmark.json) — **100-case `z3.Optimize()` counterfactual self-heal benchmark**: **`100/100 (100%)`** 1-shot guided repair vs **`0%`** blind 1-shot (**`1%`** blind 3-shot), with **`15/15`** SQL-embedded negative literal attacks safely clamped to **`$0`** (`p50 = 5.904 ms`).
- [`evidence/odoo20-mcp-advisory-readonly-poc.md`](./evidence/odoo20-mcp-advisory-readonly-poc.md) — **Odoo 20 Advisory Readonly MCP PoC**: executable exploit & mitigation proof showing UI-only `Readonly` flags bypassed over `/json/2/` and blocked by `wrap-odoo --mode observe|enforce`.
- [`evidence/rust-workspace-receipt.txt`](./evidence/rust-workspace-receipt.txt) — **`176/176`** passing Rust unit tests across 9 crates (`0` failures), including multi-table `BEGIN`/`COMMIT`/`ROLLBACK` stateful proofs (`stock_quant`, `account_move_line`, `product_pricelist_item`), `--mode observe|enforce`, and `--savepoint-mode`.
- [`evidence/vitest-verification-receipt.txt`](./evidence/vitest-verification-receipt.txt) — **`47/47`** passing Vitest integration tests across `9` test files (Hosted Streamable HTTP `/api/mcp` 10 live tools, single-use `tx_digest`-bound Ed25519 HITL CFO approvals, Zod Policy IR + Z3 deadlock checks, PGlite shadow execution, and SPIFFE SVID auth).
- [`docs/odoo20-mcp-advisory-readonly-poc.md`](./docs/odoo20-mcp-advisory-readonly-poc.md) — Executable PoC & defense analysis for Odoo 20's UI-only advisory `Readonly` bypass over `/json/2/` and `/mcp`.

## Run All 10 Standalone Z3 & Odoo 18–20 Proof Bundles Locally

```bash
pip install -r requirements.txt
for f in gists/*/*.py; do echo "=== $f ==="; python3 "$f"; done
```

## Run SDK & MCP Verifier Test Suites

```bash
(cd packages/apodictic-sdk && npm install && npm test)
(cd packages/apodictic-mcp-verifier && npm install && npm test)
```

## All 11 Standalone Executable Proof Gists & Live Bundles

| # | Repository Bundle Path | Standalone Gist (`HTTP 200`) | Domain & Verified Coverage |
| :--- | :--- | :--- | :--- |
| **01** | [`gists/01-apodictic-main-architecture-showcase`](./gists/01-apodictic-main-architecture-showcase) | [Open Gist 01](https://gist.github.com/sofiantarek2009-hash/e1e50ef1c6cf2da885b6bbf5d7f1cc27) | Full-Stack 12-Subsystem Kernel & Dual SMT Flow |
| **02** | [`gists/02-critical-path-multi-erp-lifecycle`](./gists/02-critical-path-multi-erp-lifecycle) | [Open Gist 02](https://gist.github.com/sofiantarek2009-hash/1835af1152570f714bf08a27e16045e5) | Critical Path & 5-System ERP Clearing Walkthrough |
| **03** | [`gists/03-nontech-ai-financial-safety-net`](./gists/03-nontech-ai-financial-safety-net) | [Open Gist 03](https://gist.github.com/sofiantarek2009-hash/a435fa60eb6f8fc84dd71ee5cf7fd318) | Zero Data Leaks, Reserve Floor & Instant Rewind |
| **04** | [`gists/04-nontech-erp-autopilot`](./gists/04-nontech-erp-autopilot) | [Open Gist 04](https://gist.github.com/sofiantarek2009-hash/a701512b42e82b528c764392710f7bca) | Automated 3-Way Match & Subset-Sum Wire Clearing |
| **05** | [`gists/05-nontech-audit-in-one-second`](./gists/05-nontech-audit-in-one-second) | [Open Gist 05](https://gist.github.com/sofiantarek2009-hash/2e23399e09d3517519d890423918e1c7) | Bi-Temporal SQL:2011 Accounting & SEC 17a-4 RFC 6962 Merkle Audit |
| **06** | [`gists/06-domain-secrets-erp-split-brain`](./gists/06-domain-secrets-erp-split-brain) | [Open Gist 06](https://gist.github.com/sofiantarek2009-hash/bebb0a61d894d6cf8527ef7c8b5c8120) | Multicurrency ERP Split-Brain & FX Drift Reversal |
| **07** | [`gists/07-domain-secrets-mena-einvoicing-tax`](./gists/07-domain-secrets-mena-einvoicing-tax) | [Open Gist 07](https://gist.github.com/sofiantarek2009-hash/7e08539ce025abbb1f76779f6e2415d8) | Egypt ETA Compound T2/T1 Tax, T4 WHT & KSA ZATCA BR-CO-14 Parity |
| **08** | [`gists/08-domain-secrets-multi-turn-smurfing-defense`](./gists/08-domain-secrets-multi-turn-smurfing-defense) | [Open Gist 08](https://gist.github.com/sofiantarek2009-hash/820360e91d5a353ff949c1ac4acae18f) | Indirect OCR Prompt Injection & 24h Split-Payment Smurfing Defense |
| **09** | [`gists/09-live-odoo-eta-invoice-pipeline`](./gists/09-live-odoo-eta-invoice-pipeline) | [Open Gist 09](https://gist.github.com/sofiantarek2009-hash/8df417b9511306993ef1252b3485e68f) | Live Odoo 18–20 JSON-RPC 2.0 / JSON-2 & Egypt ETA v1.0 Pipeline |
| **10** | [`gists/10-odoo20-mcp-json2-firewall`](./gists/10-odoo20-mcp-json2-firewall) | [Open Gist 10](https://gist.github.com/sofiantarek2009-hash/ee838059d7c4b0c3b9896ca40094a39d) | Odoo 20 `/json/2/` Bearer API & MCP Agentic ERP Firewall |
| **11** | [`evidence/`](./evidence) & [`docs/odoo20-mcp-advisory-readonly-poc.md`](./docs/odoo20-mcp-advisory-readonly-poc.md) | [Open Gist 11](https://gist.github.com/sofiantarek2009-hash/592c0ebdb0255ba88172f5ecbfbf4bc3) | v3.10.1 Proof Pack: 16-Worker TCP & PG 18.7 Concurrency, 100-Case Self-Heal, Odoo 20 Readonly PoC & Scope |

## Live Site, Machine-Readable Specs, Packages & PDF Briefs

- **Live Web Explorer & Proofs:** [`www.apodictic.dev/proofs`](https://www.apodictic.dev/proofs) · [Interactive Sandbox](https://www.apodictic.dev/sandbox) · [Hosted MCP (`/api/mcp`)](https://www.apodictic.dev/mcp) · [`/api/health`](https://www.apodictic.dev/api/health) · [`/api/apodictic/proof-transcript`](https://www.apodictic.dev/api/apodictic/proof-transcript)
- **AI Agent & Crawler Discovery:** [`/llms.txt`](https://www.apodictic.dev/llms.txt) · [`/llms-full.txt`](https://www.apodictic.dev/llms-full.txt) · [`/.well-known/agent.json`](https://www.apodictic.dev/.well-known/agent.json) · [`/.well-known/mcp.json`](https://www.apodictic.dev/.well-known/mcp.json) · [`/sitemap.xml`](https://www.apodictic.dev/sitemap.xml)
- **Published npm Packages (v3.10.1):** [`apodictic-sdk@3.10.1`](https://www.npmjs.com/package/apodictic-sdk) · [`apodictic-mcp-verifier@3.10.1`](https://www.npmjs.com/package/apodictic-mcp-verifier)
- **Technical Briefs (PDF):** [Working Paper](https://www.apodictic.dev/apodictic-working-paper-2026.pdf) · [System Model Card](https://www.apodictic.dev/apodictic-model-card-v3.pdf) · [Security Architecture Brief](https://www.apodictic.dev/apodictic-security-architecture-brief.pdf)

## Proof Bundles & Related Systems

- **Alpha Genesis (EGX Trading Engine):** [Showcase Repo](https://github.com/sofiantarek2009-hash/alpha-genesis-overview) · [Runnable Proof Gist](https://gist.github.com/sofiantarek2009-hash/a342d001d6ee81478a3e33519afaed29)
- **Polymarket Statistical Models:** [Showcase Repo](https://github.com/sofiantarek2009-hash/polymarket-prediction-models) · [Runnable Proof Gist](https://gist.github.com/sofiantarek2009-hash/9b62a1b39b175a7574452c393e16f71f)
- **AI Legal NLP, Biotech & Forecasting:** [Showcase Repo](https://github.com/sofiantarek2009-hash/ai-legal-compliance-nlp) · [Runnable Proof Gist](https://gist.github.com/sofiantarek2009-hash/66bcce759395d549fa402d0ee4411cd8)
- **Autonomous Fixed-Wing UAV (SIL):** [Showcase Repo](https://github.com/sofiantarek2009-hash/autonomous-fixed-wing-uav) · [Runnable Proof Gist](https://gist.github.com/sofiantarek2009-hash/5a2fe80e4b6eb7809202c54b7a337255)
- **Apodictic Public Verification Harness (11 Proof Bundles + 23 Sealed Artifacts):** [apodictic-verified-proofs](https://github.com/sofiantarek2009-hash/apodictic-verified-proofs)
- **Live Explorer & AI Agent Specs:** [www.apodictic.dev/proofs](https://www.apodictic.dev/proofs) · [`llms.txt`](https://www.apodictic.dev/llms.txt) · [`.well-known/agent.json`](https://www.apodictic.dev/.well-known/agent.json) · [GitHub Profile](https://github.com/sofiantarek2009-hash)
