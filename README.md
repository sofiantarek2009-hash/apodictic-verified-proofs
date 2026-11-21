# Apodictic — Public Verification Harness, SDKs & CI Attestations

> **Public verification suite, open-source SDKs (`apodictic-sdk`, `apodictic-mcp-verifier`), and GitHub Actions CI attestation logs for [Apodictic](https://www.apodictic.dev).**
>
> The Apodictic enterprise core (`apodictic_engine/`, `apodictic_infra/` 9-crate Rust workspace, and enterprise ERP adapters) enforces deterministic SQL/ERP/MCP formal verification via Microsoft Z3 `5.4.1`, pure-Rust OxiZ `0.3.4`, and WASM PostgreSQL 17 (`@electric-sql/pglite`). This public repository contains all **10 standalone executable Z3 `5.4.1` & Odoo 18–20 proof bundles**, the public **`apodictic-sdk@3.9.0`** & **`apodictic-mcp-verifier@3.9.0`** npm packages (with zero-Python WebAssembly Z3 + WASM PostgreSQL 17), and reproducible CI test logs.

## Instant Zero-Python Verification Demo (`npx`)

Run the 3-scenario formal verification demo (WASM PostgreSQL 17 + Z3 5.4.1 WebAssembly) on any machine with Node.js `>=22.5`:

```bash
npx apodictic-mcp-verifier demo
```

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

## All 10 Standalone Executable Proof Gists & Live Bundles

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

## Live Site, Machine-Readable Specs, Packages & PDF Briefs

- **Live Web Explorer & Proofs:** [`www.apodictic.dev/proofs`](https://www.apodictic.dev/proofs) · [Interactive Sandbox](https://www.apodictic.dev/sandbox) · [`/api/health`](https://www.apodictic.dev/api/health) · [`/api/apodictic/proof-transcript`](https://www.apodictic.dev/api/apodictic/proof-transcript)
- **AI Agent & Crawler Discovery:** [`/llms.txt`](https://www.apodictic.dev/llms.txt) · [`/llms-full.txt`](https://www.apodictic.dev/llms-full.txt) · [`/.well-known/agent.json`](https://www.apodictic.dev/.well-known/agent.json) · [`/.well-known/mcp.json`](https://www.apodictic.dev/.well-known/mcp.json) · [`/sitemap.xml`](https://www.apodictic.dev/sitemap.xml)
- **Published npm Packages (v3.9.0):** [`apodictic-sdk@3.9.0`](https://www.npmjs.com/package/apodictic-sdk) · [`apodictic-mcp-verifier@3.9.0`](https://www.npmjs.com/package/apodictic-mcp-verifier)
- **Technical Briefs (v3.9.0 PDF):** [Working Paper](https://www.apodictic.dev/apodictic-working-paper-2026.pdf) · [System Model Card](https://www.apodictic.dev/apodictic-model-card-v3.pdf) · [Security Architecture Brief](https://www.apodictic.dev/apodictic-security-architecture-brief.pdf)

## Proof Bundles & Related Systems

- **Alpha Genesis (EGX Trading Engine):** [Showcase Repo](https://github.com/sofiantarek2009-hash/alpha-genesis-overview) · [Runnable Proof Gist](https://gist.github.com/sofiantarek2009-hash/a342d001d6ee81478a3e33519afaed29)
- **Polymarket Statistical Models:** [Showcase Repo](https://github.com/sofiantarek2009-hash/polymarket-prediction-models) · [Runnable Proof Gist](https://gist.github.com/sofiantarek2009-hash/9b62a1b39b175a7574452c393e16f71f)
- **AI Legal NLP, Biotech & Forecasting:** [Showcase Repo](https://github.com/sofiantarek2009-hash/ai-legal-compliance-nlp) · [Runnable Proof Gist](https://gist.github.com/sofiantarek2009-hash/66bcce759395d549fa402d0ee4411cd8)
- **Autonomous Fixed-Wing UAV (SIL):** [Showcase Repo](https://github.com/sofiantarek2009-hash/autonomous-fixed-wing-uav) · [Runnable Proof Gist](https://gist.github.com/sofiantarek2009-hash/5a2fe80e4b6eb7809202c54b7a337255)
- **Apodictic Public Verification Harness (10 Proof Bundles + CI):** [apodictic-verified-proofs](https://github.com/sofiantarek2009-hash/apodictic-verified-proofs)
- **Live Explorer & AI Agent Specs:** [www.apodictic.dev/proofs](https://www.apodictic.dev/proofs) · [`llms.txt`](https://www.apodictic.dev/llms.txt) · [`.well-known/agent.json`](https://www.apodictic.dev/.well-known/agent.json) · [GitHub Profile](https://github.com/sofiantarek2009-hash)
