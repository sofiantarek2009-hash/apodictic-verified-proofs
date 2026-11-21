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
