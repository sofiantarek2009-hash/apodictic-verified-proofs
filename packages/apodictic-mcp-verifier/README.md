# `apodictic-mcp-verifier` (v3.10.0)

Drop-in Model Context Protocol (MCP) JSON-RPC 2.0 pre-commit verifier, stdio firewall, and **Odoo 18–20 `/json/2/` observe/enforce reverse proxy** for autonomous AI agents interacting with PostgreSQL, **Odoo 18–20 (`/json/2/` Bearer API, `/doc-bearer/`, & `/mcp`)**, Stripe, and enterprise ledgers.

## 60-Second Reproducible Demo (Zero Setup, Zero Python Required)

Run three real scenarios against an in-memory **WASM PostgreSQL 18.7** (`@electric-sql/pglite`) instance and **Microsoft Z3 5.4.1** (uses bundled Z3 5.4.1 WebAssembly out of the box when Python `z3-solver` is absent, or runs remote via `--endpoint https://www.apodictic.dev/api/v1/enclave`):

```bash
npx apodictic-mcp-verifier demo
```

What you will see:
1. **Legitimate financial write (`$12,500` disbursement)** → `SAT · ALLOWED` via Z3 5.4.1 (PostgreSQL balance updates `250,000 → 237,500`).
2. **Schema-accurate Odoo 18–20 `account_move_line` debit update (`$4,820` debit vs `$4,500` paired credit)** → passes PostgreSQL's single-row `CHECK (debit * credit = 0)` inside a PGlite shadow transaction (`ROLLBACK`), then blocked by Z3 5.4.1 `INV_DOUBLE_ENTRY_BALANCE` (`$320.00` multi-row drift).
3. **Attempted protected tax-record deletion (`DELETE FROM tax_chain`)** → `UNSAT · BLOCKED` by Z3 5.4.1 (`INV_REVERSIBILITY_GUARD`).

## Wrap Odoo 18–20 JSON-2 & MCP (`observe` or `enforce` Mode)

```bash
# Shadow observe mode first (forwards all requests, logs every would-be block):
npx apodictic-mcp-verifier wrap-odoo --mode observe --port 8070 --upstream http://127.0.0.1:8069

# Inspect executive "Caught in Shadow" summary:
curl -s http://127.0.0.1:8070/_apodictic/report

# Flip to enforce mode to hard-block Odoo 20 advisory Readonly bypasses & lock-date writes:
npx apodictic-mcp-verifier wrap-odoo --mode enforce --port 8070 --upstream http://127.0.0.1:8069
```

Also supports **single-use `tx_digest`-bound Ed25519 HITL CFO approval tokens** (`APODICTIC_APPROVAL_PUBKEY_PEM`) so replay or payload tampering fails closed, plus **lazy `/doc-bearer/<model>.json` OpenAPI introspection**.

## Wrap Any Stdio MCP Server (Postgres, Odoo 20 `/mcp`, Stripe)

```bash
npx apodictic-mcp-verifier wrap -- <your-mcp-server-command> [args...]
```

Or run as a standalone MCP verification server:

```bash
npx apodictic-mcp-verifier serve
```

## Open Developer Edition vs. Enterprise Edition

| Capability | Open Developer CLI / SDK (MIT) | Apodictic Enterprise (Paid Pilot / Annual) |
| :--- | :--- | :--- |
| Stdio MCP wrapping & 3-scenario PGlite + Z3 5.4.1 WASM demo | Included | Included |
| Stateless + local SQLite WAL Z3 5.4.1 verification (Zero Python) | Included | Included |
| Single-node PGlite WASM shadow execution (`BEGIN ... ROLLBACK`) | Included | Included |
| Odoo 19/20 `bearer_scope='mcp'`, `hard_lock_date` & `inalterable_hash` guard | Included | Included |
| `z3.Optimize()` counterfactual safe SQL patch synthesis & RFC 6962 proofs | Included | Included |
| Dual-solver SMT consensus (`libz3` + pure-Rust `OxiZ`) & Rust `pgwire` proxy | — | Included |
| Multi-cluster HA, PostgreSQL WAL locks & Odoo 18–20 `/doc-bearer/` live sync | — | Included |
| NIST SP 800-38G `AES-256-FF1` FPE & Cedar / Regorus / CEL engines | — | Included |
| Air-gapped Docker + Linux bare-metal KVM Firecracker MicroVM deployment | — | Included |
| SPIFFE SVIDs, C2SP `tlog-tiles` & Monthly CFO Financial Integrity Report | — | Included |

Growth Firewall from **$490/mo** (single-cluster) or **Enterprise Sovereign Enclave** ($2,500/mo / $30,000/yr, starting with a **$3,000–$5,000 30-Day Production Integrity Pilot**, 100% credited to annual): https://apodictic.dev/pricing · `sofianmousa@apodictic.dev`

## Founder & Lineage
Apodictic was founded by **Sofian Mousa**:
- **Mousa Consultancy (Ages 13–15, Feb 2023 – Sep 2025)**: Solo B2B technical consultancy for 26 paying business clients (124,000 EGP / ~$2,500 USD).
- **Rasmi (2.34 million+ Documents)**: Automated tax & statutory compliance software across Egypt ETA and Saudi ZATCA.
- **Apodictic**: Pre-commit formal verification firewall protecting 8 paying production chains.
