# `apodictic-sdk`

Pre-commit formal verification & Zero-PII symbolic gateway SDK for AI agents writing to PostgreSQL, Odoo 18–20 (`/json/2/` Bearer API & `/jsonrpc`), Stripe, and enterprise ledgers.

Runs **100% locally with zero Python required** via bundled Microsoft **Z3 5.4.1 WebAssembly** (`z3-solver`), **WASM PostgreSQL 17** (`@electric-sql/pglite`), and SQLite WAL persistence — or seamlessly delegates to Python Z3 5.4.1 (`engine: 'auto'`), the native Rust kernel (`engine: 'rust'`), or HTTPS (`/api/v1/enclave`).

## Install

```bash
npm install apodictic-sdk
```

## Quick Start

```ts
import { SymbolicGateway } from 'apodictic-sdk';

const gw = new SymbolicGateway({
  posture: 'MODE_B_HYBRID', // or MODE_A_AIRGAP with { airgap: true }
  engine: 'auto',           // 'auto' | 'wasm' | 'python' | 'rust'
  endpoint: process.env.APODICTIC_ENDPOINT, // optional remote /api/v1/enclave URL
  forbidRawLiterals: true,
});

// 1. Strip spaced/hyphenated IBANs, Luhn PANs, tax IDs, emails, and secrets locally before LLM calls
const { sanitized } = gw.scrubSqlAst("PAY iban='DE89 3704 0044 0532 0130 00' amount=14200");

// 2. Verify proposed SQL mutation before commit (verifySql or verifyMutation)
const verdict = await gw.verifySql('UPDATE invoices SET total = 100 WHERE id = 1;', {
  amount: 100,
  currentBalance: 250000,
  minReserve: 50000,
  maxAutonomousLimit: 50000,
  cfoSigned: true,
});

if (!verdict.verified) throw new Error(`Blocked: ${verdict.reason}`);

// 3. Shadow-execute inside WASM Postgres 17 (ROLLBACK unconditionally) + Z3 proof
const shadow = await gw.shadowExecuteAndProve({
  sql: "UPDATE accounts SET balance = balance - 12500 WHERE id = 'acc_treasury';",
  accountId: 'acc_treasury',
});

// 4. Verify Odoo 19/20 JSON-2 & MCP scope invariants
const odooCheck = await gw.verifyMutation({
  sql: 'POST /json/2/account.move/button_draft',
  odoo: {
    model: 'account.move',
    method: 'button_draft',
    bearerScope: 'mcp',
    moveDate: '2026-09-01',
    hardLockDate: '2026-09-30',
    inalterableHash: '9f86d081884c7d65',
  },
});

await gw.close();
```
