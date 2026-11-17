# `@apodictic/sdk`

Pre-commit formal verification & Zero-PII symbolic gateway SDK for AI agents writing to PostgreSQL, Odoo, and enterprise ledgers.

## Install

```bash
npm install @apodictic/sdk
```

## Quick Start

```ts
import { SymbolicGateway } from '@apodictic/sdk';

const gw = new SymbolicGateway({
  posture: 'MODE_B_HYBRID',
  endpoint: process.env.APODICTIC_ENDPOINT, // or local Z3 5.4.1 enclave
  forbidRawLiterals: true,
});

// 1. Strip IBANs, tax IDs, emails, and secrets locally before LLM calls
const { sanitized } = gw.scrubSqlAst("PAY iban='DE89370400440532013000' amount=14200");

// 2. Verify proposed SQL/ERP mutation before commit
const verdict = await gw.verifyMutation({
  sql: 'UPDATE vendor_disbursements SET amount=14200 WHERE id=4092;',
  amount: 14200,
  currentBalance: 250000,
  minReserve: 50000,
  maxAutonomousLimit: 50000,
  cfoSigned: true,
});

if (!verdict.verified) throw new Error(`Blocked: ${verdict.reason}`);
await gw.close();
```
