# Odoo 19/20 JSON-2 & MCP Agentic ERP Firewall

> **Market Insight**: Odoo 19 and Odoo 20 fundamentally break legacy ERP agent integrations—deprecating XML-RPC and `/jsonrpc`, removing the remote `db` RPC service, replacing stored chatter field tracking values, and introducing scoped `bearer_scope='mcp'|'rpc'` API keys alongside OpenAPI `/doc-bearer/<model>.json` schema introspection.  
> **Apodictic** is the deterministic pre-execution firewall for autonomous AI/MCP agents operating on Odoo 19/20 `/json/2/`.

---

## Why Odoo 19/20 Needs a Formal Pre-Commit Firewall

1. **Deprecation of XML-RPC / `/jsonrpc` & Removal of `db` RPC Service**:
   - Legacy connectors calling `/xmlrpc/2/` or `/jsonrpc` with `service="db"` fail or expose stale attack surfaces. Odoo 19/20 standardizes on `POST /json/2/<model>/<method>` with `Authorization: Bearer <token>` and `X-Odoo-Database: <db>`.
   - Apodictic blocks removed `db` RPC calls (`ODOO20_REMOVED_DB_RPC_BLOCKED`) and enforces Bearer + `X-Odoo-Database` routing.

2. **Mandatory `bearer_scope='mcp'` vs `'rpc'` Least-Privilege Gate**:
   - Even with an `mcp`-scoped token, an agent prompted via indirect injection may try to call `account.move/unlink`, `button_draft`, `res.company/write` (weakening `hard_lock_date`), or `ir.rule` / `ir.model.access` mutations.
   - Apodictic evaluates scope + model + method in Z3 before any HTTP call leaves the gateway, blocking un-countersigned escalations with `INV_ODOO20_MCP_SCOPE_ESCALATION` (`UNSAT`).

3. **Removal of Stored Chatter Tracking Values -> SEC 17a-4 `field_diff` WORM Vault**:
   - Because Odoo 20 removes automatic stored chatter tracking values on model fields, an autonomous write can silently alter accounting metadata without an audit diff.
   - Apodictic reads the pre-mutation record, constructs an immutable `before -> proposed` `field_diff` snapshot, and seals it into an SEC 17a-4 SHA-256 hash chain.

4. **Live `/doc-bearer/<model>.json` OpenAPI Schema & X2many Tuple Validation**:
   - LLMs frequently hallucinate non-existent Odoo fields or invalid X2many relational command tuples (valid command codes are strictly `0..6`).
   - Apodictic introspects `GET /doc-bearer/account.move.json` at pre-flight, blocking unknown fields (`ODOO20_SCHEMA_UNKNOWN_FIELD`) and invalid tuples (`ODOO_INVALID_X2M_COMMAND`) before touching Odoo.

5. **`hard_lock_date`, `inalterable_hash`, and Multi-Row `account.move.line` Z3 Proofs**:
   - **Period & Hash Immutability**: Rejects backdated entries (`date <= hard_lock_date` -> `INV_ODOO_FISCAL_LOCK_VIOLATION`) and mutations to sealed entries (`inalterable_hash != null` -> `INV_ODOO_INALTERABLE_HASH_IMMUTABLE`), synthesizing non-destructive `account.move.reversal` credit notes instead.
   - **Multi-Row Accounting & Analytic Conservation (Z3 `5.4.1`)**: Proves integer-cent `Sum(debit_cents) == Sum(credit_cents)` (`INV_ODOO_DOUBLE_ENTRY_BALANCE`), debit/credit mutual exclusion per row (`INV_ODOO_LINE_DEBIT_CREDIT_MUTEX`), `analytic_distribution` weight sum `== 100.00%` (`INV_ODOO_ANALYTIC_DISTRIBUTION_100PCT`), and foreign-currency `amount_currency` sign parity with functional-currency `balance` (`INV_ODOO_MULTICURRENCY_SIGN_PARITY`).

---

## Reproduce Live Locally (Zero External Containers Required)

```bash
pip install z3-solver
python3 02-LIVE-ODOO20-JSON2-MCP-PROOF.py
```
