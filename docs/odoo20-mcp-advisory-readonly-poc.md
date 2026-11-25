# Odoo 20 `/json/2/` & MCP Advisory `Readonly` Scope Verification Note & 1-Command Shadow Pilot

**Author:** Apodictic Engineering · Verified across Odoo 20 `/json/2/` + `/doc-bearer/<model>.json`
**Scope:** Multi-branch ERP deployments connecting AI agents to Odoo 20 External JSON-2 API and MCP tool adapters.

---

## 1. Architectural Observation: Advisory `Readonly` Hints vs. Server-Side Enforcement

Odoo 20 replaces legacy XML-RPC endpoints with the JSON-2 External API (`POST /json/2/<model>/<method>`) and machine-readable OpenAPI descriptors (`GET /doc-bearer/<model>.json`) protected by Bearer API keys.

When LLM / MCP adapters connect to Odoo 20:
- Agent tool manifests often advertise a read-only annotation or client-side hint (`bearer_scope: "mcp"`, read-only tool selection) rather than cryptographic capability separation at the database/API key boundary.
- If the underlying Odoo Bearer API key possesses write ACLs (`perm_write`, `perm_create`, `perm_unlink`) in `ir.model.access`, an agent under prompt injection or schema confusion can still invoke mutating JSON-2 methods such as:
  - `POST /json/2/account.move/create` (unbalanced debit/credit lines or fiscal-locked dates)
  - `POST /json/2/account.move/button_draft` or `/unlink` on hashed entries (`inalterable_hash`)
  - `POST /json/2/product.pricelist.item/write` (multi-branch blanket markdowns)
  - `POST /json/2/stock.quant/create` or `/write` (non-conservative cross-branch stock deltas)

Single-row SQL `CHECK` constraints (`debit * credit = 0`) also cannot detect multi-line double-entry imbalances (`SUM(debit) != SUM(credit)`) or multi-warehouse stock conservation breaches across separate requests.

---

## 2. Minimal Reproduction Against `apodictic-mcp-verifier wrap-odoo`

1. Start Odoo (or local staging) on `http://127.0.0.1:8069`.
2. Drop Apodictic in front in **zero-risk Shadow Observation (`observe`) mode**:

```bash
npx @apodictic/mcp-verifier wrap-odoo \
  --upstream http://127.0.0.1:8069 \
  --listen 127.0.0.1:8070 \
  --mode observe \
  --max-discount-pct 15 \
  --max-branches 1 \
  --report-out ./odoo-shadow.jsonl
```

3. Simulate an agent invoking `POST /json/2/account.move/create` using an MCP-scoped caller with unbalanced journal lines:

```bash
curl -s -i -X POST http://127.0.0.1:8070/json/2/account.move/create \
  -H 'Content-Type: application/json' \
  -H 'X-Odoo-Bearer-Scope: mcp' \
  -d '{
    "vals_list": [{
      "line_ids": [
        [0, 0, {"account_code": "121000", "debit": 4820.00, "credit": 0.00}],
        [0, 0, {"account_code": "211000", "debit": 0.00, "credit": 4500.00}]
      ]
    }]
  }'
```

- **In `--mode observe`**: Traffic forwards immediately without production blocking risk, returns `X-Apodictic-Shadow-Verdict: WOULD_BLOCK`, records exact dollar exposure to `odoo-shadow.jsonl`, and exposes a live executive summary at `GET http://127.0.0.1:8070/_apodictic/report`.
- **In `--mode enforce`**: Rejects immediately with **HTTP 403** (`INV_ODOO20_MCP_READONLY_BYPASS` and `INV_DOUBLE_ENTRY_BALANCE`) before a single request reaches Odoo upstream.

---

## 3. PostgreSQL Wire Companion (Zero-Internet Branch Server Rooms)

For self-hosted Odoo installations requiring PostgreSQL-layer `SAVEPOINT` proofs and cross-branch POS `stock_quant` conservation offline:

```bash
apodictic_pg_proxy \
  --listen 127.0.0.1:5433 \
  --upstream 127.0.0.1:5432 \
  --mode observe \
  --savepoint-mode \
  --state-file /var/lib/apodictic/checkpoint.json \
  --audit-wal /var/lib/apodictic/audit.wal

# Generate 7-day CFO/CTO audit summary before switching to --mode enforce:
apodictic_pg_proxy report --audit-wal /var/lib/apodictic/audit.wal --since-days 7 --format markdown
```

All blocked high-value exceptions can optionally require single-use, transaction-digest-bound **Ed25519 CFO capability tokens** (`_apodictic_approval_token`), preventing token replay or post-approval payload tampering.
