# `apodictic_odoo_guard` — Odoo 18–20 Partner App Module

Installable Odoo add-on for Odoo implementation partners deploying Apodictic in front of Odoo 18–20 (`/json/2/` Bearer API, `/doc-bearer/`, MCP `bearer_scope='mcp'`, and JSON-RPC).

## Capabilities
1. **Accounting Settings Panel**: Configure `wrap-odoo` reverse proxy endpoint, start in safe `Shadow Observe` mode (`--mode observe`), enforce advisory `bearer_scope='mcp'` blocking on mutating methods, set autonomous spend caps, and bind CFO HITL webhooks.
2. **1-Click Shadow Exposure Sync**: Queries `GET <proxy_url>/_apodictic/report` inside Odoo Accounting Settings and shows caught exposure in USD before promoting to `Pre-Commit Enforce`.
3. **WORM & HITL Audit Log (`apodictic.audit.event`)**: Ingests signed events at `/apodictic/ingest_event` authenticated by constant-time `X-Apodictic-Signature` HMAC-SHA256 verification.

## Quick Setup
```bash
# 1. Start the Apodictic Odoo 20 reverse proxy in zero-disruption shadow observe mode
npx apodictic-mcp-verifier wrap-odoo \
  --upstream http://127.0.0.1:8069 \
  --listen 127.0.0.1:8070 \
  --mode observe \
  --report-out /var/log/apodictic/odoo-shadow.jsonl

# 2. Export printable CFO/CTO Shadow Audit Report
npx apodictic-mcp-verifier audit-report \
  --input /var/log/apodictic/odoo-shadow.jsonl \
  --format html \
  --out ./odoo-shadow-audit.html
```
