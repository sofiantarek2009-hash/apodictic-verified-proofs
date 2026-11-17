# `@apodictic/mcp-verifier`

Drop-in MCP JSON-RPC 2.0 pre-commit firewall & standalone verification server backed by Apodictic (`Z3 5.4.1`, `SYM_*` PII masking, SQLite WAL crash-durable velocity/WORM ledger).

## Usage

### 1. Wrap any existing MCP server (Postgres, Odoo, Stripe)
```bash
npx @apodictic/mcp-verifier wrap -- npx @modelcontextprotocol/server-postgres "$DATABASE_URL"
```

### 2. Run as a standalone MCP server (Claude Desktop / Cursor)
```bash
npx @apodictic/mcp-verifier serve
```
Exposes `apodictic_verify_mutation`, `apodictic_verify_three_way_match`, `apodictic_verify_tax`, `apodictic_rollback`, and `apodictic_audit_status`.
