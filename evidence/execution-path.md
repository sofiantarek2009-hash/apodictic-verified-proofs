# Execution Path

1. **Agent / Client** calls `apodictic-sdk` (`SymbolicGateway.verifyMutation`) or `apodictic-mcp-verifier` (`wrap` / `serve`).
2. **Enclave Worker (`enclave_worker.py`)** runs:
   - Structured PII & secret masking (`SYM_*`)
   - SQL AST & destructive-DDL/DML check (`DROP`, `TRUNCATE`, unbounded `DELETE`)
   - Z3 `5.4.1` SMT invariant check (`QF_LRA`: reserve floor, 24h velocity cap, CFO signature, VAT parity)
3. **Persistence & Audit**:
   - Approved writes record 24h velocity in SQLite WAL (`APODICTIC_STATE_DB`) and append to the SHA-256 WORM audit chain.
