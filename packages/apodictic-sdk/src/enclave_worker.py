#!/usr/bin/env python3
"""
Apodictic Persistent Local Enclave Worker
Maintains one stateful session holding:
  - NoesisProxyInterceptor (DeepDlp + SqlAstCompiler + Z3 5.4.1 + MerkleAuditLedger + 24h Velocity)
  - EnterpriseRollbackManager (SQLite SAVEPOINT staging & <38ms atomic reversal)
  - BiTemporalLedger (SQL:2011 orthogonal Valid Time & System Time)
  - ThreeWayMatchZ3Solver & GlobalIndirectTaxSolver (ZATCA / Egypt ETA / EU VAT)
"""
import json
import os
import sqlite3
import sys
import time
import z3

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from noesis_engine.src.proxy.interceptor import NoesisProxyInterceptor
from noesis_engine.src.rollback.coordinator import EnterpriseRollbackManager
from noesis_engine.src.core.bitemporal import BiTemporalLedger
from noesis_engine.src.erp_clearing.three_way_match_solver import (
    ThreeWayMatchZ3Solver,
    PurchaseOrderLine,
    GoodsReceiptLine,
    VendorInvoiceLine,
)
from noesis_engine.src.statutory_theorems.global_indirect_tax_theorems import (
    GlobalIndirectTaxSolver,
    TaxJurisdiction,
    IndirectTaxLineItem,
)


class EnclaveSession:
    def __init__(self, state_db_path: str = ""):
        self.started_at = time.perf_counter()
        self.state_db_path = state_db_path or os.environ.get("APODICTIC_STATE_DB") or os.path.join(
            os.path.expanduser("~"), ".apodictic", "enclave_state.db"
        )
        os.makedirs(os.path.dirname(self.state_db_path), exist_ok=True)
        self.state_conn = sqlite3.connect(self.state_db_path, check_same_thread=False)
        self.state_conn.execute("PRAGMA journal_mode=WAL;")
        self.state_conn.execute(
            "CREATE TABLE IF NOT EXISTS velocity_events (account_id TEXT NOT NULL, amount REAL NOT NULL, ts REAL NOT NULL)"
        )
        self.state_conn.execute(
            "CREATE TABLE IF NOT EXISTS worm_blocks (block_index INTEGER PRIMARY KEY, block_json TEXT NOT NULL)"
        )
        self.state_conn.commit()

        self.proxy = NoesisProxyInterceptor()
        # Hydrate persistent 24h velocity & WORM audit chain from SQLite on startup
        cutoff = time.time() - 86400.0
        for acct, amt in self.state_conn.execute(
            "SELECT account_id, amount FROM velocity_events WHERE ts >= ?", (cutoff,)
        ).fetchall():
            self.proxy._account_velocity.setdefault(acct, []).append(float(amt))

        saved_blocks = [
            json.loads(row[0])
            for row in self.state_conn.execute("SELECT block_json FROM worm_blocks ORDER BY block_index ASC").fetchall()
        ]
        if saved_blocks:
            self.proxy.audit.blocks = saved_blocks

        self.rollback_mgr = EnterpriseRollbackManager()
        self.rollback_mgr.seed_account("sdk_default", "Primary Operating Account", 250000.0, 50000.0)
        self.bitemporal = BiTemporalLedger("enterprise_gl")
        self.three_way = ThreeWayMatchZ3Solver()
        self.tax_solver = GlobalIndirectTaxSolver()

    def _persist_last_block(self):
        if self.proxy.audit.blocks:
            blk = self.proxy.audit.blocks[-1]
            self.state_conn.execute(
                "INSERT OR REPLACE INTO worm_blocks (block_index, block_json) VALUES (?, ?)",
                (blk["block_index"], json.dumps(blk, sort_keys=True)),
            )
            self.state_conn.commit()

    def handle(self, method: str, params: dict) -> dict:
        if method == "health":
            return {
                "status": "healthy",
                "z3_version": z3.get_version_string(),
                "uptime_ms": round((time.perf_counter() - self.started_at) * 1000.0, 2),
                "worm_blocks": len(self.proxy.audit.blocks),
                "worm_integrity_valid": self.proxy.audit.verify_integrity(),
                "velocity_accounts": len(self.proxy._account_velocity),
                "bitemporal_records": len(self.bitemporal.records),
            }

        if method == "verify_mutation":
            acct = str(params.get("accountId", "sdk_default"))
            curr_bal = float(params.get("currentBalance", 250000.0))
            min_res = float(params.get("minReserve", 50000.0))
            amt = params.get("amount")
            amt_val = float(amt) if amt is not None else None
            if amt_val is not None and (amt_val < 0 or amt_val != amt_val):
                raise ValueError("Invalid negative or NaN amount")

            res = self.proxy.intercept_and_execute(
                raw_statement=str(params.get("sql", "")),
                account_id=acct,
                current_balance=curr_bal,
                min_reserve=min_res,
                spending_limit=float(params.get("maxAutonomousLimit", 50000.0)),
                cfo_signed=bool(params.get("cfoSigned", False)),
                statutory_vat=float(params.get("statutoryVat", 0.14)),
                expected_vat=float(params.get("expectedVat", 0.14)),
                amount=amt_val,
            )

            if res["verified"] and amt_val and amt_val > 0:
                self.state_conn.execute(
                    "INSERT INTO velocity_events (account_id, amount, ts) VALUES (?, ?, ?)",
                    (acct, amt_val, time.time()),
                )
                self.state_conn.commit()
            self._persist_last_block()

            batch_id = None
            if res["verified"]:
                if self.rollback_mgr.get_account_balance(acct) is None:
                    self.rollback_mgr.seed_account(acct, f"Account {acct}", curr_bal, min_res)
                batch_id = f"batch_{int(time.time() * 1000)}_{res['block_index']}"
                self.rollback_mgr.stage_atomic_transaction(
                    batch_id=batch_id,
                    account_id=acct,
                    amount=amt_val or 0.0,
                    target_system=str(params.get("targetSystem", "postgresql")),
                    action=res["ast_analysis"]["statement_type"],
                )
            res["rollback_batch_id"] = batch_id
            return res

        if method == "rollback":
            batch_id = str(params.get("batchId", ""))
            if not batch_id:
                raise ValueError("batchId is required")
            rb = self.rollback_mgr.rollback_batch(batch_id)
            rb_ok = rb.get("actions_compensated", 0) > 0
            blk = self.proxy.audit.append_block(
                proof_id=f"rb_{batch_id}",
                action="ATOMIC_ROLLBACK",
                verdict="REVERTED" if rb_ok else "NOOP",
                target_system="POSTGRESQL",
                zk_digest=self.proxy.audit.blocks[-1]["block_hash"] if self.proxy.audit.blocks else self.proxy.audit._genesis_hash,
                metadata={"batch_id": batch_id},
            )
            self._persist_last_block()
            return {**rb, "success": rb_ok, "audit_block_index": blk["block_index"], "audit_block_hash": blk["block_hash"]}

        if method == "verify_three_way_match":
            po_raw = params["po"]
            po = PurchaseOrderLine(
                po_id=str(po_raw["poId"]),
                sku=str(po_raw["sku"]),
                ordered_qty=float(po_raw["orderedQty"]),
                unit_price=float(po_raw["unitPrice"]),
            )
            receipts = [
                GoodsReceiptLine(
                    receipt_id=str(r["receiptId"]),
                    po_id=str(r["poId"]),
                    sku=str(r["sku"]),
                    received_qty=float(r["receivedQty"]),
                )
                for r in params.get("receipts", [])
            ]
            invoices = [
                VendorInvoiceLine(
                    invoice_id=str(i["invoiceId"]),
                    po_id=str(i["poId"]),
                    sku=str(i["sku"]),
                    billed_qty=float(i["billedQty"]),
                    billed_unit_price=float(i["billedUnitPrice"]),
                )
                for i in params.get("invoices", [])
            ]
            solver = ThreeWayMatchZ3Solver(price_tolerance_pct=float(params.get("priceTolerancePct", 0.02)))
            r = solver.verify_three_way_match(po, receipts, invoices)
            return {
                "matched": r.matched,
                "verdict": r.verdict,
                "sku": r.sku,
                "po_qty": r.po_qty,
                "received_qty": r.received_qty,
                "billed_qty": r.billed_qty,
                "price_variance_pct": r.price_variance_pct,
                "violated_rules": r.violated_rules,
                "z3_solve_ms": r.z3_solve_ms,
            }

        if method == "verify_tax_compliance":
            jur = TaxJurisdiction(str(params["jurisdiction"]))
            lines = [
                IndirectTaxLineItem(
                    sku=str(x["sku"]),
                    net_amount=float(x["netAmount"]),
                    claimed_vat_amount=float(x["claimedVatAmount"]),
                    claimed_wht_amount=float(x.get("claimedWhtAmount", 0.0)),
                    is_exempt=bool(x.get("isExempt", False)),
                )
                for x in params.get("lines", [])
            ]
            r = self.tax_solver.verify_invoice_taxes(
                jurisdiction=jur,
                lines=lines,
                has_cryptographic_stamp=bool(params.get("hasCryptographicStamp", True)),
                tolerance=float(params.get("tolerance", 0.02)),
            )
            return {
                "jurisdiction": r.jurisdiction.value,
                "verdict": r.verdict,
                "verified": r.verified,
                "expected_total_vat": r.expected_total_vat,
                "claimed_total_vat": r.claimed_total_vat,
                "violated_tax_laws": r.violated_tax_laws,
                "z3_solve_ms": r.z3_solve_ms,
                "proof_hash": r.proof_hash,
            }

        if method == "bitemporal_insert":
            rec = self.bitemporal.insert_fact(
                entity_id=str(params["entityId"]),
                data=dict(params["data"]),
                valid_start=int(params["validStart"]),
                valid_end=int(params.get("validEnd", -1)),
                system_time=int(params["systemTime"]) if params.get("systemTime") is not None else None,
            )
            return {"inserted": True, "entity_id": rec.entity_id, "valid_start": rec.valid_start, "system_start": rec.system_start}

        if method == "bitemporal_restate":
            rec = self.bitemporal.retroactive_restatement(
                entity_id=str(params["entityId"]),
                new_data=dict(params["data"]),
                effective_valid_start=int(params["validStart"]),
                effective_valid_end=int(params.get("validEnd", -1)),
                adjustment_system_time=int(params["systemTime"]) if params.get("systemTime") is not None else None,
            )
            return {"restated": True, "entity_id": rec.entity_id, "valid_start": rec.valid_start, "system_start": rec.system_start}

        if method == "bitemporal_as_of":
            snap = self.bitemporal.as_of(
                entity_id=str(params["entityId"]),
                valid_time=int(params["validTime"]),
                system_time=int(params["systemTime"]),
            )
            return {"found": snap is not None, "data": snap}

        if method == "verify_audit_chain":
            valid = self.proxy.audit.verify_integrity()
            tip = self.proxy.audit.blocks[-1]["block_hash"] if self.proxy.audit.blocks else self.proxy.audit._genesis_hash
            return {"valid": valid, "block_count": len(self.proxy.audit.blocks), "tip_hash": tip}

        raise ValueError(f"Unknown enclave method: {method}")


def main():
    session = EnclaveSession()
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        req_id = None
        try:
            req = json.loads(line)
            req_id = req.get("id")
            result = session.handle(req.get("method", ""), req.get("params") or {})
            sys.stdout.write(json.dumps({"id": req_id, "result": result}) + "\n")
            sys.stdout.flush()
        except Exception as exc:
            sys.stdout.write(json.dumps({"id": req_id, "error": {"message": str(exc)}}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
