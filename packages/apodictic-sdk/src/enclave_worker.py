#!/usr/bin/env python3
"""
Apodictic Persistent Local Enclave Worker
Maintains one stateful session holding either the full monorepo kernel (`apodictic_engine`)
or the bundled standalone Z3 5.4.1 enclave (`standalone_z3_enclave.py`) when installed via npm.
All velocity windows, WORM SHA-256 blocks, staged rollback batches, and bi-temporal records
are persisted to SQLite WAL (`APODICTIC_STATE_DB`) across restarts.
"""
import hashlib
import json
import os
import sqlite3
import sys
import time
import uuid

try:
    import z3
except ImportError:
    msg = (
        "Python z3-solver not found. Install with: pip install z3-solver, "
        "or pass --endpoint https://www.apodictic.dev/api/v1/enclave"
    )
    sys.stderr.write(json.dumps({"error": msg}) + "\n")
    sys.stderr.flush()
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

REPO_ROOT = os.environ.get("APODICTIC_REPO_ROOT") or os.path.abspath(os.path.join(HERE, "..", "..", ".."))
USE_MONOREPO = os.path.exists(os.path.join(REPO_ROOT, "apodictic_engine", "src", "proxy", "interceptor.py"))
if USE_MONOREPO and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

if USE_MONOREPO:
    from apodictic_engine.src.proxy.interceptor import ApodicticProxyInterceptor
    from apodictic_engine.src.core.bitemporal import BiTemporalLedger
    from apodictic_engine.src.audit_ledger.merkle_sealer import rfc6962_leaf_hash
    from apodictic_engine.src.smt_theory.policy_compiler import ApodicticPolicyZ3Compiler, DEFAULT_ENTERPRISE_POLICY
    from apodictic_engine.src.erp_clearing.three_way_match_solver import (
        ThreeWayMatchZ3Solver,
        PurchaseOrderLine,
        GoodsReceiptLine,
        VendorInvoiceLine,
    )
    from apodictic_engine.src.statutory_theorems.global_indirect_tax_theorems import (
        GlobalIndirectTaxSolver,
        TaxJurisdiction,
        IndirectTaxLineItem,
    )
else:
    from standalone_z3_enclave import StandaloneEnclaveSession


class MonorepoEnclaveSession:
    def __init__(self, state_db_path: str = ""):
        self.started_at = time.perf_counter()
        self.state_db_path = state_db_path or os.environ.get("APODICTIC_STATE_DB") or os.path.join(
            os.path.expanduser("~"), ".apodictic", "enclave_state.db"
        )
        os.makedirs(os.path.dirname(self.state_db_path), exist_ok=True)
        self.state_conn = sqlite3.connect(self.state_db_path, check_same_thread=False, timeout=5.0)
        self.state_conn.row_factory = sqlite3.Row
        self.state_conn.execute("PRAGMA journal_mode=WAL;")
        self.state_conn.execute("PRAGMA busy_timeout=5000;")
        self.state_conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS velocity_events (
                account_id TEXT NOT NULL,
                amount REAL NOT NULL,
                ts REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS worm_blocks (
                block_index INTEGER PRIMARY KEY,
                block_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger_accounts (
                account_id TEXT PRIMARY KEY,
                balance REAL NOT NULL,
                min_reserve REAL NOT NULL DEFAULT 0.0,
                debits_pending REAL NOT NULL DEFAULT 0.0,
                debits_posted REAL NOT NULL DEFAULT 0.0,
                credits_posted REAL NOT NULL DEFAULT 0.0
            );
            CREATE TABLE IF NOT EXISTS wal_tuple_journal (
                tuple_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                lsn TEXT NOT NULL,
                table_name TEXT NOT NULL,
                before_image_json TEXT NOT NULL,
                after_image_json TEXT NOT NULL,
                restored INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rollback_batches (
                batch_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL,
                amount REAL NOT NULL,
                target_system TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                rolled_back_at REAL
            );
            """
        )
        for col in ("debits_pending", "debits_posted", "credits_posted"):
            try:
                self.state_conn.execute(f"ALTER TABLE ledger_accounts ADD COLUMN {col} REAL NOT NULL DEFAULT 0.0")
            except sqlite3.OperationalError:
                pass
        self.state_conn.execute(
            "INSERT OR IGNORE INTO ledger_accounts (account_id, balance, min_reserve, debits_pending, debits_posted, credits_posted) VALUES (?, ?, ?, 0.0, 0.0, ?)",
            ("sdk_default", 250000.0, 50000.0, 250000.0),
        )
        self.state_conn.execute(
            "UPDATE ledger_accounts SET credits_posted = balance WHERE credits_posted = 0.0 AND debits_pending = 0.0 AND debits_posted = 0.0 AND balance > 0.0"
        )
        self.state_conn.commit()

        self.pg_dsn = os.environ.get("APODICTIC_POSTGRES_URL", "")
        self.pg_conn = None
        if self.pg_dsn and os.environ.get("APODICTIC_AIRGAP") != "1":
            import psycopg
            self.pg_conn = psycopg.connect(self.pg_dsn, autocommit=True)
            with self.pg_conn.cursor() as cur:
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS apodictic_velocity_events (account_id TEXT NOT NULL, amount DOUBLE PRECISION NOT NULL, ts DOUBLE PRECISION NOT NULL)"
                )

        self.proxy = ApodicticProxyInterceptor()
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
            self.proxy.audit._leaf_hashes = [
                rfc6962_leaf_hash(str(b.get("block_hash", "")).encode("utf-8"))
                for b in saved_blocks
            ]

        self.bitemporal = BiTemporalLedger("enterprise_gl")
        self.three_way = ThreeWayMatchZ3Solver()
        self.tax_solver = GlobalIndirectTaxSolver()

    def _get_double_entry_account(self, account_id: str) -> dict:
        row = self.state_conn.execute("SELECT * FROM ledger_accounts WHERE account_id = ?", (account_id,)).fetchone()
        if not row:
            return {
                "account_id": account_id,
                "balance": 0.0,
                "min_reserve": 0.0,
                "debits_pending": 0.0,
                "debits_posted": 0.0,
                "credits_posted": 0.0,
                "available_balance": 0.0,
            }
        credits_posted = float(row["credits_posted"])
        debits_posted = float(row["debits_posted"])
        debits_pending = float(row["debits_pending"])
        return {
            "account_id": row["account_id"],
            "balance": round(float(row["balance"]), 4),
            "min_reserve": round(float(row["min_reserve"]), 4),
            "debits_pending": round(debits_pending, 4),
            "debits_posted": round(debits_posted, 4),
            "credits_posted": round(credits_posted, 4),
            "available_balance": round(credits_posted - debits_posted - debits_pending, 4),
        }

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
                "mode": "monorepo-kernel",
                "z3_version": z3.get_version_string(),
                "uptime_ms": round((time.perf_counter() - self.started_at) * 1000.0, 2),
                "worm_blocks": len(self.proxy.audit.blocks),
                "worm_integrity_valid": self.proxy.audit.verify_integrity(),
                "velocity_accounts": len(self.proxy._account_velocity),
                "bitemporal_records": len(self.bitemporal.records),
                "airgap": os.environ.get("APODICTIC_AIRGAP") == "1",
            }

        if method == "verify_mutation":
            acct = str(params.get("accountId", "sdk_default"))
            has_explicit_bal = bool(params.get("hasExplicitCurrentBalance", "currentBalance" in params and params.get("currentBalance") is not None))
            existing_acct_row = self.state_conn.execute(
                "SELECT balance, min_reserve FROM ledger_accounts WHERE account_id = ?",
                (acct,),
            ).fetchone()
            use_persisted_bal = existing_acct_row is not None and not has_explicit_bal and not bool(params.get("stateless", False))
            curr_bal = float(existing_acct_row["balance"]) if use_persisted_bal else float(params.get("currentBalance", 250000.0))
            min_res = float(existing_acct_row["min_reserve"]) if use_persisted_bal else float(params.get("minReserve", 50000.0))
            amt = params.get("amount")
            amt_val = float(amt) if amt is not None else None
            if amt_val is not None and (amt_val < 0 or amt_val != amt_val):
                raise ValueError("Invalid negative or NaN amount")

            debit_total_raw = params.get("debitTotal")
            credit_total_raw = params.get("creditTotal")
            de_unsat_reason = None
            de_z3_ms = 0.0
            if debit_total_raw is not None and credit_total_raw is not None:
                debit_total = float(debit_total_raw)
                credit_total = float(credit_total_raw)
                de_t0 = time.perf_counter()
                de_ctx = z3.Context()
                de_solver = z3.Solver(ctx=de_ctx)
                de_solver.set("timeout", 5000)
                z_debit = z3.Real("debit_total", ctx=de_ctx)
                z_credit = z3.Real("credit_total", ctx=de_ctx)
                z_tol = z3.RealVal("0.005", ctx=de_ctx)
                de_solver.add(z_debit == z3.RealVal(str(debit_total), ctx=de_ctx))
                de_solver.add(z_credit == z3.RealVal(str(credit_total), ctx=de_ctx))
                de_solver.assert_and_track(
                    z3.And(z_debit - z_credit <= z_tol, z_credit - z_debit <= z_tol),
                    "INV_DOUBLE_ENTRY_BALANCE",
                )
                de_chk = de_solver.check()
                de_z3_ms = (time.perf_counter() - de_t0) * 1000.0
                if de_chk != z3.sat:
                    de_unsat_reason = (
                        f"INV_DOUBLE_ENTRY_BALANCE: sum(debit)={debit_total:.2f} != "
                        f"sum(credit)={credit_total:.2f} (drift=${abs(debit_total - credit_total):.2f})"
                    )

            live_pg_lock = bool(params.get("livePostgresLock")) or os.environ.get("APODICTIC_LIVE_PG_LOCK") == "1"
            locked_pg_row = False
            pg_tx_open = False

            try:
                if self.pg_conn is not None:
                    cutoff = time.time() - 86400.0
                    with self.pg_conn.cursor() as cur:
                        if live_pg_lock:
                            cur.execute("BEGIN")
                            pg_tx_open = True
                            cur.execute(
                                "SELECT balance, min_reserve FROM ledger_accounts WHERE account_id = %s FOR UPDATE",
                                (acct,),
                            )
                            pg_row = cur.fetchone()
                            if pg_row is not None:
                                curr_bal = float(pg_row[0])
                                min_res = float(pg_row[1]) if pg_row[1] is not None else min_res
                                locked_pg_row = True
                        cur.execute(
                            "SELECT COALESCE(SUM(amount), 0) FROM apodictic_velocity_events WHERE account_id = %s AND ts >= %s",
                            (acct, cutoff),
                        )
                        shared_sum = float(cur.fetchone()[0])
                    self.proxy._account_velocity[acct] = [shared_sum] if shared_sum > 0 else []

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
                if de_unsat_reason is not None:
                    res["verified"] = False
                    res["verdict"] = "UNSAT"
                    core = list(res.get("unsat_core") or [])
                    if "INV_DOUBLE_ENTRY_BALANCE" not in core:
                        core.insert(0, "INV_DOUBLE_ENTRY_BALANCE")
                    res["unsat_core"] = core
                    viols = list(res.get("violated_invariants") or [])
                    if "INV_DOUBLE_ENTRY_BALANCE" not in viols:
                        viols.insert(0, "INV_DOUBLE_ENTRY_BALANCE")
                    res["violated_invariants"] = viols
                    res["violation_reason"] = de_unsat_reason
                    if isinstance(res.get("timings"), dict):
                        res["timings"]["z3_solve_ms"] = round(float(res["timings"].get("z3_solve_ms", 0.0)) + de_z3_ms, 3)

                eff_amt = amt_val if amt_val is not None else float(res.get("extracted_amount") or res.get("amount") or 0.0)
                if res["verified"] and eff_amt > 0:
                    now_ts = time.time()
                    self.state_conn.execute(
                        "INSERT INTO velocity_events (account_id, amount, ts) VALUES (?, ?, ?)",
                        (acct, eff_amt, now_ts),
                    )
                    if self.pg_conn is not None:
                        with self.pg_conn.cursor() as cur:
                            if locked_pg_row:
                                cur.execute(
                                    "UPDATE ledger_accounts SET balance = balance - %s WHERE account_id = %s",
                                    (eff_amt, acct),
                                )
                            cur.execute(
                                "INSERT INTO apodictic_velocity_events (account_id, amount, ts) VALUES (%s, %s, %s)",
                                (acct, eff_amt, now_ts),
                            )
                if pg_tx_open and self.pg_conn is not None:
                    with self.pg_conn.cursor() as cur:
                        cur.execute("COMMIT" if res["verified"] else "ROLLBACK")
                    pg_tx_open = False
                res["live_pg_locked"] = locked_pg_row
                res["authoritative_balance"] = curr_bal
            except Exception:
                if pg_tx_open and self.pg_conn is not None:
                    try:
                        with self.pg_conn.cursor() as cur:
                            cur.execute("ROLLBACK")
                    except Exception:
                        pass
                raise
            self._persist_last_block()

            raw_sql_upper = str(params.get("sql", "")).upper()
            target_sys_raw = str(params.get("targetSystem", "postgresql")).lower()
            is_ext_escrow = any(k in target_sys_raw for k in ("stripe", "wire", "iso20022", "netsuite")) or any(
                k in raw_sql_upper for k in ("WIRE", "PAYOUT", "STRIPE", "ISO20022")
            )
            res["escrow_status"] = (
                ("ESCROW_HELD" if is_ext_escrow else "SAVEPOINT_STAGED")
                if res["verified"]
                else "VETOED_PRE_COMMIT"
            )
            batch_id = None
            wal_before_image = None
            if res["verified"]:
                self.state_conn.execute(
                    "INSERT OR IGNORE INTO ledger_accounts (account_id, balance, min_reserve, debits_pending, debits_posted, credits_posted) VALUES (?, ?, ?, 0.0, 0.0, ?)",
                    (acct, curr_bal, min_res, curr_bal),
                )
                wal_before_image = self._get_double_entry_account(acct)
                if is_ext_escrow:
                    self.state_conn.execute(
                        "UPDATE ledger_accounts SET balance = balance - ?, debits_pending = debits_pending + ? WHERE account_id = ?",
                        (eff_amt, eff_amt, acct),
                    )
                else:
                    self.state_conn.execute(
                        "UPDATE ledger_accounts SET balance = balance - ?, debits_posted = debits_posted + ? WHERE account_id = ?",
                        (eff_amt, eff_amt, acct),
                    )
                wal_after_image = self._get_double_entry_account(acct)
                batch_id = f"batch_{int(time.time() * 1000)}_{res['block_index']}"
                lsn = f"0/{int(time.time_ns()) & 0xFFFFFFFF:08X}"
                tbl_list = res.get("ast_analysis", {}).get("target_tables") or []
                self.state_conn.execute(
                    "INSERT INTO wal_tuple_journal (tuple_id, batch_id, lsn, table_name, before_image_json, after_image_json, restored, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                    (
                        f"wal_{uuid.uuid4().hex[:12]}",
                        batch_id,
                        lsn,
                        str(tbl_list[0]) if tbl_list else "ledger_accounts",
                        json.dumps(wal_before_image),
                        json.dumps(wal_after_image),
                        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    ),
                )
                self.state_conn.execute(
                    "INSERT INTO rollback_batches (batch_id, account_id, amount, target_system, action, status, created_at) VALUES (?, ?, ?, ?, ?, 'STAGED', ?)",
                    (batch_id, acct, eff_amt, target_sys_raw, res["ast_analysis"]["statement_type"], time.time()),
                )
                self.state_conn.commit()
            res["rollback_batch_id"] = batch_id
            res["double_entry_account"] = self._get_double_entry_account(acct) if res["verified"] else None
            res["wal_before_image"] = wal_before_image
            if self.proxy.audit.blocks:
                res["rfc6962_leaf_hash"] = self.proxy.audit.blocks[-1].get("rfc6962_leaf_hash")
                res["rfc6962_tree_root"] = self.proxy.audit.blocks[-1].get("rfc6962_tree_root")
            return res

        if method == "rollback":
            t0 = time.perf_counter()
            batch_id = str(params.get("batchId", ""))
            if not batch_id:
                raise ValueError("batchId is required")
            row = self.state_conn.execute("SELECT * FROM rollback_batches WHERE batch_id = ?", (batch_id,)).fetchone()
            compensated = []
            escrow_res = "NOOP"
            restored_tuple = None
            double_entry_acct = None
            if row and row["status"] == "STAGED":
                ts_low = str(row["target_system"] or "").lower()
                is_esc = any(k in ts_low for k in ("stripe", "wire", "iso20022", "netsuite"))
                if is_esc:
                    self.state_conn.execute(
                        "UPDATE ledger_accounts SET balance = balance + ?, debits_pending = MAX(0.0, debits_pending - ?) WHERE account_id = ?",
                        (row["amount"], row["amount"], row["account_id"]),
                    )
                else:
                    self.state_conn.execute(
                        "UPDATE ledger_accounts SET balance = balance + ?, debits_posted = MAX(0.0, debits_posted - ?) WHERE account_id = ?",
                        (row["amount"], row["amount"], row["account_id"]),
                    )
                self.state_conn.execute(
                    "UPDATE rollback_batches SET status = 'ROLLED_BACK', rolled_back_at = ? WHERE batch_id = ?",
                    (time.time(), batch_id),
                )
                wal_row = self.state_conn.execute(
                    "SELECT before_image_json, lsn, table_name FROM wal_tuple_journal WHERE batch_id = ?",
                    (batch_id,),
                ).fetchone()
                if wal_row:
                    self.state_conn.execute("UPDATE wal_tuple_journal SET restored = 1 WHERE batch_id = ?", (batch_id,))
                    restored_tuple = {
                        "lsn": wal_row["lsn"],
                        "table_name": wal_row["table_name"],
                        "restored_before_image": json.loads(wal_row["before_image_json"]),
                    }
                self.state_conn.commit()
                double_entry_acct = self._get_double_entry_account(row["account_id"])
                escrow_res = "ESCROW_CANCELLED_PRE_DISPATCH" if is_esc else "SAVEPOINT_ROLLED_BACK"
                compensated.append({
                    "batch_id": batch_id,
                    "system": row["target_system"],
                    "amount_restored": row["amount"],
                    "status": "COMPENSATED",
                    "escrow_status": escrow_res,
                    "pgoutput_restored_tuple": restored_tuple,
                    "double_entry_account": double_entry_acct,
                })
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            rb_ok = len(compensated) > 0
            blk = self.proxy.audit.append_block(
                proof_id=f"rb_{batch_id}",
                action="ATOMIC_ROLLBACK",
                verdict="REVERTED" if rb_ok else "NOOP",
                target_system="POSTGRESQL",
                zk_digest=self.proxy.audit.blocks[-1]["block_hash"] if self.proxy.audit.blocks else self.proxy.audit._genesis_hash,
                metadata={"batch_id": batch_id, "escrow_status": escrow_res},
            )
            self._persist_last_block()
            return {
                "batch_id": batch_id,
                "success": rb_ok,
                "actions_compensated": len(compensated),
                "escrow_status": escrow_res,
                "total_dispatch_ms": elapsed_ms,
                "sla_met": elapsed_ms < 38.0,
                "compensated_steps": compensated,
                "pgoutput_restored_tuple": restored_tuple,
                "double_entry_account": double_entry_acct,
                "audit_block_index": blk["block_index"],
                "audit_block_hash": blk["block_hash"],
                "rfc6962_leaf_hash": blk.get("rfc6962_leaf_hash"),
                "rfc6962_tree_root": blk.get("rfc6962_tree_root"),
            }

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

        if method == "flush_escrow":
            t0 = time.perf_counter()
            cooling_sec = float(params.get("coolingWindowSec", 0.0))
            batch_id = str(params.get("batchId", "")).strip()
            cutoff = time.time() - max(0.0, cooling_sec)
            if batch_id:
                rows = self.state_conn.execute(
                    "SELECT * FROM rollback_batches WHERE batch_id = ? AND status = 'STAGED'",
                    (batch_id,),
                ).fetchall()
            else:
                rows = self.state_conn.execute(
                    "SELECT * FROM rollback_batches WHERE status = 'STAGED' AND created_at <= ? ORDER BY created_at ASC",
                    (cutoff,),
                ).fetchall()
            dispatched = []
            now = time.time()
            for row in rows:
                ts_low = str(row["target_system"] or "").lower()
                if not any(k in ts_low for k in ("stripe", "wire", "iso20022", "netsuite")) and not batch_id:
                    continue
                b_id = row["batch_id"]
                self.state_conn.execute(
                    "UPDATE ledger_accounts SET debits_pending = MAX(0.0, debits_pending - ?), debits_posted = debits_posted + ? WHERE account_id = ?",
                    (row["amount"], row["amount"], row["account_id"]),
                )
                self.state_conn.execute(
                    "UPDATE rollback_batches SET status = 'DISPATCHED_TO_RAIL', rolled_back_at = ? WHERE batch_id = ?",
                    (now, b_id),
                )
                rail_ref = f"iso20022_pain001_{b_id}" if ("wire" in ts_low or "iso20022" in ts_low) else f"po_stripe_{b_id}"
                dispatched.append({
                    "batch_id": b_id,
                    "account_id": row["account_id"],
                    "amount": row["amount"],
                    "target_system": row["target_system"],
                    "escrow_status": "DISPATCHED_TO_RAIL",
                    "settlement_reference": rail_ref,
                    "double_entry_account": self._get_double_entry_account(row["account_id"]),
                })
            self.state_conn.commit()
            blk = self.proxy.audit.append_block(
                proof_id=f"escrow_flush_{int(now * 1000)}",
                action="ESCROW_OUTBOX_SETTLEMENT_FLUSH",
                verdict="DISPATCHED" if dispatched else "NOOP",
                target_system="ESCROW_RAIL",
                zk_digest=self.proxy.audit.blocks[-1]["block_hash"] if self.proxy.audit.blocks else self.proxy.audit._genesis_hash,
                metadata={"flushed_count": len(dispatched)},
            )
            self._persist_last_block()
            return {
                "flushed_count": len(dispatched),
                "dispatched": dispatched,
                "escrow_status": "DISPATCHED_TO_RAIL" if dispatched else "NO_ELIGIBLE_ESCROW",
                "flush_latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                "audit_block_index": blk["block_index"],
                "audit_block_hash": blk["block_hash"],
                "rfc6962_leaf_hash": blk.get("rfc6962_leaf_hash"),
                "rfc6962_tree_root": blk.get("rfc6962_tree_root"),
            }

        if method == "merkle_inclusion_proof":
            blocks = self.proxy.audit.blocks
            if not blocks:
                return {
                    "spec": "RFC-6962-Certificate-Transparency-v1",
                    "block_index": 0,
                    "leaf_index": 0,
                    "tree_size": 0,
                    "leaf_hash": None,
                    "root_hash": hashlib.sha256(b"").hexdigest(),
                    "audit_path": [],
                    "inclusion_verified": False,
                }
            target_idx = int(params["blockIndex"]) if params.get("blockIndex") is not None else len(blocks)
            return self.proxy.audit.generate_rfc6962_inclusion_proof(target_idx)

        if method == "evaluate_policy":
            t0 = time.perf_counter()
            policy_text = str(params.get("policyText") or DEFAULT_ENTERPRISE_POLICY)
            action = str(params.get("action") or "UPDATE").upper()
            ctx_raw = params.get("context")
            ctx = dict(ctx_raw) if isinstance(ctx_raw, dict) else {}
            if "amount" in params and "amount" not in ctx:
                ctx["amount"] = params["amount"]
            if "currentBalance" in params and "current_balance" not in ctx:
                ctx["current_balance"] = params["currentBalance"]
            if "minReserve" in params and "min_reserve" not in ctx:
                ctx["min_reserve"] = params["minReserve"]
            if "spendingLimit" in params and "spending_limit" not in ctx:
                ctx["spending_limit"] = params["spendingLimit"]
            if "cfoSigned" in params and "cfo_signed" not in ctx:
                ctx["cfo_signed"] = params["cfoSigned"]
            if "reversalArmed" in params and "reversal_armed" not in ctx:
                ctx["reversal_armed"] = params["reversalArmed"]
            principal = params.get("principal") or ctx.get("principal")
            resource = params.get("resource") or ctx.get("resource")
            hierarchy = params.get("entityHierarchy") or params.get("entity_hierarchy") or ctx.get("entity_hierarchy")
            res = ApodicticPolicyZ3Compiler.evaluate_and_prove(
                policy_text=policy_text,
                action=action,
                context=ctx,
                principal=principal,
                resource=resource,
                entity_hierarchy=hierarchy,
            )
            digest = hashlib.sha256(
                json.dumps({"action": action, "principal": principal, "resource": resource, "verdict": res["verdict"]}, sort_keys=True).encode()
            ).hexdigest()
            blk = self.proxy.audit.append_block(
                proof_id=f"pol_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}",
                action="POLICY_EVAL",
                verdict=res["verdict"],
                target_system="POLICY_ENGINE",
                zk_digest=digest,
                metadata={"principal": principal, "resource": resource, "unsat_core": res["unsat_core"]},
            )
            self._persist_last_block()
            res["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
            res["block_index"] = blk["block_index"]
            res["block_hash"] = blk["block_hash"]
            res["rfc6962_leaf_hash"] = blk.get("rfc6962_leaf_hash")
            res["rfc6962_tree_root"] = blk.get("rfc6962_tree_root")
            return res

        raise ValueError(f"Unknown enclave method: {method}")


def main():
    session = MonorepoEnclaveSession() if USE_MONOREPO else StandaloneEnclaveSession()
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
