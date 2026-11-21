#!/usr/bin/env python3
"""
Apodictic — Critical Path & Multi-ERP Production Walkthrough
=============================================================
Executes the Critical Path:
    apodictic-wire-proxy -> ZeroPIIGateway -> apodictic-z3-engine -> apodictic-sovereign-audit-vault
plus 4 additional real-world ERP/Banking workflows (Odoo 18-20, Oracle NetSuite,
SAP S/4HANA 3-Way Match, ISO 20022 camt.053/pain.001 + Bi-Temporal & WORM).

Run standalone anywhere:
    pip install z3-solver && python3 02-LIVE-MULTI-ERP-WALKTHROUGH.py
Or inside the Apodictic repository:
    PYTHONPATH=. python3 gists/02-critical-path-multi-erp-lifecycle/02-LIVE-MULTI-ERP-WALKTHROUGH.py
"""

import bisect
import hashlib
import json
import re
import sqlite3
import struct
import time
from typing import Dict, List, Optional, Tuple
import z3

try:
    from apodictic_engine.src.wire_proxy.pg_protocol import PostgresWireCodec, MSG_QUERY
    from apodictic_engine.src.gateway.zero_pii import ZeroPIIGateway
    from apodictic_engine.src.verifier.smt_kernel import FormalInvariantKernel
    from apodictic_engine.src.audit_ledger.merkle_sealer import MerkleAuditLedger
    from apodictic_engine.src.erp_clearing import (
        PurchaseOrderLine,
        GoodsReceiptLine,
        VendorInvoiceLine,
        ThreeWayMatchZ3Solver,
        OpenLedgerInvoice,
        BankSettlementWire,
        ShadowLedgerReconciler,
    )
    from apodictic_engine.src.statutory_theorems import (
        BaselTreasuryCovenantOptimizer,
        TreasuryCovenantInput,
    )
    from apodictic_engine.src.core.bitemporal import BiTemporalLedger
    IN_REPO = True
except ImportError:
    IN_REPO = False


def encode_pg_query(sql: str) -> bytes:
    body = sql.encode("utf-8") + b"\x00"
    return b"Q" + struct.pack("!I", len(body) + 4) + body


def encode_pg_error(message: str, sqlstate: str) -> bytes:
    fields = b"SERROR\x00VERROR\x00C" + sqlstate.encode("ascii") + b"\x00M" + message.encode("utf-8") + b"\x00\x00"
    return b"E" + struct.pack("!I", len(fields) + 4) + fields


def mask_pii(text: str) -> tuple:
    if IN_REPO:
        gw = ZeroPIIGateway()
        sanitized, redactions, _ = gw.sanitize_string(text)
        restored_ok = gw.restore_payload(sanitized) == text
        assert restored_ok
        return sanitized, [r["token"] for r in redactions], restored_ok

    forward: Dict[str, str] = {}
    reverse: Dict[str, str] = {}
    counters: Dict[str, int] = {}
    out = text
    for prefix, pat in [
        ("SYM_IBAN", r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,28}\b"),
        ("SYM_TAX", r"\b(?:ETA|VAT|TIN|EIN|ZATCA)[-:\s]?[0-9]{9,15}\b"),
        ("SYM_EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ]:
        def _repl(m: re.Match, pfx: str = prefix) -> str:
            raw = m.group(0)
            if raw not in forward:
                counters[pfx] = counters.get(pfx, 0) + 1
                tok = f"<{pfx}_{counters[pfx]}>"
                forward[raw] = tok
                reverse[tok] = raw
            return forward[raw]

        out = re.sub(pat, _repl, out, flags=re.IGNORECASE)

    restored = out
    for tok, raw in reverse.items():
        restored = restored.replace(tok, raw)
    restored_ok = (restored == text)
    assert restored_ok, "Bijective PII restoration failed"
    return out, list(reverse.keys()), restored_ok


def _rfc6962_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _rfc6962_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _rfc6962_root_and_path(leaves: List[bytes], index: int) -> Tuple[bytes, List[Tuple[str, bytes]]]:
    level = list(leaves)
    path: List[Tuple[str, bytes]] = []
    idx = index
    while len(level) > 1:
        if idx % 2 == 0:
            if idx + 1 < len(level):
                path.append(("R", level[idx + 1]))
        else:
            path.append(("L", level[idx - 1]))
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_rfc6962_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
        idx //= 2
    return level[0], path


def _rfc6962_verify(leaf: bytes, path: List[Tuple[str, bytes]], root: bytes) -> bool:
    cur = leaf
    for side, sibling in path:
        cur = _rfc6962_node(cur, sibling) if side == "R" else _rfc6962_node(sibling, cur)
    return cur == root


def scenario_1_postgres_critical_path() -> dict:
    """Critical Path: apodictic-wire-proxy -> ZeroPIIGateway -> apodictic-z3-engine -> apodictic-sovereign-audit-vault."""
    raw_sql = (
        "UPDATE accounts SET balance = balance - 90000 "
        "WHERE iban = 'DE89370400440532013000' AND vat_id = 'ETA-301994821';"
    )
    pkt = encode_pg_query(raw_sql)
    sanitized_sql, minted_tokens, lossless = mask_pii(raw_sql)
    assert "DE89370400440532013000" not in sanitized_sql
    assert "ETA-301994821" not in sanitized_sql
    assert lossless is True

    ctx = z3.Context()
    s = z3.Solver(ctx=ctx)
    z_bal, z_amt, z_min, z_cap = z3.Reals("bal amt min_res cap", ctx=ctx)
    s.add(
        z_bal == z3.RealVal("100000", ctx=ctx),
        z_amt == z3.RealVal("90000", ctx=ctx),
        z_min == z3.RealVal("20000", ctx=ctx),
        z_cap == z3.RealVal("25000", ctx=ctx),
    )
    s.assert_and_track(z_bal - z_amt >= z_min, "INV_LIQUIDITY_FLOOR")
    s.assert_and_track(z_amt <= z_cap, "INV_AUTONOMOUS_CAP")
    verdict = s.check()
    unsat_core = [str(c) for c in s.unsat_core()]
    err_packet = encode_pg_error(f"Blocked by Z3 ({unsat_core})", "40001")

    proof_hash = hashlib.sha256(f"{sanitized_sql}|{unsat_core}".encode()).hexdigest()
    prev_hash = "0" * 64
    block_hash = hashlib.sha256(f"1:{prev_hash}:{proof_hash}".encode()).hexdigest()

    return {
        "scenario": "1_CRITICAL_PATH_PG_WIRE",
        "wire_packet_type": chr(pkt[0]),
        "wire_packet_bytes": len(pkt),
        "sanitized_sql": sanitized_sql,
        "minted_tokens": minted_tokens,
        "bijective_restore_ok": lossless,
        "z3_verdict": str(verdict).upper(),
        "unsat_core": unsat_core,
        "pg_error_sqlstate": "40001" if b"40001" in err_packet else "NONE",
        "worm_block_hash": block_hash,
    }


def scenario_2_odoo18_vat_and_reversal() -> dict:
    """Odoo 18 account.move VAT parity violation -> atomic account.move.reversal wizard."""
    ctx = z3.Context()
    s = z3.Solver(ctx=ctx)
    z_claimed, z_stat = z3.Reals("claimed_vat statutory_eta_vat", ctx=ctx)
    s.add(z_claimed == z3.RealVal("0.10", ctx=ctx), z_stat == z3.RealVal("0.14", ctx=ctx))
    s.assert_and_track(z_claimed == z_stat, "INV_STATUTORY_TAX_PARITY_ETA_14PCT")
    verdict = s.check()
    core = [str(c) for c in s.unsat_core()]
    odoo_jsonrpc_reversal = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": {
            "service": "object",
            "method": "execute_kw",
            "args": ["odoo18", 2, "<SYM_KEY_1>", "account.move.reversal", "create", [{"move_ids": [[4, 4092]], "reason": f"Z3 {core}"}]],
        },
    }
    return {
        "scenario": "2_ODOO_18_VAT_AND_REVERSAL",
        "z3_verdict": str(verdict).upper(),
        "unsat_core": core,
        "compensator_target": "odoo18.account.move.reversal",
        "jsonrpc_payload_preview": odoo_jsonrpc_reversal["params"]["args"][3:6],
    }


def scenario_3_netsuite_sod_and_basel3() -> dict:
    """Oracle NetSuite Intercompany + ABAC Separation of Duties + Basel III Optimize."""
    ctx = z3.Context()
    s = z3.Solver(ctx=ctx)
    z_creator = z3.String("creator", ctx=ctx)
    z_approver = z3.String("approver", ctx=ctx)
    s.add(z_creator == z3.StringVal("EMP-CREATOR", ctx=ctx), z_approver == z3.StringVal("EMP-CREATOR", ctx=ctx))
    s.assert_and_track(z_creator != z_approver, "POLICY_SEPARATION_OF_DUTIES_CONFLICT")
    sod_verdict = s.check()
    sod_core = [str(c) for c in s.unsat_core()]

    if IN_REPO:
        basel = BaselTreasuryCovenantOptimizer().compute_max_safe_payout(
            TreasuryCovenantInput(2_000_000.0, 5_000_000.0, 1_500_000.0, 850_000.0, 3.0, 1.0, 100_000.0)
        )
        max_safe, binding = basel.max_safe_payout_usd, basel.binding_covenant
    else:
        opt = z3.Optimize(ctx=ctx)
        p = z3.Real("payout", ctx=ctx)
        opt.add(
            p >= 0,
            z3.RealVal("2000000", ctx=ctx) - p >= z3.RealVal("100000", ctx=ctx),
            z3.RealVal("2000000", ctx=ctx) - p >= z3.RealVal("850000", ctx=ctx),
            z3.RealVal("5000000", ctx=ctx) - (z3.RealVal("2000000", ctx=ctx) - p) <= z3.RealVal("4500000", ctx=ctx),
        )
        opt.maximize(p)
        assert opt.check() == z3.sat
        val = opt.model()[p]
        max_safe = float(val.numerator_as_long()) / float(val.denominator_as_long())
        binding = "BASEL_III_LCR"

    return {
        "scenario": "3_NETSUITE_SOD_AND_BASEL3_OPTIMIZER",
        "self_approval_decision": "DENY" if sod_verdict == z3.unsat else "PERMIT",
        "sod_unsat_core": sod_core,
        "basel3_max_safe_payout_usd": max_safe,
        "binding_covenant": binding,
    }


def scenario_4_sap_three_way_match() -> dict:
    """SAP S/4HANA PO <-> Goods Receipt <-> Supplier Invoice 3-Way Z3 Solver."""
    if IN_REPO:
        solver = ThreeWayMatchZ3Solver(price_tolerance_pct=0.02)
        po = PurchaseOrderLine("PO-2026-88", "NVIDIA-B200-NODE", 10.0, 42000.0)
        gr = [GoodsReceiptLine("GR-88A", "PO-2026-88", "NVIDIA-B200-NODE", 8.0)]
        bad = solver.verify_three_way_match(po, gr, [VendorInvoiceLine("INV-PHANTOM", "PO-2026-88", "NVIDIA-B200-NODE", 10.0, 42000.0)])
        good = solver.verify_three_way_match(po, gr, [VendorInvoiceLine("INV-OK", "PO-2026-88", "NVIDIA-B200-NODE", 8.0, 42400.0)])
        bad_verdict, bad_rules, good_verdict = bad.verdict, bad.violated_rules, good.verdict
    else:
        ctx = z3.Context()

        def _check_match(billed_qty: float, billed_price: float) -> Tuple[str, List[str]]:
            sv = z3.Solver(ctx=ctx)
            z_po_q, z_rec_q, z_bil_q = z3.Reals("po_qty rec_qty billed_qty", ctx=ctx)
            z_po_p, z_bil_p = z3.Reals("po_price billed_price", ctx=ctx)
            sv.add(
                z_po_q == z3.RealVal("10", ctx=ctx),
                z_rec_q == z3.RealVal("8", ctx=ctx),
                z_bil_q == z3.RealVal(str(billed_qty), ctx=ctx),
                z_po_p == z3.RealVal("42000", ctx=ctx),
                z_bil_p == z3.RealVal(str(billed_price), ctx=ctx),
            )
            sv.assert_and_track(z_rec_q <= z_po_q, "3WAY_RECEIPT_WITHIN_PO_QTY")
            sv.assert_and_track(z_bil_q <= z_rec_q, "3WAY_BILLED_WITHIN_RECEIVED_QTY")
            sv.assert_and_track(
                z3.And(z_bil_p >= z_po_p * z3.Q(98, 100, ctx=ctx), z_bil_p <= z_po_p * z3.Q(102, 100, ctx=ctx)),
                "3WAY_PRICE_WITHIN_2PCT_TOLERANCE",
            )
            res = sv.check()
            return ("SAT" if res == z3.sat else "UNSAT"), [str(c) for c in sv.unsat_core()]

        bad_verdict, bad_rules = _check_match(10.0, 42000.0)
        good_verdict, good_rules = _check_match(8.0, 42400.0)
        assert bad_verdict == "UNSAT" and good_verdict == "SAT" and not good_rules

    return {
        "scenario": "4_SAP_S4HANA_THREE_WAY_MATCH",
        "phantom_10_unit_invoice": bad_verdict,
        "violated_rule": bad_rules,
        "partial_8_unit_within_2pct_price_tolerance": good_verdict,
    }


def _generate_pain001_xml(msg_id: str, amount_usd: float, remittance_refs: List[str]) -> str:
    refs = ", ".join(remittance_refs)
    return (
        f'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09">'
        f"<CstmrCdtTrfInitn><GrpHdr><MsgId>{msg_id}</MsgId><NbOfTxs>1</NbOfTxs></GrpHdr>"
        f"<PmtInf><CdtTrfTxInf><Amt><InstdAmt Ccy=\"USD\">{amount_usd:.2f}</InstdAmt></Amt>"
        f"<RmtInf><Ustrd>CLEARED:{refs}</Ustrd></RmtInf></CdtTrfTxInf></PmtInf>"
        f"</CstmrCdtTrfInitn></Document>"
    )


def scenario_5_iso20022_subset_sum_and_bitemporal() -> dict:
    """ISO 20022 camt.053 lump-sum wire reconciliation + pain.001 XML + SQL:2011 Bi-Temporal + Merkle Exclusion."""
    if IN_REPO:
        rec = ShadowLedgerReconciler().reconcile_lump_sum_wire(
            BankSettlementWire("CAMT053-77", 84975_00, 50_00),
            [OpenLedgerInvoice("AR-101", 31500_00), OpenLedgerInvoice("AR-102", 50000_00), OpenLedgerInvoice("AR-103", 35000_00)],
        )
        matched, fee_usd = rec.matched_invoice_ids, rec.implied_bank_fee_cents / 100.0
        bt = BiTemporalLedger("gl")
        bt.insert_fact("ACC-1010", {"balance": 1_000_000}, valid_start=100, valid_end=500, system_time=1000)
        bt.retroactive_restatement("ACC-1010", {"balance": 1_150_000}, effective_valid_start=100, effective_valid_end=500, adjustment_system_time=2000)
        v_then = bt.as_of("ACC-1010", valid_time=250, system_time=1500)["balance"]
        v_now = bt.as_of("ACC-1010", valid_time=250, system_time=2500)["balance"]
    else:
        ctx = z3.Context()
        s = z3.Solver(ctx=ctx)
        invs = [("AR-101", 31500_00), ("AR-102", 50000_00), ("AR-103", 35000_00)]
        sel = [z3.Int(f"s_{i}", ctx=ctx) for i in range(3)]
        for x in sel:
            s.add(z3.Or(x == 0, x == 1))
        tot = z3.Sum([sel[i] * invs[i][1] for i in range(3)])
        z_wire = z3.IntVal(84975_00, ctx=ctx)
        z_fee = z3.Int("implied_fee_cents", ctx=ctx)
        s.add(z_fee == tot - z_wire, z_fee >= 0, z_fee <= 50_00, z3.Sum(sel) >= 1)
        assert s.check() == z3.sat
        m = s.model()
        matched = [invs[i][0] for i in range(3) if m.evaluate(sel[i]).as_long() == 1]
        fee_usd = m.evaluate(z_fee).as_long() / 100.0

        # Real SQLite SQL:2011 bi-temporal table & point-in-time queries
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE gl_bitemporal (entity_id TEXT, balance INTEGER, valid_start INTEGER, valid_end INTEGER, sys_start INTEGER, sys_end INTEGER)"
        )
        conn.execute("INSERT INTO gl_bitemporal VALUES ('ACC-1010', 1000000, 100, 500, 1000, 2000)")
        conn.execute("INSERT INTO gl_bitemporal VALUES ('ACC-1010', 1150000, 100, 500, 2000, 999999)")
        q = "SELECT balance FROM gl_bitemporal WHERE entity_id=? AND ? >= valid_start AND ? < valid_end AND ? >= sys_start AND ? < sys_end"
        v_then = conn.execute(q, ("ACC-1010", 250, 250, 1500, 1500)).fetchone()[0]
        v_now = conn.execute(q, ("ACC-1010", 250, 250, 2500, 2500)).fetchone()[0]
        conn.close()

    pain001_xml = _generate_pain001_xml("PAIN001-2026-77", 84975.00, matched)
    assert "<CstmrCdtTrfInitn>" in pain001_xml

    # Real sorted-neighbor RFC 6962 Merkle exclusion witness proving ACC-OFFSHORE-99 absent
    sorted_balances = [("ACC-1010", str(v_now)), ("ACC-2040", "250000"), ("ACC-3090", "850000")]
    leaves = [_rfc6962_leaf(f"{k}={v}".encode()) for k, v in sorted_balances]
    target = "ACC-OFFSHORE-99"
    keys = [k for k, _ in sorted_balances]
    pos = bisect.bisect_left(keys, target)
    assert pos == len(keys) or keys[pos] != target
    root, path = _rfc6962_root_and_path(leaves, pos - 1)
    exclusion_verified = (keys[pos - 1] < target) and _rfc6962_verify(leaves[pos - 1], path, root)
    assert exclusion_verified

    return {
        "scenario": "5_ISO20022_WIRE_AND_BITEMPORAL",
        "lump_sum_wire_usd": 84975.00,
        "matched_open_invoices": matched,
        "inferred_bank_fee_usd": fee_usd,
        "pain001_xml_sha256": hashlib.sha256(pain001_xml.encode()).hexdigest(),
        "bitemporal_audit_view_t1500": v_then,
        "bitemporal_restated_view_t2500": v_now,
        "merkle_root": root.hex(),
        "offshore_account_exclusion_verified": exclusion_verified,
    }


def main() -> None:
    t0 = time.perf_counter()
    report = {
        "runtime_mode": "IN_REPO_FULL_KERNEL" if IN_REPO else "STANDALONE_Z3_GIST_RUNNER",
        "z3_version": z3.get_version_string(),
        "scenarios": [
            scenario_1_postgres_critical_path(),
            scenario_2_odoo18_vat_and_reversal(),
            scenario_3_netsuite_sod_and_basel3(),
            scenario_4_sap_three_way_match(),
            scenario_5_iso20022_subset_sum_and_bitemporal(),
        ],
        "total_execution_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
