#!/usr/bin/env python3
"""
Noesis Proof 04 — Automated 3-Way Match, Lump-Sum Wire Subset-Sum & Treasury Cap
================================================================================
Reproduces 3 autonomous finance operations mathematically via Microsoft Z3:
  1. Phantom Billing Trap: Blocks a 10-GPU invoice against 8 received warehouse units.
  2. Mystery Bank Wire: Solves 0-1 Subset-Sum for a $84,975 wire net of $25 SWIFT fee.
  3. Basel III Treasury Ceiling: Finds exact $1,150,000 max safe cash payout today.

Run anywhere: pip install z3-solver && python3 02-THREE-WAY-MATCH-AND-BANK-WIRE-PROOF.py
"""

import json
import time
import z3


def prove_three_way_match() -> dict:
    po_qty, rec_qty, billed_qty = 10, 8, 10
    ctx = z3.Context()
    s = z3.Solver(ctx=ctx)
    s.assert_and_track(z3.IntVal(rec_qty, ctx=ctx) <= z3.IntVal(po_qty, ctx=ctx), "RECEIPT_LEQ_PO")
    s.assert_and_track(z3.IntVal(billed_qty, ctx=ctx) <= z3.IntVal(rec_qty, ctx=ctx), "BILLED_LEQ_RECEIVED")
    verdict = s.check()
    return {
        "po_qty": po_qty,
        "warehouse_received_qty": rec_qty,
        "vendor_billed_qty": billed_qty,
        "verdict": "UNSAT_PHANTOM_BILL_BLOCKED" if verdict == z3.unsat else "SAT",
        "unsat_core": [str(c) for c in s.unsat_core()],
        "max_approvable_qty_today": rec_qty,
    }


def solve_lump_sum_bank_wire() -> dict:
    invoices = [
        ("AR-101", 31500_00),
        ("AR-102", 50000_00),
        ("AR-103", 35000_00),
        ("AR-104", 19200_00),
    ]
    wire_cents = 84975_00
    max_fee_cents = 50_00

    ctx = z3.Context()
    s = z3.Solver(ctx=ctx)
    sel = [z3.Int(f"pick_{inv_id}", ctx=ctx) for inv_id, _ in invoices]
    for v in sel:
        s.add(z3.Or(v == 0, v == 1))
    total = z3.Sum([sel[i] * invoices[i][1] for i in range(len(invoices))])
    fee = total - wire_cents
    s.add(fee >= 0, fee <= max_fee_cents, z3.Sum(sel) >= 1)
    assert s.check() == z3.sat
    m = s.model()
    matched = [invoices[i][0] for i in range(len(invoices)) if m.evaluate(sel[i]).as_long() == 1]
    matched_sum = sum(invoices[i][1] for i in range(len(invoices)) if m.evaluate(sel[i]).as_long() == 1)
    return {
        "bank_wire_usd": wire_cents / 100.0,
        "matched_open_invoices": matched,
        "invoice_gross_sum_usd": matched_sum / 100.0,
        "implied_swift_fee_usd": (matched_sum - wire_cents) / 100.0,
    }


def solve_basel3_max_payout() -> dict:
    cash, debt, ebitda, outflows_30d = 2_000_000.0, 5_000_000.0, 1_500_000.0, 850_000.0
    ctx = z3.Context()
    opt = z3.Optimize(ctx=ctx)
    p = z3.Real("payout", ctx=ctx)
    opt.add(p >= 0)
    # 1. Min $100k reserve
    opt.add(z3.RealVal(str(cash), ctx=ctx) - p >= z3.RealVal("100000", ctx=ctx))
    # 2. Basel III LCR >= 100% -> (cash - payout) / 850k >= 1.0
    opt.add((z3.RealVal(str(cash), ctx=ctx) - p) >= z3.RealVal(str(outflows_30d), ctx=ctx))
    # 3. Net Leverage <= 3.0x -> (debt - (cash - payout)) / ebitda <= 3.0
    opt.add((z3.RealVal(str(debt), ctx=ctx) - (z3.RealVal(str(cash), ctx=ctx) - p)) <= z3.RealVal(str(3.0 * ebitda), ctx=ctx))
    opt.maximize(p)
    assert opt.check() == z3.sat
    max_p = float(opt.model().evaluate(p).as_decimal(4).rstrip("?"))
    return {
        "cash_and_hqla_usd": cash,
        "binding_lcr_min_usd": outflows_30d,
        "exact_max_safe_payout_usd": max_p,
    }


if __name__ == "__main__":
    t0 = time.perf_counter()
    res = {
        "1_phantom_invoice_3way_match": prove_three_way_match(),
        "2_subset_sum_wire_clearing": solve_lump_sum_bank_wire(),
        "3_basel3_lcr_leverage_optimizer": solve_basel3_max_payout(),
        "total_solve_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }
    print(json.dumps(res, indent=2))
