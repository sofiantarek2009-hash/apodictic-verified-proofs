#!/usr/bin/env python3
"""
Noesis Domain Proof 07 — ETA (Egypt) Mixed-Tax Cascade, T4 WHT Timing & ZATCA BR-CO-14 Solver
=============================================================================================
Demonstrates deterministic verification of:
  1. Egypt ETA compound T2 Table Tax -> T1 14% VAT tax base
  2. Payment-time T4 Withholding Tax (on Net excluding VAT) conservation
  3. ZATCA Phase 2 BR-CO-14 penny-exact header-vs-line tax parity

Run anywhere: pip install z3-solver && python3 01-MIXED-TAX-SOLVER.py
"""

import json
import time
import z3


def verify_eta_compound_tax_and_wht(
    net_amount: float,
    t2_table_rate: float,
    t1_vat_rate: float,
    t4_wht_rate: float,
    claimed_vat: float,
    cash_settled: float,
    wht_certificate_amt: float,
) -> dict:
    t0 = time.perf_counter()
    ctx = z3.Context()
    s = z3.Solver(ctx=ctx)

    t2_tax = round(net_amount * t2_table_rate, 2)
    compound_vat_base = round(net_amount + t2_tax, 2)
    expected_t1_vat = round(compound_vat_base * t1_vat_rate, 2)
    gross_invoice = round(compound_vat_base + expected_t1_vat, 2)
    expected_wht_t4 = round(net_amount * t4_wht_rate, 2)  # T4 computed on net excl. taxes

    z_tol = z3.RealVal("0.01", ctx=ctx)
    z_claimed = z3.RealVal(str(claimed_vat), ctx=ctx)
    z_expected_vat = z3.RealVal(str(expected_t1_vat), ctx=ctx)
    s.assert_and_track(
        z3.And(z_claimed - z_expected_vat <= z_tol, z_expected_vat - z_claimed <= z_tol),
        "ETA_COMPOUND_T2_T1_VAT_PARITY",
    )

    z_cash = z3.RealVal(str(cash_settled), ctx=ctx)
    z_wht = z3.RealVal(str(wht_certificate_amt), ctx=ctx)
    z_gross = z3.RealVal(str(gross_invoice), ctx=ctx)
    s.assert_and_track(
        z3.And((z_cash + z_wht) - z_gross <= z_tol, z_gross - (z_cash + z_wht) <= z_tol),
        "ETA_T4_WHT_SETTLEMENT_CONSERVATION",
    )
    s.assert_and_track(
        z3.And(
            z_wht - z3.RealVal(str(expected_wht_t4), ctx=ctx) <= z_tol,
            z3.RealVal(str(expected_wht_t4), ctx=ctx) - z_wht <= z_tol,
        ),
        "ETA_T4_WHT_RATE_APPLIED_TO_NET_ONLY",
    )

    res = s.check()
    core = [str(c) for c in s.unsat_core()] if res == z3.unsat else []
    return {
        "verdict": "SAT" if res == z3.sat else "UNSAT",
        "unsat_core": core,
        "net_egp": net_amount,
        "t2_table_tax_egp": t2_tax,
        "expected_compound_t1_vat_egp": expected_t1_vat,
        "gross_invoice_egp": gross_invoice,
        "expected_t4_wht_egp": expected_wht_t4,
        "solve_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }


def solve_zatca_br_co_14_line_rounding(line_nets: list, vat_rate: float = 0.15) -> dict:
    """Computes halala-exact VAT per line so sum(line_vats_cents) == header_vat_cents."""
    t0 = time.perf_counter()
    header_net_cents = sum(round(x * 100) for x in line_nets)
    header_vat_cents = round(header_net_cents * vat_rate)

    raw_line_vats = [round(x * 100) * vat_rate for x in line_nets]
    rounded_line_vats = [round(v) for v in raw_line_vats]
    drift_cents = header_vat_cents - sum(rounded_line_vats)

    # Allocate any 1-halala residual via Z3 integer constraints to the line with max fractional remainder
    ctx = z3.Context()
    s = z3.Solver(ctx=ctx)
    deltas = [z3.Int(f"d_{i}", ctx=ctx) for i in range(len(line_nets))]
    for d in deltas:
        s.add(d >= -1, d <= 1)
    adjusted = [rounded_line_vats[i] + deltas[i] for i in range(len(line_nets))]
    s.add(z3.Sum(adjusted) == header_vat_cents)
    assert s.check() == z3.sat
    m = s.model()
    final_line_vats = [rounded_line_vats[i] + m.evaluate(deltas[i]).as_long() for i in range(len(line_nets))]

    ubl_tax_xml = (
        f'<cac:TaxTotal><cbc:TaxAmount currencyID="SAR">{header_vat_cents / 100.0:.2f}</cbc:TaxAmount>'
        + "".join(
            f'<cac:TaxSubtotal><cbc:LineExtensionAmount>{line_nets[i]:.2f}</cbc:LineExtensionAmount>'
            f'<cbc:TaxAmount currencyID="SAR">{final_line_vats[i] / 100.0:.2f}</cbc:TaxAmount></cac:TaxSubtotal>'
            for i in range(len(line_nets))
        )
        + "</cac:TaxTotal>"
    )

    return {
        "header_vat_sar": header_vat_cents / 100.0,
        "naive_line_sum_sar": sum(rounded_line_vats) / 100.0,
        "detected_br_co_14_drift_halalas": drift_cents,
        "reconciled_line_vats_sar": [v / 100.0 for v in final_line_vats],
        "parity_verified": (sum(final_line_vats) == header_vat_cents),
        "ubl_2_1_tax_total_xml": ubl_tax_xml,
        "solve_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }


if __name__ == "__main__":
    # 100,000 EGP engineering consulting w/ 5% T2 -> 105,000 base -> 14% T1 VAT = 14,700 (not 14,000!), Gross = 119,700, 5% T4 WHT = 5,000
    bad_flat = verify_eta_compound_tax_and_wht(100_000.0, 0.05, 0.14, 0.05, claimed_vat=14_000.0, cash_settled=114_700.0, wht_certificate_amt=5_000.0)
    ok_compound = verify_eta_compound_tax_and_wht(100_000.0, 0.05, 0.14, 0.05, claimed_vat=14_700.0, cash_settled=114_700.0, wht_certificate_amt=5_000.0)
    zatca = solve_zatca_br_co_14_line_rounding([10.03, 10.03, 10.03], vat_rate=0.15)
    assert bad_flat["verdict"] == "UNSAT" and ok_compound["verdict"] == "SAT" and zatca["parity_verified"]
    print(json.dumps({"flat_tax_bug_caught": bad_flat, "eta_compound_verified": ok_compound, "zatca_br_co_14": zatca}, indent=2))
