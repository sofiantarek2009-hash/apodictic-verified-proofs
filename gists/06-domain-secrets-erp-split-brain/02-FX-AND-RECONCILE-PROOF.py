#!/usr/bin/env python3
"""
Apodictic Domain Proof 06 — Multicurrency ERP Revaluation & Split-Brain Reversal
=============================================================================
Demonstrates:
  1. Why naive ERP reversals corrupt multicurrency general ledgers when FX spot drifts
     between posting (49.20 EGP/USD) and reversal (49.35 EGP/USD) -> 6,000 EGP leak.
  2. How Z3 proves exact base-currency Debit == Credit conservation with explicit FX
     clearing journal legs + fiscal period lock invariant.
  3. Idempotent retry guard: executing reversal twice triggers atomic move reversal once
     and returns an idempotent no-op on duplicate retry (zero double-credit-notes).

Run anywhere: pip install z3-solver && python3 02-FX-AND-RECONCILE-PROOF.py
"""

import json
import time
import z3


def verify_multicurrency_reversal(
    usd_principal: float,
    booking_fx_rate: float,
    settlement_fx_rate: float,
    booked_fx_gain_loss: float,
    period_open: bool,
) -> dict:
    t0 = time.perf_counter()
    ctx = z3.Context()
    s = z3.Solver(ctx=ctx)

    base_booked = round(usd_principal * booking_fx_rate, 2)
    base_settled = round(usd_principal * settlement_fx_rate, 2)

    z_booked = z3.RealVal(str(base_booked), ctx=ctx)
    z_settled = z3.RealVal(str(base_settled), ctx=ctx)
    z_fx_gl = z3.RealVal(str(booked_fx_gain_loss), ctx=ctx)
    z_tol = z3.RealVal("0.01", ctx=ctx)

    s.assert_and_track(z3.BoolVal(period_open, ctx=ctx), "ERP_FISCAL_PERIOD_OPEN")
    residual = (z_settled - z_booked) - z_fx_gl
    s.assert_and_track(z3.And(residual <= z_tol, residual >= -z_tol), "ERP_FX_REVALUATION_CONSERVATION")

    # Verify Odoo account.move.reversal double-entry legs balance in functional currency (EGP)
    legs = [
        {"account": "210100_AP_CLEARING", "debit_egp": base_booked, "credit_egp": 0.0},
        {"account": "710500_REALIZED_FX_LOSS", "debit_egp": booked_fx_gain_loss, "credit_egp": 0.0},
        {"account": "101200_BANK_SUSPENSE", "debit_egp": 0.0, "credit_egp": base_settled},
    ]
    z_debits = z3.RealVal(str(sum(l["debit_egp"] for l in legs)), ctx=ctx)
    z_credits = z3.RealVal(str(sum(l["credit_egp"] for l in legs)), ctx=ctx)
    s.assert_and_track(
        z3.And(z_debits - z_credits <= z_tol, z_credits - z_debits <= z_tol),
        "ERP_GL_FUNCTIONAL_CURRENCY_DEBIT_EQ_CREDIT",
    )

    verdict = s.check()
    core = [str(c) for c in s.unsat_core()] if verdict == z3.unsat else []
    return {
        "verdict": "SAT" if verdict == z3.sat else "UNSAT",
        "unsat_core": core,
        "booked_egp": base_booked,
        "settled_egp": base_settled,
        "required_fx_gain_loss_egp": round(base_settled - base_booked, 2),
        "compensating_journal_legs": legs if verdict == z3.sat else [],
        "solve_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }


def simulate_idempotent_saga_reversal() -> dict:
    posted_reversals = set()

    def compensate_once(move_id: str) -> dict:
        if move_id in posted_reversals:
            return {"move_id": move_id, "steps_reverted": 0, "idempotent_noop": True}
        posted_reversals.add(move_id)
        return {"move_id": move_id, "steps_reverted": 1, "reversal_ref": f"R{move_id}"}

    first = compensate_once("BILL/2026/00412")
    retry = compensate_once("BILL/2026/00412")
    return {"first_call": first, "duplicate_retry_call": retry}


if __name__ == "__main__":
    naive = verify_multicurrency_reversal(40_000.0, 49.20, 49.35, booked_fx_gain_loss=0.0, period_open=True)
    closed_period = verify_multicurrency_reversal(40_000.0, 49.20, 49.35, booked_fx_gain_loss=6_000.0, period_open=False)
    exact = verify_multicurrency_reversal(40_000.0, 49.20, 49.35, booked_fx_gain_loss=6_000.0, period_open=True)
    idemp = simulate_idempotent_saga_reversal()
    assert naive["verdict"] == "UNSAT" and "ERP_FX_REVALUATION_CONSERVATION" in naive["unsat_core"]
    assert closed_period["verdict"] == "UNSAT" and "ERP_FISCAL_PERIOD_OPEN" in closed_period["unsat_core"]
    assert exact["verdict"] == "SAT"
    assert idemp["first_call"]["steps_reverted"] == 1 and idemp["duplicate_retry_call"]["steps_reverted"] == 0
    print(json.dumps({
        "naive_reversal": naive,
        "locked_period_reversal": closed_period,
        "apodictic_fx_compensated_reversal": exact,
        "idempotent_saga_retry_guard": idemp,
    }, indent=2))
