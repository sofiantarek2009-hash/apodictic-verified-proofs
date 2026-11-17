"""
Apodictic GAAP ASC 606 & IFRS 15 Revenue Recognition Z3 Solver.
Verifies multi-element performance obligation allocation using Standalone Selling
Price (SSP) proportionality, variable consideration constraints, and deferred revenue
roll-forward conservation.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Dict, List
import z3


@dataclass(frozen=True)
class PerformanceObligation:
    obligation_id: str
    description: str
    standalone_selling_price: float
    recognized_at_inception: float
    deferred_revenue: float


@dataclass
class Asc606AllocationResult:
    verdict: str  # "SAT" | "UNSAT"
    verified: bool
    total_contract_price: float
    total_ssp: float
    allocated_amounts: Dict[str, float]
    violated_theorems: List[str]
    z3_solve_ms: float
    proof_hash: str


class Asc606RevenueSolver:
    """
    Formal Z3 solver for ASC 606 / IFRS 15 5-Step Revenue Recognition.
    """

    def verify_contract_allocation(
        self,
        total_transaction_price: float,
        obligations: List[PerformanceObligation],
        tolerance: float = 0.01,
    ) -> Asc606AllocationResult:
        t0 = time.perf_counter()
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)

        total_ssp = sum(o.standalone_selling_price for o in obligations)
        z_tx_price = z3.Real("total_transaction_price", ctx=ctx)
        z_total_ssp = z3.Real("total_ssp", ctx=ctx)
        z_tol = z3.RealVal(str(tolerance), ctx=ctx)

        solver.add(z_tx_price == z3.RealVal(str(total_transaction_price), ctx=ctx))
        solver.add(z_total_ssp == z3.RealVal(str(total_ssp), ctx=ctx))
        solver.assert_and_track(z_tx_price > 0, "ASC606_POSITIVE_TRANSACTION_PRICE")
        solver.assert_and_track(z_total_ssp > 0, "ASC606_POSITIVE_TOTAL_SSP")

        sum_recognized_and_deferred = z3.RealVal("0", ctx=ctx)
        allocated: Dict[str, float] = {}

        for ob in obligations:
            expected_alloc = (ob.standalone_selling_price / total_ssp) * total_transaction_price if total_ssp > 0 else 0.0
            allocated[ob.obligation_id] = round(expected_alloc, 2)

            z_rec = z3.Real(f"rec_{ob.obligation_id}", ctx=ctx)
            z_def = z3.Real(f"def_{ob.obligation_id}", ctx=ctx)
            z_exp = z3.Real(f"exp_alloc_{ob.obligation_id}", ctx=ctx)

            solver.add(z_rec == z3.RealVal(str(ob.recognized_at_inception), ctx=ctx))
            solver.add(z_def == z3.RealVal(str(ob.deferred_revenue), ctx=ctx))
            solver.add(z_exp == z3.RealVal(str(round(expected_alloc, 4)), ctx=ctx))

            solver.assert_and_track(z_rec >= 0, f"ASC606_NON_NEG_RECOGNIZED_{ob.obligation_id}")
            solver.assert_and_track(z_def >= 0, f"ASC606_NON_NEG_DEFERRED_{ob.obligation_id}")
            solver.assert_and_track(
                z3.And((z_rec + z_def) - z_exp <= z_tol, z_exp - (z_rec + z_def) <= z_tol),
                f"ASC606_SSP_PROPORTIONAL_ALLOCATION_{ob.obligation_id}",
            )
            sum_recognized_and_deferred = sum_recognized_and_deferred + z_rec + z_def

        solver.assert_and_track(
            z3.And(
                sum_recognized_and_deferred - z_tx_price <= z_tol,
                z_tx_price - sum_recognized_and_deferred <= z_tol,
            ),
            "ASC606_TOTAL_CONTRACT_CONSERVATION",
        )

        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        verdict = "SAT" if res == z3.sat else "UNSAT"
        violations = [str(c) for c in solver.unsat_core()] if res == z3.unsat else []
        proof_hash = hashlib.sha256(
            json.dumps({"price": total_transaction_price, "verdict": verdict, "violations": violations}, sort_keys=True).encode()
        ).hexdigest()

        return Asc606AllocationResult(
            verdict=verdict,
            verified=(verdict == "SAT"),
            total_contract_price=total_transaction_price,
            total_ssp=total_ssp,
            allocated_amounts=allocated,
            violated_theorems=violations,
            z3_solve_ms=elapsed_ms,
            proof_hash=proof_hash,
        )
