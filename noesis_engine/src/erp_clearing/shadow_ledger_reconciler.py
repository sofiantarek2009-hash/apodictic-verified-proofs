"""
Apodictic Shadow-Ledger Bank Settlement Reconciler (Z3 Subset-Sum Solver).
Automatically matches lump-sum bank wires (ISO 20022 camt.053) against
subsets of open AR/AP invoices net of wire fees.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List
import z3


@dataclass(frozen=True)
class OpenLedgerInvoice:
    invoice_id: str
    amount_cents: int


@dataclass(frozen=True)
class BankSettlementWire:
    wire_id: str
    settled_amount_cents: int
    max_bank_fee_cents: int = 5000


@dataclass
class SubsetSumMatchResult:
    reconciled: bool
    wire_id: str
    matched_invoice_ids: List[str]
    matched_sum_cents: int
    implied_bank_fee_cents: int
    z3_solve_ms: float


class ShadowLedgerReconciler:
    """
    Uses Z3 integer programming (0-1 Knapsack / Subset-Sum) to find the exact
    combination of open invoices that sum to a lump-sum bank wire.
    """

    def reconcile_lump_sum_wire(
        self,
        wire: BankSettlementWire,
        open_invoices: List[OpenLedgerInvoice],
    ) -> SubsetSumMatchResult:
        t0 = time.perf_counter()
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)

        selectors = [z3.Int(f"sel_{inv.invoice_id}", ctx=ctx) for inv in open_invoices]
        for s in selectors:
            solver.add(z3.Or(s == 0, s == 1))

        total_expr = z3.Sum([selectors[i] * open_invoices[i].amount_cents for i in range(len(open_invoices))])
        # total_invoices - wire.settled_amount_cents == bank_fee in [0, max_bank_fee_cents]
        fee_expr = total_expr - wire.settled_amount_cents
        solver.add(fee_expr >= 0)
        solver.add(fee_expr <= wire.max_bank_fee_cents)
        solver.add(z3.Sum(selectors) >= 1)

        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        if res != z3.sat:
            return SubsetSumMatchResult(
                reconciled=False,
                wire_id=wire.wire_id,
                matched_invoice_ids=[],
                matched_sum_cents=0,
                implied_bank_fee_cents=0,
                z3_solve_ms=elapsed_ms,
            )

        model = solver.model()
        matched_ids: List[str] = []
        matched_sum = 0
        for i, inv in enumerate(open_invoices):
            if model.evaluate(selectors[i]).as_long() == 1:
                matched_ids.append(inv.invoice_id)
                matched_sum += inv.amount_cents

        return SubsetSumMatchResult(
            reconciled=True,
            wire_id=wire.wire_id,
            matched_invoice_ids=matched_ids,
            matched_sum_cents=matched_sum,
            implied_bank_fee_cents=matched_sum - wire.settled_amount_cents,
            z3_solve_ms=elapsed_ms,
        )
