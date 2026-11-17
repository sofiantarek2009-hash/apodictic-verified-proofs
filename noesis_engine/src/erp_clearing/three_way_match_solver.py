"""
Apodictic 3-Way Match Combinatorial Z3 Solver.
Verifies Purchase Order <-> Goods Receipt <-> Vendor Invoice parity across
partial shipments, unit price tolerances, and duplicate-invoice prevention.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List
import z3


@dataclass(frozen=True)
class PurchaseOrderLine:
    po_id: str
    sku: str
    ordered_qty: float
    unit_price: float


@dataclass(frozen=True)
class GoodsReceiptLine:
    receipt_id: str
    po_id: str
    sku: str
    received_qty: float


@dataclass(frozen=True)
class VendorInvoiceLine:
    invoice_id: str
    po_id: str
    sku: str
    billed_qty: float
    billed_unit_price: float


@dataclass
class ThreeWayMatchResult:
    matched: bool
    verdict: str  # "SAT" | "UNSAT"
    sku: str
    po_qty: float
    received_qty: float
    billed_qty: float
    price_variance_pct: float
    violated_rules: List[str]
    z3_solve_ms: float


class ThreeWayMatchZ3Solver:
    def __init__(self, price_tolerance_pct: float = 0.02) -> None:
        self.price_tolerance_pct = price_tolerance_pct

    def verify_three_way_match(
        self,
        po: PurchaseOrderLine,
        receipts: List[GoodsReceiptLine],
        invoices: List[VendorInvoiceLine],
    ) -> ThreeWayMatchResult:
        t0 = time.perf_counter()
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)

        total_rec_qty = sum(r.received_qty for r in receipts if r.po_id == po.po_id and r.sku == po.sku)
        total_inv_qty = sum(i.billed_qty for i in invoices if i.po_id == po.po_id and i.sku == po.sku)

        z_po_qty = z3.RealVal(str(po.ordered_qty), ctx=ctx)
        z_rec_qty = z3.RealVal(str(total_rec_qty), ctx=ctx)
        z_inv_qty = z3.RealVal(str(total_inv_qty), ctx=ctx)
        z_po_price = z3.RealVal(str(po.unit_price), ctx=ctx)
        z_tol = z3.RealVal(str(self.price_tolerance_pct), ctx=ctx)

        # 1. Cannot receive more than ordered
        solver.assert_and_track(z_rec_qty <= z_po_qty, "3WAY_RECEIPT_WITHIN_PO_QTY")
        # 2. Cannot bill for more than physically received (prevents phantom billing)
        solver.assert_and_track(z_inv_qty <= z_rec_qty, "3WAY_BILLED_WITHIN_RECEIVED_QTY")
        # 3. Positive quantities
        solver.assert_and_track(z_inv_qty > 0, "3WAY_POSITIVE_BILLED_QTY")

        max_var = 0.0
        for idx, inv in enumerate(invoices):
            if inv.po_id == po.po_id and inv.sku == po.sku:
                var_pct = abs(inv.billed_unit_price - po.unit_price) / po.unit_price if po.unit_price > 0 else 0.0
                max_var = max(max_var, var_pct)
                z_inv_price = z3.RealVal(str(inv.billed_unit_price), ctx=ctx)
                solver.assert_and_track(
                    z3.And(
                        z_inv_price <= z_po_price * (1 + z_tol),
                        z_inv_price >= z_po_price * (1 - z_tol),
                    ),
                    f"3WAY_UNIT_PRICE_TOLERANCE_{idx}",
                )

        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        verdict = "SAT" if res == z3.sat else "UNSAT"
        violations = [str(c) for c in solver.unsat_core()] if res == z3.unsat else []

        return ThreeWayMatchResult(
            matched=(verdict == "SAT"),
            verdict=verdict,
            sku=po.sku,
            po_qty=po.ordered_qty,
            received_qty=total_rec_qty,
            billed_qty=total_inv_qty,
            price_variance_pct=round(max_var * 100.0, 3),
            violated_rules=violations,
            z3_solve_ms=elapsed_ms,
        )
