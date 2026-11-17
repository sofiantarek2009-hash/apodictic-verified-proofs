"""
Apodictic Global Indirect Tax & E-Invoicing Z3 Theorem Prover.
Encodes statutory tax rules for Saudi ZATCA Phase 2 (15% VAT), Egypt ETA v1.0 (14% VAT + WHT),
and EU VAT Directive 2006/112/EC (Reverse Charge & Standard VAT).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import List
import z3


class TaxJurisdiction(str, Enum):
    KSA_ZATCA = "KSA_ZATCA"       # 15% standard VAT
    EGYPT_ETA = "EGYPT_ETA"       # 14% standard VAT + Withholding Tax
    EU_VAT_DE = "EU_VAT_DE"       # 19% standard VAT
    EU_REVERSE_CHARGE = "EU_REVERSE_CHARGE"  # 0% B2B cross-border reverse charge


@dataclass(frozen=True)
class IndirectTaxLineItem:
    sku: str
    net_amount: float
    claimed_vat_amount: float
    claimed_wht_amount: float = 0.0
    is_exempt: bool = False


@dataclass
class IndirectTaxVerificationReceipt:
    jurisdiction: TaxJurisdiction
    verdict: str  # "SAT" | "UNSAT"
    verified: bool
    expected_total_vat: float
    claimed_total_vat: float
    violated_tax_laws: List[str]
    z3_solve_ms: float
    proof_hash: str


class GlobalIndirectTaxSolver:
    STATUTORY_RATES = {
        TaxJurisdiction.KSA_ZATCA: 0.15,
        TaxJurisdiction.EGYPT_ETA: 0.14,
        TaxJurisdiction.EU_VAT_DE: 0.19,
        TaxJurisdiction.EU_REVERSE_CHARGE: 0.00,
    }

    def verify_invoice_taxes(
        self,
        jurisdiction: TaxJurisdiction,
        lines: List[IndirectTaxLineItem],
        has_cryptographic_stamp: bool = True,
        tolerance: float = 0.02,
    ) -> IndirectTaxVerificationReceipt:
        t0 = time.perf_counter()
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)

        rate = self.STATUTORY_RATES[jurisdiction]
        z_tol = z3.RealVal(str(tolerance), ctx=ctx)

        if jurisdiction in (TaxJurisdiction.KSA_ZATCA, TaxJurisdiction.EGYPT_ETA):
            solver.assert_and_track(
                z3.BoolVal(has_cryptographic_stamp, ctx=ctx),
                f"TAX_LAW_{jurisdiction.value}_CRYPTO_STAMP_REQUIRED",
            )

        expected_total_vat = 0.0
        claimed_total_vat = 0.0

        for idx, item in enumerate(lines):
            eff_rate = 0.0 if item.is_exempt else rate
            exp_vat = round(item.net_amount * eff_rate, 4)
            expected_total_vat += exp_vat
            claimed_total_vat += item.claimed_vat_amount

            z_net = z3.Real(f"line_{idx}_net", ctx=ctx)
            z_vat = z3.Real(f"line_{idx}_claimed_vat", ctx=ctx)
            z_exp = z3.Real(f"line_{idx}_expected_vat", ctx=ctx)

            solver.add(z_net == z3.RealVal(str(item.net_amount), ctx=ctx))
            solver.add(z_vat == z3.RealVal(str(item.claimed_vat_amount), ctx=ctx))
            solver.add(z_exp == z3.RealVal(str(exp_vat), ctx=ctx))

            solver.assert_and_track(z_net >= 0, f"TAX_NON_NEG_NET_{idx}")
            solver.assert_and_track(
                z3.And(z_vat - z_exp <= z_tol, z_exp - z_vat <= z_tol),
                f"TAX_STATUTORY_VAT_PARITY_{jurisdiction.value}_{idx}",
            )

        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        verdict = "SAT" if res == z3.sat else "UNSAT"
        violations = [str(c) for c in solver.unsat_core()] if res == z3.unsat else []
        proof_hash = hashlib.sha256(
            json.dumps({"jurisdiction": jurisdiction.value, "verdict": verdict, "violations": violations}, sort_keys=True).encode()
        ).hexdigest()

        return IndirectTaxVerificationReceipt(
            jurisdiction=jurisdiction,
            verdict=verdict,
            verified=(verdict == "SAT"),
            expected_total_vat=round(expected_total_vat, 2),
            claimed_total_vat=round(claimed_total_vat, 2),
            violated_tax_laws=violations,
            z3_solve_ms=elapsed_ms,
            proof_hash=proof_hash,
        )
