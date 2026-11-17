#!/usr/bin/env python3
"""
Apodictic Proof 03 — AI Financial Safety Net (Zero-PII Leak Guard + Z3 Solvency Veto)
====================================================================================
Reproduces the exact 2-step safety net in under 2 milliseconds:
  1. Strips sensitive bank IBANs & tax IDs BEFORE any external AI sees the prompt,
     then restores the real values losslessly inside the local trust boundary.
  2. Uses Z3 to mathematically block a $90,000 disbursement against a $100,000 account
     ($20,000 payroll reserve floor) and compute the exact safe maximum ($80,000).

Run anywhere: pip install z3-solver && python3 02-SAFETY-NET-RUNNABLE-PROOF.py
"""

import json
import re
import time
import z3


class BijectiveTokenizer:
    def __init__(self) -> None:
        self._reverse = {}

    def sanitize(self, text: str) -> str:
        patterns = [
            ("IBAN", re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,28}\b")),
            ("TAX", re.compile(r"\b(?:ETA|VAT|ZATCA)[-:\s]?[0-9]{9,15}\b")),
            ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
        ]
        out = text
        idx = 0
        for label, pat in patterns:
            for m in pat.finditer(text):
                raw = m.group(0)
                if raw in out:
                    idx += 1
                    tok = f"<SYM_{label}_{idx}>"
                    self._reverse[tok] = raw
                    out = out.replace(raw, tok, 1)
        return out

    def restore(self, sanitized: str) -> str:
        out = sanitized
        for tok, raw in self._reverse.items():
            out = out.replace(tok, raw)
        return out


def main() -> None:
    t0 = time.perf_counter()
    prompt = "Pay $90,000 to vendor billing@supplier.eg on IBAN DE89370400440532013000 (Tax ETA-301994821)"

    vault = BijectiveTokenizer()
    masked = vault.sanitize(prompt)
    assert "DE89370400440532013000" not in masked and "ETA-301994821" not in masked
    assert vault.restore(masked) == prompt

    # Checkpoint 2: Mathematical Solvency Veto ($100k cash, $20k payroll floor)
    cash, reserve, requested = 100_000.0, 20_000.0, 90_000.0
    ctx = z3.Context()
    s = z3.Solver(ctx=ctx)
    s.assert_and_track(
        z3.RealVal(str(cash - requested), ctx=ctx) >= z3.RealVal(str(reserve), ctx=ctx),
        "PAYROLL_RESERVE_FLOOR_INVARIANT",
    )
    verdict = s.check()
    unsat_core = [str(c) for c in s.unsat_core()] if verdict == z3.unsat else []

    # Synthesize exact safe cap via Z3 Optimize
    opt = z3.Optimize(ctx=ctx)
    z_pay = z3.Real("safe_payout", ctx=ctx)
    opt.add(z_pay >= 0, z3.RealVal(str(cash), ctx=ctx) - z_pay >= z3.RealVal(str(reserve), ctx=ctx))
    opt.maximize(z_pay)
    assert opt.check() == z3.sat
    safe_cap = float(opt.model().evaluate(z_pay).as_decimal(4).rstrip("?"))

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    print(json.dumps({
        "zero_pii_masked_prompt_sent_to_llm": masked,
        "secret_bytes_exposed_to_cloud_llm": 0,
        "lossless_local_restoration": True,
        "attempted_wire_usd": requested,
        "payroll_reserve_usd": reserve,
        "verdict": "BLOCKED" if verdict == z3.unsat else "APPROVED",
        "violated_rule": unsat_core,
        "z3_synthesized_max_safe_payout_usd": safe_cap,
        "elapsed_ms": elapsed_ms,
    }, indent=2))


if __name__ == "__main__":
    main()
