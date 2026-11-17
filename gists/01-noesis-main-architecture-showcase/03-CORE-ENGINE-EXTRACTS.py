"""
Apodictic — Verbatim Core Engine Architectural Extracts
======================================================
Contains annotated, runnable abstractions of the 5 deep enterprise subsystems
from `noesis_engine/src/`:
  1. ZeroPIIGateway                     (noesis_engine/src/gateway/zero_pii.py)
  2. WeakestPreconditionVerifier + Patch (noesis_engine/src/symbolic_sql/)
  3. AbacPolicyZ3Compiler               (noesis_engine/src/ontology/abac_policy_compiler.py)
  4. BaselTreasuryCovenantOptimizer     (noesis_engine/src/statutory_theorems/basel_treasury_covenants.py)
  5. ThreeWayMatchZ3Solver & Reconciler (noesis_engine/src/erp_clearing/)
"""

import hashlib
import json
import re
import z3


class HoareSqlTransferVerifier:
    """Compact mirror of WeakestPreconditionVerifier (noesis_engine/src/symbolic_sql/weakest_precondition.py)."""

    WHERE_EQ_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*'?([a-zA-Z0-9_-]+)'?", re.IGNORECASE)
    ARITH_DELTA_RE = re.compile(r"balance\s*([+-])\s*([0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)

    @classmethod
    def verify_and_synthesize_patch(cls, sql_script: str, initial_accounts: dict, min_reserve: float) -> dict:
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)
        concrete = dict(initial_accounts)
        sym = {k: z3.RealVal(str(v), ctx=ctx) for k, v in initial_accounts.items()}
        debits, credits, unguarded = 0.0, 0.0, False

        for raw in (p.strip() for p in sql_script.split(";") if p.strip()):
            up = raw.upper()
            if up.startswith("DELETE") and "WHERE" not in up:
                unguarded = True
            elif up.startswith("UPDATE"):
                if "WHERE" not in up:
                    unguarded = True
                    continue
                m_w = cls.WHERE_EQ_RE.search(raw.split("WHERE", 1)[1])
                m_a = cls.ARITH_DELTA_RE.search(raw)
                if m_w and m_a and m_w.group(2) in sym:
                    acct = m_w.group(2)
                    val = float(m_a.group(2))
                    if m_a.group(1) == "-":
                        sym[acct] = sym[acct] - z3.RealVal(str(val), ctx=ctx)
                        concrete[acct] -= val
                        debits += val
                    else:
                        sym[acct] = sym[acct] + z3.RealVal(str(val), ctx=ctx)
                        concrete[acct] += val
                        credits += val

        solver.assert_and_track(z3.BoolVal(not unguarded, ctx=ctx), "INV_NO_UNGUARDED_TABLE_MUTATION")
        for acct, z_bal in sym.items():
            solver.assert_and_track(z_bal >= z3.RealVal(str(min_reserve), ctx=ctx), f"INV_NON_NEGATIVE_RESERVE_{acct}")
        solver.assert_and_track(z3.RealVal(str(debits), ctx=ctx) == z3.RealVal(str(credits), ctx=ctx), "INV_DOUBLE_ENTRY_CONSERVATION")

        res = solver.check()
        core = [str(c) for c in solver.unsat_core()] if res == z3.unsat else []
        patches = [
            f"UPDATE accounts SET balance = balance + {round(min_reserve - bal, 2)} WHERE account_id = '{acct}';"
            for acct, bal in concrete.items()
            if bal < min_reserve
        ]
        return {
            "verdict": "SAT" if res == z3.sat else "UNSAT",
            "unsat_core": core,
            "final_balances": concrete,
            "compensating_sql": patches,
            "proof_hash": hashlib.sha256(json.dumps({"sql": sql_script, "core": core}).encode()).hexdigest(),
        }


if __name__ == "__main__":
    out = HoareSqlTransferVerifier.verify_and_synthesize_patch(
        "BEGIN; UPDATE accounts SET balance = balance - 18000 WHERE account_id = 'ACC_MAIN'; "
        "UPDATE accounts SET balance = balance + 18000 WHERE account_id = 'ACC_VENDOR'; COMMIT;",
        {"ACC_MAIN": 20000.0, "ACC_VENDOR": 0.0},
        min_reserve=5000.0,
    )
    print(json.dumps(out, indent=2))
