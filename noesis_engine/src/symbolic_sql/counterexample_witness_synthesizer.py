"""
Apodictic Counterexample Witness & Compensating SQL Patch Synthesizer.
When Z3 returns UNSAT on a symbolic SQL transaction, extracts the failing
witness row, dollar delta, and generates an exact compensating SQL patch.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from noesis_engine.src.symbolic_sql.weakest_precondition import HoareVerificationResult


@dataclass(frozen=True)
class FailingWitnessRow:
    account_id: str
    resulting_balance: float
    required_min_reserve: float
    deficit_amount: float


@dataclass
class CompensatingSqlPatch:
    violated_invariants: List[str]
    witness_rows: List[FailingWitnessRow]
    compensating_sql: str
    explanation: str


class CounterexampleWitnessSynthesizer:
    """
    Synthesizes minimal failing witness tables and compensating SQL patches
    from UNSAT Hoare verification results.
    """

    def synthesize_patch(
        self,
        result: HoareVerificationResult,
        min_reserve: float = 0.0,
    ) -> Optional[CompensatingSqlPatch]:
        if result.verified:
            return None

        witness_rows: List[FailingWitnessRow] = []
        sql_lines: List[str] = ["BEGIN;"]

        for acct_id, bal in result.final_symbolic_balances.items():
            if bal < min_reserve:
                deficit = round(min_reserve - bal, 2)
                witness_rows.append(
                    FailingWitnessRow(
                        account_id=acct_id,
                        resulting_balance=bal,
                        required_min_reserve=min_reserve,
                        deficit_amount=deficit,
                    )
                )
                sql_lines.append(
                    f"UPDATE accounts SET balance = balance + {deficit} WHERE account_id = '{acct_id}'; -- Restore reserve floor"
                )

        if "INV_DOUBLE_ENTRY_CONSERVATION" in result.violated_invariants:
            delta = round(result.total_debits - result.total_credits, 2)
            if delta > 0:
                sql_lines.append(
                    f"INSERT INTO journal_entries (account_id, debit, credit) VALUES ('SUSPENSE_CLEARING', 0, {delta});"
                )
            elif delta < 0:
                sql_lines.append(
                    f"INSERT INTO journal_entries (account_id, debit, credit) VALUES ('SUSPENSE_CLEARING', {abs(delta)}, 0);"
                )

        sql_lines.append("COMMIT;")
        return CompensatingSqlPatch(
            violated_invariants=result.violated_invariants,
            witness_rows=witness_rows,
            compensating_sql="\n".join(sql_lines),
            explanation=f"Synthesized {len(witness_rows)} reserve-restoration witness(es) for {result.violated_invariants}",
        )
