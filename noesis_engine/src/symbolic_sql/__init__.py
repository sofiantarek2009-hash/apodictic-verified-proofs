"""
Apodictic Symbolic SQL-to-SMT Hoare Logic & Weakest-Precondition Compiler.
Symbolically lifts multi-statement SQL transactions into SSA relational algebra,
computes Dijkstra's Weakest Precondition wp(S, Q), and synthesizes minimal failing
witnesses + compensating SQL patches via Z3.
"""

from noesis_engine.src.symbolic_sql.sql_ssa_lifter import (
    SymbolicStatementKind,
    SymbolicAssignment,
    SymbolicSqlStatement,
    SqlSsaLifter,
)
from noesis_engine.src.symbolic_sql.weakest_precondition import (
    InvariantRule,
    HoareVerificationResult,
    WeakestPreconditionVerifier,
)
from noesis_engine.src.symbolic_sql.counterexample_witness_synthesizer import (
    FailingWitnessRow,
    CompensatingSqlPatch,
    CounterexampleWitnessSynthesizer,
)

__all__ = [
    "SymbolicStatementKind",
    "SymbolicAssignment",
    "SymbolicSqlStatement",
    "SqlSsaLifter",
    "InvariantRule",
    "HoareVerificationResult",
    "WeakestPreconditionVerifier",
    "FailingWitnessRow",
    "CompensatingSqlPatch",
    "CounterexampleWitnessSynthesizer",
]
