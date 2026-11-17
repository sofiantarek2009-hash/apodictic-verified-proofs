"""
Apodictic Enterprise Database Proxy & Invariant Interceptor
Intercepts client database queries, parses SQL AST on-the-fly, evaluates formal SMT invariants,
and applies compensating savepoints before statements ever hit production storage engines.
"""

import re
import time
from typing import Dict, Any, List, Optional
from noesis_engine.src.ast_compiler.sql_compiler import SqlAstCompiler
from noesis_engine.src.smt_theory.theory_kernel import AdvancedSmtKernel
from noesis_engine.src.dlp_engine.deep_dlp import DeepDlpEngine
from noesis_engine.src.saga_engine.saga_coordinator import DistributedSagaCoordinator
from noesis_engine.src.audit_ledger.merkle_sealer import MerkleAuditLedger
from noesis_engine.src.core.types import DagStep, TargetSystemType, Verdict


def _extract_sql_amount(sql: str) -> float:
    m = re.search(r"\b(?:SET\s+[^;]*?\b(?:amount|total_amount|payment_amount)|(?:amount|total_amount|payment_amount))\s*=\s*([0-9]+(?:\.[0-9]+)?)", sql, re.I)
    return float(m.group(1)) if m else 0.0


class NoesisProxyInterceptor:
    def __init__(self):
        self.dlp = DeepDlpEngine()
        self.smt = AdvancedSmtKernel()
        self.saga = DistributedSagaCoordinator()
        self.audit = MerkleAuditLedger()
        self._account_velocity: Dict[str, List[float]] = {}

    def intercept_and_execute(
        self,
        raw_statement: str,
        account_id: str,
        current_balance: float,
        min_reserve: float,
        spending_limit: float,
        cfo_signed: bool = False,
        statutory_vat: float = 0.14,
        expected_vat: float = 0.14,
        amount: Optional[float] = None,
        reversal_armed: Optional[bool] = None,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()

        # 1. Zero-PII Context-Aware Tokenization
        sanitized_stmt, redactions, bytes_cut = self.dlp.sanitize_text(raw_statement)
        dlp_ms = (time.perf_counter() - t0) * 1000.0

        # 2. SQL AST Compilation & Semantic Analysis
        ast_t0 = time.perf_counter()
        ast_node = SqlAstCompiler.compile(sanitized_stmt)
        ast_ms = (time.perf_counter() - ast_t0) * 1000.0

        # 3. Formulate Transaction Step (extract numeric amount + cumulative rolling velocity)
        is_destructive = ast_node.is_unbounded or ast_node.statement_type.value in ('DELETE', 'DROP', 'TRUNCATE')
        tx_amount = float(amount) if amount is not None else _extract_sql_amount(raw_statement)
        prior_sum = sum(self._account_velocity.get(account_id, []))
        effective_amount = tx_amount + prior_sum
        effective_reversal_armed = reversal_armed if reversal_armed is not None else (not is_destructive)

        step = DagStep(
            step_id=f"step_{int(time.time()*1000)}",
            name=f"sql_{ast_node.statement_type.value.lower()}",
            target_system=TargetSystemType.POSTGRESQL,
            action=ast_node.statement_type.value,
            amount=effective_amount,
            account_id=account_id
        )

        # 4. Formal SMT Invariant Theorem Proving
        # Destructive SQL drops/deletes/unbounded mutations require explicit reversal arming.
        proof = self.smt.verify_financial_dag(
            initial_balance=current_balance,
            minimum_reserve=min_reserve,
            spending_limit=spending_limit,
            cfo_signed=cfo_signed,
            is_destructive_op=is_destructive,
            reversal_armed=effective_reversal_armed,
            statutory_vat=statutory_vat,
            expected_vat=expected_vat,
            dag_steps=[step]
        )

        if proof.verdict == Verdict.SAT and tx_amount > 0:
            self._account_velocity.setdefault(account_id, []).append(tx_amount)

        # 5. Atomic Saga Staging
        saga_id = None
        if proof.verdict == Verdict.SAT:
            saga_id = self.saga.begin_saga(f"batch_{int(time.time()*1000)}", [step])
            self.saga.execute_forward_step(saga_id, step.step_id)

        # 6. Merkle Cryptographic Sealing
        block = self.audit.append_block(
            proof_id=proof.proof_id,
            action=ast_node.statement_type.value,
            verdict=proof.verdict.value,
            target_system="POSTGRESQL",
            zk_digest=proof.sha256_hash,
            metadata={"tables": ast_node.target_tables, "unbounded": ast_node.is_unbounded}
        )

        total_latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "verdict": proof.verdict.value,
            "verified": proof.verdict == Verdict.SAT,
            "proof_id": proof.proof_id,
            "proof_digest": proof.sha256_hash,
            "block_index": block["block_index"],
            "block_hash": block["block_hash"],
            "timings": {
                "dlp_latency_ms": round(dlp_ms, 3),
                "ast_latency_ms": round(ast_ms, 3),
                "z3_solve_ms": proof.z3_solve_ms,
                "total_proxy_latency_ms": round(total_latency_ms, 3)
            },
            "redactions": len(redactions),
            "sanitized_sql": sanitized_stmt,
            "ast_analysis": {
                "statement_type": ast_node.statement_type.value,
                "target_tables": ast_node.target_tables,
                "is_unbounded": ast_node.is_unbounded,
                "has_where": ast_node.has_where_clause
            },
            "saga_id": saga_id
        }
