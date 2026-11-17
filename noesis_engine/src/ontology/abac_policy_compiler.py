"""
Apodictic Attribute-Based Access Control (ABAC) & Separation of Duties (SoD) Z3 Compiler.
Compiles enterprise org-chart clearances, data residency laws, dual-custody thresholds,
and Separation of Duties rules into formal Z3 boolean/integer constraints.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set
import z3


class SecurityClearanceLevel(IntEnum):
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4
    SOVEREIGN_TOP_SECRET = 5


@dataclass(frozen=True)
class PrincipalAttributes:
    principal_id: str
    department: str
    clearance: SecurityClearanceLevel
    jurisdiction: str
    approval_limit_usd: float
    roles: Set[str] = field(default_factory=set)


@dataclass(frozen=True)
class ResourceSecurityTag:
    resource_id: str
    required_clearance: SecurityClearanceLevel
    allowed_jurisdictions: Set[str]
    created_by_principal_id: str
    transaction_amount_usd: float = 0.0
    requires_dual_custody_above_usd: float = 50000.0


@dataclass(frozen=True)
class SeparationOfDutiesRule:
    rule_id: str
    conflicting_action_a: str
    conflicting_action_b: str
    description: str


@dataclass
class AbacDecisionReceipt:
    decision: str  # "PERMIT" | "DENY"
    principal_id: str
    resource_id: str
    violated_policies: List[str]
    z3_solve_ms: float
    proof_hash: str


class AbacPolicyZ3Compiler:
    """
    Compiles ABAC clearances, data residency, dual-custody, and Separation of Duties (SoD)
    into Z3 formal constraints with unsat-core policy diagnostics.
    """

    def __init__(self) -> None:
        self.sod_rules: List[SeparationOfDutiesRule] = [
            SeparationOfDutiesRule(
                rule_id="SOD-001",
                conflicting_action_a="CREATE_VENDOR",
                conflicting_action_b="APPROVE_PAYMENT",
                description="Creator of a vendor cannot approve payments to that vendor",
            )
        ]

    def evaluate_access(
        self,
        principal: PrincipalAttributes,
        resource: ResourceSecurityTag,
        co_signer: Optional[PrincipalAttributes] = None,
    ) -> AbacDecisionReceipt:
        t0 = time.perf_counter()
        ctx = z3.Context()
        solver = z3.Solver(ctx=ctx)

        z_p_clear = z3.Int("principal_clearance", ctx=ctx)
        z_r_clear = z3.Int("resource_required_clearance", ctx=ctx)
        z_residency_ok = z3.Bool("data_residency_match", ctx=ctx)
        z_sod_conflict = z3.Bool("sod_creator_approver_conflict", ctx=ctx)
        z_tx_amt = z3.Real("tx_amount_usd", ctx=ctx)
        z_p_limit = z3.Real("principal_approval_limit", ctx=ctx)
        z_dual_thresh = z3.Real("dual_custody_threshold", ctx=ctx)
        z_has_cosigner = z3.Bool("has_valid_cosigner", ctx=ctx)

        solver.add(z_p_clear == int(principal.clearance))
        solver.add(z_r_clear == int(resource.required_clearance))
        solver.add(z_residency_ok == z3.BoolVal(principal.jurisdiction in resource.allowed_jurisdictions, ctx=ctx))
        solver.add(z_sod_conflict == z3.BoolVal(principal.principal_id == resource.created_by_principal_id, ctx=ctx))
        solver.add(z_tx_amt == z3.RealVal(str(resource.transaction_amount_usd), ctx=ctx))
        solver.add(z_p_limit == z3.RealVal(str(principal.approval_limit_usd), ctx=ctx))
        solver.add(z_dual_thresh == z3.RealVal(str(resource.requires_dual_custody_above_usd), ctx=ctx))

        cosigner_valid = (
            co_signer is not None
            and co_signer.principal_id != principal.principal_id
            and co_signer.principal_id != resource.created_by_principal_id
            and co_signer.clearance >= resource.required_clearance
        )
        solver.add(z_has_cosigner == z3.BoolVal(cosigner_valid, ctx=ctx))

        solver.assert_and_track(z_p_clear >= z_r_clear, "POLICY_CLEARANCE_INSUFFICIENT")
        solver.assert_and_track(z_residency_ok, "POLICY_DATA_RESIDENCY_VIOLATION")
        solver.assert_and_track(z3.Not(z_sod_conflict), "POLICY_SEPARATION_OF_DUTIES_CONFLICT")
        solver.assert_and_track(
            z3.Or(z_tx_amt <= z_p_limit, z_has_cosigner),
            "POLICY_APPROVAL_LIMIT_OR_DUAL_CUSTODY",
        )
        solver.assert_and_track(
            z3.Or(z_tx_amt <= z_dual_thresh, z_has_cosigner),
            "POLICY_MANDATORY_DUAL_CUSTODY_THRESHOLD",
        )

        res = solver.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        decision = "PERMIT" if res == z3.sat else "DENY"
        violations = [str(c) for c in solver.unsat_core()] if res == z3.unsat else []
        proof_hash = hashlib.sha256(
            json.dumps(
                {
                    "principal": principal.principal_id,
                    "resource": resource.resource_id,
                    "decision": decision,
                    "violations": violations,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()

        return AbacDecisionReceipt(
            decision=decision,
            principal_id=principal.principal_id,
            resource_id=resource.resource_id,
            violated_policies=violations,
            z3_solve_ms=elapsed_ms,
            proof_hash=proof_hash,
        )
