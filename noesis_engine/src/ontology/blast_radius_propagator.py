"""
Apodictic Financial Blast-Radius & Contagion Risk Propagator.
Performs graph-theoretic k-hop exposure propagation across the EnterpriseOntologyRegistry
to quantify exact dollar impact when a vendor defaults, a subsidiary faces a liquidity freeze,
or a tax authority flags an invoice.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from noesis_engine.src.ontology.object_type_registry import EnterpriseOntologyRegistry


class ShockType(str, Enum):
    VENDOR_DEFAULT = "VENDOR_DEFAULT"
    SUBSIDIARY_LIQUIDITY_FREEZE = "SUBSIDIARY_LIQUIDITY_FREEZE"
    TAX_AUDIT_CLAWBACK = "TAX_AUDIT_CLAWBACK"
    BANK_ACCOUNT_SEIZURE = "BANK_ACCOUNT_SEIZURE"


@dataclass(frozen=True)
class ContagionShockSpec:
    shock_type: ShockType
    origin_object_id: str
    severity_ratio: float  # 0.0 to 1.0
    max_hops: int = 5
    attenuation_per_hop: float = 0.75


@dataclass
class EntityExposureReport:
    object_id: str
    object_type: str
    hop_distance: int
    direct_exposure_usd: float
    propagated_risk_score: float
    causal_path: List[str]


@dataclass
class BlastRadiusSimulationReport:
    origin_object_id: str
    shock_type: ShockType
    total_affected_entities: int
    total_exposure_usd: float
    max_hop_reached: int
    exposures: List[EntityExposureReport] = field(default_factory=list)


class BlastRadiusPropagator:
    """
    Traverses directed and undirected ontology links to compute downstream financial
    exposure and systemic contagion across subsidiaries, accounts, and invoices.
    """

    def __init__(self, registry: EnterpriseOntologyRegistry) -> None:
        self.registry = registry

    def _estimate_object_dollar_value(self, object_id: str) -> float:
        obj = self.registry.objects.get(object_id)
        if not obj:
            return 0.0
        props = obj.properties
        if obj.object_type == "Invoice":
            return float(props.get("net_amount", 0.0)) + float(props.get("vat_amount", 0.0))
        if obj.object_type == "BankAccount":
            return float(props.get("balance", 0.0))
        if obj.object_type == "Subsidiary":
            return float(props.get("cash_balance", 0.0))
        if obj.object_type == "PurchaseOrder":
            return float(props.get("total_amount", 0.0))
        return 0.0

    def simulate_shock(self, spec: ContagionShockSpec) -> BlastRadiusSimulationReport:
        if spec.origin_object_id not in self.registry.objects:
            raise ValueError(f"Origin object '{spec.origin_object_id}' not found in ontology")

        visited: Dict[str, int] = {spec.origin_object_id: 0}
        queue: deque[Tuple[str, int, float, List[str]]] = deque(
            [(spec.origin_object_id, 0, spec.severity_ratio, [spec.origin_object_id])]
        )
        exposures: List[EntityExposureReport] = []
        total_exposure = 0.0
        max_hop = 0

        while queue:
            curr_id, hop, risk, path = queue.popleft()
            curr_obj = self.registry.objects[curr_id]
            base_val = self._estimate_object_dollar_value(curr_id)
            direct_exp = round(base_val * risk, 2)
            total_exposure += direct_exp
            max_hop = max(max_hop, hop)

            exposures.append(
                EntityExposureReport(
                    object_id=curr_id,
                    object_type=curr_obj.object_type,
                    hop_distance=hop,
                    direct_exposure_usd=direct_exp,
                    propagated_risk_score=round(risk * 100.0, 2),
                    causal_path=path,
                )
            )

            if hop >= spec.max_hops:
                continue

            # Propagate along outgoing and incoming ontology links
            neighbor_ids: Set[str] = set()
            for lid in self.registry._outgoing.get(curr_id, []):
                neighbor_ids.add(self.registry.links[lid].target_id)
            for lid in self.registry._incoming.get(curr_id, []):
                neighbor_ids.add(self.registry.links[lid].source_id)

            next_risk = risk * spec.attenuation_per_hop
            for nid in sorted(neighbor_ids):
                if nid not in visited:
                    visited[nid] = hop + 1
                    queue.append((nid, hop + 1, next_risk, path + [nid]))

        return BlastRadiusSimulationReport(
            origin_object_id=spec.origin_object_id,
            shock_type=spec.shock_type,
            total_affected_entities=len(exposures),
            total_exposure_usd=round(total_exposure, 2),
            max_hop_reached=max_hop,
            exposures=exposures,
        )
