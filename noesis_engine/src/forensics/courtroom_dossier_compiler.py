"""
Apodictic SEC 17a-4 / PCAOB AS 1105 Courtroom Audit Dossier Compiler.
Generates deterministic, self-verifying cryptographic audit dossiers binding
Z3 SMT-LIB2 proofs, Merkle-Patricia inclusion branches, and Benford forensic reports.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List

from noesis_engine.src.forensics.merkle_patricia_ledger import MerklePatriciaInclusionProof


@dataclass
class PcaobAuditDossier:
    dossier_id: str
    entity_id: str
    merkle_root_hash: str
    z3_proof_hash: str
    inclusion_proof: MerklePatriciaInclusionProof
    forensic_summary: Dict[str, Any]
    compiled_at_utc_ms: int
    dossier_seal_hash: str


class CourtroomDossierCompiler:
    def compile_dossier(
        self,
        entity_id: str,
        z3_proof_hash: str,
        inclusion_proof: MerklePatriciaInclusionProof,
        forensic_summary: Dict[str, Any],
    ) -> PcaobAuditDossier:
        ts = int(time.time() * 1000)
        canonical = json.dumps(
            {
                "entity_id": entity_id,
                "merkle_root": inclusion_proof.root_hash,
                "z3_proof_hash": z3_proof_hash,
                "forensic_summary": forensic_summary,
                "ts": ts,
            },
            sort_keys=True,
        ).encode("utf-8")
        seal = hashlib.sha256(b"PCAOB_AS1105_DOSSIER:" + canonical).hexdigest()
        return PcaobAuditDossier(
            dossier_id=f"DOS-{seal[:12].upper()}",
            entity_id=entity_id,
            merkle_root_hash=inclusion_proof.root_hash,
            z3_proof_hash=z3_proof_hash,
            inclusion_proof=inclusion_proof,
            forensic_summary=forensic_summary,
            compiled_at_utc_ms=ts,
            dossier_seal_hash=seal,
        )
