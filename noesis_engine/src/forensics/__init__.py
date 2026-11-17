"""
Apodictic Cryptographic Merkle-Patricia State Trie & Courtroom Forensics Engine.
Provides O(log N) inclusion & exclusion proofs for corporate balance sheets,
Benford's Law & structuring fraud detection, and SEC 17a-4 / PCAOB AS 1105 Audit Dossiers.
"""

from noesis_engine.src.forensics.merkle_patricia_ledger import (
    MerklePatriciaInclusionProof,
    MerklePatriciaStateTrie,
)
from noesis_engine.src.forensics.benford_forensic_anomaly_detector import (
    ForensicAnomalyAlert,
    BenfordForensicReport,
    BenfordForensicDetector,
)
from noesis_engine.src.forensics.courtroom_dossier_compiler import (
    PcaobAuditDossier,
    CourtroomDossierCompiler,
)

__all__ = [
    "MerklePatriciaInclusionProof",
    "MerklePatriciaStateTrie",
    "ForensicAnomalyAlert",
    "BenfordForensicReport",
    "BenfordForensicDetector",
    "PcaobAuditDossier",
    "CourtroomDossierCompiler",
]
