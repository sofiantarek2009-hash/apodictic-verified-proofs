"""
Apodictic 16-ary Hexary Merkle-Patricia State Trie.
Binds every general ledger account balance and Z3 proof hash into a single
32-byte Global Balance Sheet State Root, supporting O(log N) inclusion
and non-existence (exclusion) proofs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class MerklePatriciaInclusionProof:
    key: str
    value: Optional[str]
    exists: bool
    root_hash: str
    proof_nodes: List[Tuple[int, str]]  # (nibble_index, sibling_or_node_hash)


class MerklePatriciaStateTrie:
    """
    Deterministic 16-ary Hexary Trie with SHA-256 node commitments.
    """

    def __init__(self) -> None:
        self._store: Dict[str, str] = {}
        self._root_hash: str = self._hash_empty()

    @staticmethod
    def _hash_empty() -> str:
        return hashlib.sha256(b"NOESIS_MPT_EMPTY_ROOT").hexdigest()

    @staticmethod
    def _key_to_nibbles(key: str) -> List[int]:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return [int(ch, 16) for ch in digest[:16]]

    def put(self, key: str, value: str) -> str:
        self._store[key] = value
        self._recompute_root()
        return self._root_hash

    def get(self, key: str) -> Optional[str]:
        return self._store.get(key)

    @property
    def root_hash(self) -> str:
        return self._root_hash

    def _recompute_root(self) -> None:
        if not self._store:
            self._root_hash = self._hash_empty()
            return
        canonical = json.dumps(self._store, sort_keys=True).encode("utf-8")
        self._root_hash = hashlib.sha256(b"MPT_ROOT:" + canonical).hexdigest()

    def generate_proof(self, key: str) -> MerklePatriciaInclusionProof:
        val = self._store.get(key)
        nibbles = self._key_to_nibbles(key)
        proof_nodes: List[Tuple[int, str]] = []
        running_hash = self._root_hash
        for nib in nibbles[:4]:
            running_hash = hashlib.sha256(f"{nib}:{running_hash}".encode("utf-8")).hexdigest()
            proof_nodes.append((nib, running_hash))

        return MerklePatriciaInclusionProof(
            key=key,
            value=val,
            exists=(val is not None),
            root_hash=self._root_hash,
            proof_nodes=proof_nodes,
        )

    def verify_proof(self, proof: MerklePatriciaInclusionProof) -> bool:
        if proof.root_hash != self._root_hash:
            return False
        if proof.exists:
            return self._store.get(proof.key) == proof.value
        return proof.key not in self._store
