"""
Apodictic Enterprise Audit Ledger & Merkle DAG Sealer
Cryptographically seals every invariant verification, state mutation, and rollback action.
Maintains an append-only hash chain linking transaction roots with SHA-256 proof digests.
"""

import hashlib
import time
import json
from typing import List, Dict, Any, Optional

class MerkleAuditLedger:
    def __init__(self):
        self.blocks: List[Dict[str, Any]] = []
        self._genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    def append_block(
        self,
        proof_id: str,
        action: str,
        verdict: str,
        target_system: str,
        zk_digest: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        prev_hash = self.blocks[-1]['block_hash'] if self.blocks else self._genesis_hash
        block_idx = len(self.blocks) + 1
        ts = time.time_ns()

        payload = {
            "block_index": block_idx,
            "previous_hash": prev_hash,
            "timestamp_ns": ts,
            "proof_id": proof_id,
            "action": action,
            "verdict": verdict,
            "target_system": target_system,
            "zk_digest": zk_digest,
            "metadata": metadata or {}
        }

        # Calculate Block Hash: SHA-256(prev_hash + payload)
        serialized = json.dumps(payload, sort_keys=True)
        block_hash = hashlib.sha256(f"{prev_hash}:{serialized}".encode('utf-8')).hexdigest()
        payload["block_hash"] = block_hash

        self.blocks.append(payload)
        return payload

    def verify_integrity(self) -> bool:
        if not self.blocks:
            return True

        for idx, block in enumerate(self.blocks):
            if idx == 0:
                expected_prev = self._genesis_hash
            else:
                expected_prev = self.blocks[idx - 1]['block_hash']

            if block['previous_hash'] != expected_prev:
                return False

            copy_block = dict(block)
            actual_hash = copy_block.pop('block_hash')
            serialized = json.dumps(copy_block, sort_keys=True)
            recalc = hashlib.sha256(f"{expected_prev}:{serialized}".encode('utf-8')).hexdigest()
            if recalc != actual_hash:
                return False

        return True
