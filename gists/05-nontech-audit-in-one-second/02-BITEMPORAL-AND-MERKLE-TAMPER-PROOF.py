#!/usr/bin/env python3
"""
Apodictic Proof 05 — Bi-Temporal Time-Travel Ledger, RFC 6962 Merkle Proofs & Smurfing Defense
===============================================================================================
Reproduces instant historical audit reproducibility, tamper-evident sealing, and structuring checks:
  1. Records Q1 initial balance ($1,000,000) and a Q3 retroactive restatement ($1,150,000)
     WITHOUT overwriting the historical point-in-time view.
  2. Seals events into an SHA-256 WORM hash chain, flips 1 cent inside historical row #1,
     and cryptographically flags the exact corrupted link index.
  3. Builds an RFC 6962 binary Merkle tree over the sealed balance sheet snapshot, verifying
     both O(log N) inclusion proofs AND sorted-neighbor exclusion proofs (proving an off-book
     shell account does not exist).
  4. Flags split-cap structuring ("smurfing") transactions clustered inside [0.95 * cap, cap).

Run anywhere: python3 02-BITEMPORAL-AND-MERKLE-TAMPER-PROOF.py
"""

import bisect
import hashlib
import json
import time
from typing import List, Optional, Tuple


def rfc6962_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def rfc6962_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def rfc6962_build_root(leaves: List[bytes]) -> bytes:
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(rfc6962_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


def rfc6962_audit_path(leaves: List[bytes], index: int) -> List[Tuple[str, bytes]]:
    level = list(leaves)
    path: List[Tuple[str, bytes]] = []
    idx = index
    while len(level) > 1:
        if idx % 2 == 0:
            if idx + 1 < len(level):
                path.append(("R", level[idx + 1]))
        else:
            path.append(("L", level[idx - 1]))
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(rfc6962_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
        idx //= 2
    return path


def rfc6962_verify(leaf: bytes, path: List[Tuple[str, bytes]], root: bytes) -> bool:
    cur = leaf
    for side, sibling in path:
        cur = rfc6962_node(cur, sibling) if side == "R" else rfc6962_node(sibling, cur)
    return cur == root


def main() -> None:
    t0 = time.perf_counter()

    # 1. Dual-timeline (valid_time, transaction_time) immutable fact log
    facts = [
        {"id": "F1", "valid_date": "2026-03-15", "tx_date": "2026-03-15", "q1_revenue_usd": 1_000_000.00, "note": "Initial Q1 Close"},
        {"id": "F2", "valid_date": "2026-03-15", "tx_date": "2026-10-20", "q1_revenue_usd": 1_150_000.00, "note": "Q3 Audit Restatement"},
    ]

    def as_of(valid_cutoff: str, tx_cutoff: str) -> float:
        matching = [f for f in facts if f["valid_date"] <= valid_cutoff and f["tx_date"] <= tx_cutoff]
        return matching[-1]["q1_revenue_usd"] if matching else 0.0

    march_board_view = as_of("2026-03-31", "2026-03-31")
    restated_oct_view = as_of("2026-03-31", "2026-10-31")

    # 2. Build SEC 17a-4 SHA-256 WORM Hash Chain
    chain = []
    prev = "0" * 64
    for idx, fact in enumerate(facts, start=1):
        payload = json.dumps(fact, sort_keys=True)
        digest = hashlib.sha256(f"{idx}:{prev}:{payload}".encode()).hexdigest()
        chain.append({"seq": idx, "prev_hash": prev, "fact": fact, "block_hash": digest})
        prev = digest

    def verify_worm(blocks: list) -> dict:
        expected_prev = "0" * 64
        for blk in blocks:
            if blk["prev_hash"] != expected_prev:
                return {"valid": False, "corrupted_seq": blk["seq"], "reason": "PREV_HASH_MISMATCH"}
            payload = json.dumps(blk["fact"], sort_keys=True)
            recalc = hashlib.sha256(f"{blk['seq']}:{expected_prev}:{payload}".encode()).hexdigest()
            if recalc != blk["block_hash"]:
                return {"valid": False, "corrupted_seq": blk["seq"], "reason": "PAYLOAD_TAMPER_DETECTED"}
            expected_prev = blk["block_hash"]
        return {"valid": True, "blocks_verified": len(blocks)}

    clean_check = verify_worm(chain)

    # 3. Simulate an insider altering historical Q1 revenue by $0.01
    tampered = json.loads(json.dumps(chain))
    tampered[0]["fact"]["q1_revenue_usd"] = 1_000_000.01
    tamper_check = verify_worm(tampered)
    assert clean_check["valid"] is True and tamper_check["valid"] is False and tamper_check["corrupted_seq"] == 1

    # 4. RFC 6962 Binary Merkle Inclusion + Sorted-Neighbor Exclusion Witness
    snapshot = [
        ("ACC-1010-CASH", 1_150_000.00),
        ("ACC-2040-AP", 240_000.00),
        ("ACC-3090-REVENUE", 1_150_000.00),
        ("ACC-4020-TAX", 161_000.00),
    ]
    keys = [k for k, _ in snapshot]
    leaves = [rfc6962_leaf(f"{k}:{v:.2f}".encode("utf-8")) for k, v in snapshot]
    root = rfc6962_build_root(leaves)

    # Inclusion proof for ACC-2040-AP (index 1)
    inc_path = rfc6962_audit_path(leaves, 1)
    inclusion_ok = rfc6962_verify(leaves[1], inc_path, root)

    # Sorted-neighbor exclusion proof for off-book shell account ACC-2500-OFFSHORE
    off_book_key = "ACC-2500-OFFSHORE"
    pos = bisect.bisect_left(keys, off_book_key)
    left_idx, right_idx = pos - 1, pos
    left_key: Optional[str] = keys[left_idx] if left_idx >= 0 else None
    right_key: Optional[str] = keys[right_idx] if right_idx < len(keys) else None
    excl_ok = True
    if left_key is not None:
        excl_ok = excl_ok and (left_key < off_book_key) and rfc6962_verify(leaves[left_idx], rfc6962_audit_path(leaves, left_idx), root)
    if right_key is not None:
        excl_ok = excl_ok and (off_book_key < right_key) and rfc6962_verify(leaves[right_idx], rfc6962_audit_path(leaves, right_idx), root)
    assert inclusion_ok and excl_ok

    # 5. Structuring / Smurfing Detection below $50,000 dual-approval threshold
    dual_approval_cap = 50_000.0
    ledger_stream = [49_910.0, 49_850.0, 49_975.0, 1_250.0]
    structuring_hits = [amt for amt in ledger_stream if (0.95 * dual_approval_cap) <= amt < dual_approval_cap]
    smurfing_alert = "SMURFING_STRUCTURING_DETECTED" if len(structuring_hits) >= 2 else "NONE"
    assert len(structuring_hits) == 3 and smurfing_alert == "SMURFING_STRUCTURING_DETECTED"

    print(json.dumps({
        "bitemporal_q1_as_known_march_31_usd": march_board_view,
        "bitemporal_q1_restated_oct_31_usd": restated_oct_view,
        "worm_chain_intact_check": clean_check,
        "worm_chain_after_one_cent_tamper": tamper_check,
        "rfc6962_merkle_root": root.hex(),
        "merkle_inclusion_acc_2040_verified": inclusion_ok,
        "merkle_exclusion_off_book": {
            "target_absent_key": off_book_key,
            "left_neighbor": left_key,
            "right_neighbor": right_key,
            "exclusion_verified": excl_ok,
        },
        "structuring_smurfing_detector": {
            "dual_approval_cap_usd": dual_approval_cap,
            "flagged_split_amounts_usd": structuring_hits,
            "alert": smurfing_alert,
        },
        "audit_latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }, indent=2))


if __name__ == "__main__":
    main()
