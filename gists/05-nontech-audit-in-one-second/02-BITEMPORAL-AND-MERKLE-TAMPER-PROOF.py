#!/usr/bin/env python3
"""
Apodictic Proof 05 — Bi-Temporal Time-Travel Ledger & SEC 17a-4 Tamper Detection
===============================================================================
Reproduces instant historical audit reproducibility & tamper-evident sealing:
  1. Records Q1 initial balance ($1,000,000) and a Q3 retroactive restatement
     ($1,150,000) WITHOUT overwriting the historical point-in-time view.
  2. Seals events into an SHA-256 hash chain, flips 1 cent inside historical row #1,
     and cryptographically flags the exact corrupted link index.

Run anywhere: python3 02-BITEMPORAL-AND-MERKLE-TAMPER-PROOF.py
"""

import hashlib
import json
import time


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

    print(json.dumps({
        "bitemporal_q1_as_known_march_31_usd": march_board_view,
        "bitemporal_q1_restated_oct_31_usd": restated_oct_view,
        "worm_chain_intact_check": clean_check,
        "worm_chain_after_one_cent_tamper": tamper_check,
        "audit_latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }, indent=2))


if __name__ == "__main__":
    main()
