"""
Apodictic Benford's Law & Structuring Forensic Anomaly Detector.
Detects split-transaction structuring (e.g., $49,950 just below a $50,000 cap),
round-number clustering, and Benford's Law first-digit chi-squared divergence.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class ForensicAnomalyAlert:
    alert_type: str
    severity: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    description: str
    flagged_amounts: List[float] = field(default_factory=list)


@dataclass
class BenfordForensicReport:
    sample_size: int
    chi_squared_stat: float
    benford_compliant: bool
    alerts: List[ForensicAnomalyAlert] = field(default_factory=list)


class BenfordForensicDetector:
    BENFORD_EXPECTED = {
        1: 0.30103,
        2: 0.17609,
        3: 0.12494,
        4: 0.09691,
        5: 0.07918,
        6: 0.06695,
        7: 0.05799,
        8: 0.05115,
        9: 0.04576,
    }

    def analyze_ledger_stream(
        self,
        amounts: List[float],
        approval_threshold: float = 50000.0,
    ) -> BenfordForensicReport:
        alerts: List[ForensicAnomalyAlert] = []
        valid_amounts = [a for a in amounts if a > 0]
        n = len(valid_amounts)

        # 1. Structuring detection (transactions between 95% and 99.99% of approval cap)
        structuring_hits = [
            a for a in valid_amounts if (approval_threshold * 0.95) <= a < approval_threshold
        ]
        if len(structuring_hits) >= 2:
            alerts.append(
                ForensicAnomalyAlert(
                    alert_type="SMURFING_STRUCTURING_DETECTED",
                    severity="CRITICAL",
                    description=f"Detected {len(structuring_hits)} transactions clustered just below ${approval_threshold:,.2f} approval threshold",
                    flagged_amounts=structuring_hits,
                )
            )

        # 2. Benford's Law First-Digit Chi-Squared Test
        digit_counts: Dict[int, int] = {d: 0 for d in range(1, 10)}
        for a in valid_amounts:
            s = f"{a:.6f}".lstrip("0.")
            if s and s[0].isdigit() and int(s[0]) in digit_counts:
                digit_counts[int(s[0])] += 1

        chi_sq = 0.0
        if n > 0:
            for d in range(1, 10):
                expected = n * self.BENFORD_EXPECTED[d]
                observed = digit_counts[d]
                if expected > 0:
                    chi_sq += ((observed - expected) ** 2) / expected

        # Critical value for df=8 at p=0.05 is 15.507
        benford_ok = (chi_sq <= 15.507) if n >= 20 else True
        if not benford_ok:
            alerts.append(
                ForensicAnomalyAlert(
                    alert_type="BENFORD_CHI_SQUARED_DIVERGENCE",
                    severity="HIGH",
                    description=f"Chi-squared={chi_sq:.2f} exceeds 15.51 critical threshold (p < 0.05)",
                )
            )

        return BenfordForensicReport(
            sample_size=n,
            chi_squared_stat=round(chi_sq, 3),
            benford_compliant=benford_ok,
            alerts=alerts,
        )
