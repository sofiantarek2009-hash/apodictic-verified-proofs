"""
Apodictic Basel III & Corporate Debt Covenant Optimizer.
Uses z3.Optimize to compute the exact maximum safe dollar payout a treasury
can execute without breaching Liquidity Coverage Ratio (LCR >= 100%),
Net Leverage Ratio, or Minimum Statutory Cash Reserve covenants.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List
import z3


@dataclass(frozen=True)
class TreasuryCovenantInput:
    cash_and_hqla_usd: float
    total_debt_usd: float
    ebitda_usd: float
    net_30d_cash_outflows_usd: float
    max_net_leverage_ratio: float = 3.5
    min_lcr_ratio: float = 1.0
    min_cash_reserve_usd: float = 50000.0


@dataclass
class MaxSafePayoutResult:
    feasible: bool
    max_safe_payout_usd: float
    binding_covenant: str
    z3_solve_ms: float


class BaselTreasuryCovenantOptimizer:
    """
    Solves a constrained linear optimization problem via Z3 Optimize:
      Maximize: payout >= 0
      Subject to:
        1. cash - payout >= min_cash_reserve
        2. (cash - payout) / net_30d_outflows >= min_lcr_ratio
        3. (total_debt - (cash - payout)) <= max_net_leverage_ratio * ebitda
    """

    def compute_max_safe_payout(self, inp: TreasuryCovenantInput) -> MaxSafePayoutResult:
        t0 = time.perf_counter()
        ctx = z3.Context()
        opt = z3.Optimize(ctx=ctx)

        z_payout = z3.Real("payout", ctx=ctx)
        z_cash = z3.RealVal(str(inp.cash_and_hqla_usd), ctx=ctx)
        z_debt = z3.RealVal(str(inp.total_debt_usd), ctx=ctx)
        z_ebitda = z3.RealVal(str(inp.ebitda_usd), ctx=ctx)
        z_outflows = z3.RealVal(str(inp.net_30d_cash_outflows_usd), ctx=ctx)
        z_min_res = z3.RealVal(str(inp.min_cash_reserve_usd), ctx=ctx)
        z_min_lcr = z3.RealVal(str(inp.min_lcr_ratio), ctx=ctx)
        z_max_lev = z3.RealVal(str(inp.max_net_leverage_ratio), ctx=ctx)

        opt.add(z_payout >= 0)
        # 1. Minimum reserve floor
        opt.add(z_cash - z_payout >= z_min_res)
        # 2. Basel III LCR: (cash - payout) >= min_lcr * net_30d_outflows
        opt.add(z_cash - z_payout >= z_min_lcr * z_outflows)
        # 3. Net Leverage: total_debt - (cash - payout) <= max_lev * ebitda
        opt.add(z_debt - (z_cash - z_payout) <= z_max_lev * z_ebitda)

        opt.maximize(z_payout)
        res = opt.check()
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        if res != z3.sat:
            return MaxSafePayoutResult(
                feasible=False,
                max_safe_payout_usd=0.0,
                binding_covenant="INFEASIBLE_CURRENT_STATE",
                z3_solve_ms=elapsed_ms,
            )

        model = opt.model()
        val_ref = model[z_payout]
        # Convert Z3 RatNumRef to float
        max_payout = float(val_ref.numerator_as_long()) / float(val_ref.denominator_as_long())
        max_payout = round(max_payout, 2)

        # Identify binding covenant
        rem_cash = inp.cash_and_hqla_usd - max_payout
        lcr_floor = inp.min_lcr_ratio * inp.net_30d_cash_outflows_usd
        lev_floor = inp.total_debt_usd - (inp.max_net_leverage_ratio * inp.ebitda_usd)

        binding = "MIN_CASH_RESERVE"
        if abs(rem_cash - lcr_floor) < 1.0:
            binding = "BASEL_III_LCR"
        elif abs(rem_cash - lev_floor) < 1.0:
            binding = "NET_LEVERAGE_COVENANT"

        return MaxSafePayoutResult(
            feasible=True,
            max_safe_payout_usd=max_payout,
            binding_covenant=binding,
            z3_solve_ms=elapsed_ms,
        )
