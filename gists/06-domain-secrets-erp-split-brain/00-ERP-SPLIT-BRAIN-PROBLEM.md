# Why HTTP Idempotency Keys Corrupt General Ledgers (And How Shadow-State Z3 Compensation Fixes It)

> **Domain Secret**: Most agent startups assume "add an `Idempotency-Key` header and retry on failure." That works for Stripe charges—**it destroys production ERPs** (Odoo 18, NetSuite, SAP S/4HANA).

---

## Why Naive Retries & `DELETE` Statements Fail Inside Real ERPs

When an autonomous agent commits step 1 of an intercompany settlement across multiple ERPs, three stateful ERP invariants immediately lock the ledger:

1. **Posted Ledger Immutability**: Once an Odoo `account.move` (`state = 'posted'`) or SAP `BKPF` document is assigned a statutory sequence number (`INV/2026/00412`), `DELETE FROM account_move` is legally and structurally forbidden—the ORM raises a hard integrity exception or breaks hash sequence continuity.
2. **Partial Reconciliation Links (`account.partial.reconcile`)**: If a wire settles part of an invoice across two currencies (`USD -> EGP`), the ERP locks currency exchange gain/loss lines (`account.exchange.move`). Retrying the transaction creates orphan un-reconciled suspense balances; deleting it leaves broken foreign keys.
3. **Multicurrency FX Rate Drift Between T0 and T1**: If a `$40,000` invoice is booked at `49.20 EGP/USD` (`1,968,000 EGP`) and reversed two hours later when the central bank feed ticks to `49.35 EGP/USD`, a naive quantity reversal creates a **`6,000 EGP` phantom FX loss** unless the exact originating spot rate basis is preserved or explicitly booked to the realized FX gain/loss GL account.

---

## How Apodictic Handles It Deterministically

Before mutating any ERP record, Apodictic checks via Z3 `QF_LRA`:
1. **Fiscal Period Lock Guard**: `fiscal_period_open == True` and `period_lock_date < posting_date`.
2. **Exact Base-Currency Balanced Settlement**:  
   $$\text{Debit}_{\text{USD}} \cdot r_{0} - \text{Credit}_{\text{EGP}} + \Delta_{\text{FX\_Realized}} == 0$$
3. **Analytic Dimension & Mirror Reversal Synthesis**: Generates an exact `account.move.reversal` preserving original spot rate `r_0`, analytic tags, and sequence audit linkage—with zero phantom FX drift.
