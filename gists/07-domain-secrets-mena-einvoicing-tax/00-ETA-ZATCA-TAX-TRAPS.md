# Mixed-Tax Cascades, WHT Settlement Timing & ZATCA `BR-CO-14` Header Rounding Drift

> **Domain Secret**: US/EU accounting automation assumes tax equals `subtotal * vat_rate`. Deploying that formula on real **Egypt ETA v1.0** or **Saudi ZATCA Phase 2** B2B invoices produces systemic government rejections and audit penalties.

---

## Three Failure Modes That Break Flat-Tax Models

### 1. Compound Tax Base Cascades (Egypt ETA `T2` Table Tax + `T1` 14% VAT)
- In Egypt ETA e-invoicing, taxable services carrying **Table Tax (`T2`, e.g., 5% or 8%)** are subject to **Value Added Tax (`T1`, 14%) applied on top of `(Net + T2)`**, not just on `Net`!
- Computing `Net * 0.14` systematically understates legal output VAT and fails ETA submission validation.

### 2. Withholding Tax (`T4`) Timing Mismatch (Accrual vs. Payment Settlement)
- Suppliers do **not** deduct corporate Withholding Tax (`T4`: `1%` contracting/supplies, `3%` trading services, `5%` engineering/consulting) when recognizing VAT revenue at invoice issuance; instead, the **buyer** withholds `T4` on the **net taxable base (excluding VAT)** when dispatching cash settlement, issuing a statutory withholding certificate for the difference:
  $$\text{Cash\_Paid} + \text{WHT}_{T4} == \text{Gross\_Invoice\_Receivable}$$

### 3. The 1-Halala / 1-Piastre Rounding Drift (`ZATCA BR-CO-14`)
- Suppose an invoice has `3` line items each priced at `10.03 SAR` with `15% VAT` (`1.5045 SAR` per line):
  - Sum of individually rounded line taxes (`1.50 * 3`) = **`4.50 SAR`**.
  - Header tax calculated from header net (`30.09 * 0.15 = 4.5135`) = **`4.51 SAR`** (**`0.01 SAR` / 1-halala mismatch!**)
- ZATCA Phase 2 immediately rejects the UBL 2.1 XML invoice under rule **`BR-CO-14`** because document-level VAT total differs from the sum of rounded line VAT totals by `0.01 SAR`.

Apodictic solves the exact halala/piastre distribution and `T1/T2/T4` cash conservation inside Z3 `QF_LRA` before signing the invoice UUID XML.
