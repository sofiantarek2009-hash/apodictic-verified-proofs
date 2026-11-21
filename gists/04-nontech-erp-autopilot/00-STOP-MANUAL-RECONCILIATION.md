# Why Finance Teams Spend 40 Hours a Week Matching Invoices, Warehouse Receipts, and Bank Wires — And How Apodictic Automates It With Zero Guesswork

> **Who This Is For**: Non-technical founders, Heads of Finance, Procurement Leads, and Operations Executives.

---

## The Everyday Finance Headache

In a real business, financial records never sit cleanly in one place:
- **Purchase Orders** sit in **SAP or NetSuite**.
- **Warehouse delivery slips** sit in **Odoo**.
- **Vendor bills** arrive by email or PDF.
- **Cash wires** land in the corporate bank account as lump sums with wire fees deducted.

Human accountants spend weeks checking: *"Did we actually receive all 10 servers before paying the vendor's 10-server bill?"* and *"Which subset of customer invoices make up this `$84,975` mystery wire from JPMorgan?"*

---

## 4 Expensive Problems Apodictic Solves Automatically

### 1. Catching "Phantom Billing" (Automated 3-Way Match)
- **Scenario**: You ordered `10` GPU servers at `$42,000` each. Your warehouse only signed for **`8` deliveries**, yet the supplier sends a bill for **`10` units**.
- **What Apodictic Does**: Automatically cross-checks the Purchase Order, Warehouse Receipt, and Invoice in milliseconds—blocking the over-bill immediately while allowing partial payment for the `8` units that actually arrived (even with minor approved price tolerances like `±2%`).

### 2. Solving "Mystery Bank Wires" in Milliseconds
- **Scenario**: A corporate customer owes you for 4 separate invoices (`$31,500`, `$50,000`, `$35,000`, `$19,200`). They send one combined bank wire of **`$84,975`**, and the bank took a **`$25` wire fee**.
- **What Apodictic Does**: Instantly calculates which exact invoices sum to `$85,000` (`Invoice #2 + Invoice #3`), accounts for the `$25` wire fee automatically, and closes both invoices cleanly—no spreadsheets required.

### 3. Stopping Insider Approval Loops & Shell-Company Carousels
- **Scenario**: An employee adds a new vendor to NetSuite and tries to approve a `$45,600` invoice to that same vendor—or money moves in a circle across three foreign subsidiaries (`US -> Cyprus -> Malta -> US`).
- **What Apodictic Does**: Flags circular money-movement loops across your corporate family tree and blocks any self-approval or missing executive co-signature before money moves.

### 4. Answering "What Is the Maximum Cash We Can Safely Pay Today?"
- **Scenario**: A CFO has `$2,000,000` in cash, `$5,000,000` in debt, bank loan covenants capped at `3.0x` net leverage, and `$850,000` of upcoming 30-day obligations.
- **What Apodictic Does**: Instead of guessing in Excel, Apodictic solves every loan covenant and liquidity rule simultaneously and gives one exact number: **`$1,150,000.00`** maximum safe payout before hitting the bank's liquidity guardrail.

---

## Verify Live in 2 Seconds (Executable 3-Way Match & Subset-Sum Proof)

```bash
pip install z3-solver && python3 02-THREE-WAY-MATCH-AND-BANK-WIRE-PROOF.py
```

