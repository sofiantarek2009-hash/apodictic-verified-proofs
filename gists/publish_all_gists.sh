#!/usr/bin/env bash
set -euo pipefail

# Publishes all 10 Apodictic technical proof bundles as GitHub SECRET Gists
# (unlisted from search engines and public profiles, directly viewable via URL).
if ! command -v gh >/dev/null 2>&1; then
  echo "Error: GitHub CLI (gh) is not installed. Install from https://cli.github.com/ and run 'gh auth login'."
  exit 1
fi

OUT_FILE="gists/PUBLISHED_SECRET_GISTS.txt"
: > "$OUT_FILE"

publish_secret_gist() {
  local title="$1"
  local dir="$2"
  echo "Publishing Secret Gist: $title"
  local url
  url=$(gh gist create -d "$title" "$dir"/* | tail -n 1)
  echo "  -> $url"
  echo "$title | $url" >> "$OUT_FILE"
}

publish_secret_gist "Apodictic — Enterprise Formal Verification Architecture & Rust/Z3 Kernel Proofs" "gists/01-apodictic-main-architecture-showcase"
publish_secret_gist "Apodictic — Critical Path (PG Wire -> ZeroPII -> Z3 -> WORM Vault) & Multi-ERP Lifecycle" "gists/02-critical-path-multi-erp-lifecycle"
publish_secret_gist "Apodictic — AI Financial Safety Net (Bijective PII Sanitization & Solvency Veto Proof)" "gists/03-nontech-ai-financial-safety-net"
publish_secret_gist "Apodictic — Autonomous 3-Way Match, Subset-Sum Bank Clearing & Basel III Optimizer" "gists/04-nontech-erp-autopilot"
publish_secret_gist "Apodictic — Bi-Temporal Time-Travel Ledger & SEC 17a-4 Tamper Detection Proof" "gists/05-nontech-audit-in-one-second"
publish_secret_gist "Apodictic — Multicurrency ERP Split-Brain & FX Drift Reversal Compensation Proof" "gists/06-domain-secrets-erp-split-brain"
publish_secret_gist "Apodictic — Egypt ETA Compound T2/T1 Taxes, T4 WHT & ZATCA BR-CO-14 Halala Parity" "gists/07-domain-secrets-mena-einvoicing-tax"
publish_secret_gist "Apodictic — Indirect OCR Prompt Injection & Multi-Turn 24h Smurfing Defense" "gists/08-domain-secrets-multi-turn-smurfing-defense"
publish_secret_gist "Apodictic — Live Odoo 18-20 (/jsonrpc & /json/2/) & Egypt ETA v1.0 Real Invoice Workflow" "gists/09-live-odoo-eta-invoice-pipeline"
publish_secret_gist "Apodictic — Odoo 20 JSON-2 & MCP Agentic ERP Firewall Proofs" "gists/10-odoo20-mcp-json2-firewall"

echo "All 10 Secret Gist URLs saved to $OUT_FILE"
