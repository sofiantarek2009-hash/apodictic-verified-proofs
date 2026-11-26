#!/usr/bin/env bash
# Apodictic — Independent Reproducibility & Cryptographic Verification Script (v3.10.1)
# Usage: bash frontend/public/evidence/reproduce.sh
set -euo pipefail
[ -d "$HOME/.cargo/bin" ] && export PATH="$HOME/.cargo/bin:$PATH"

echo "=== 1. Verifying 24-Artifact SHA-256 Evidence Manifest ==="
(cd frontend/public/evidence && shasum -a 256 -c manifest.sha256)

echo ""
echo "=== 2. Running 3-Scenario Reproducible MCP Demo (WASM Postgres + Z3 5.4.1) ==="
node packages/apodictic-mcp-verifier/bin/apodictic-mcp-verifier.mjs demo

echo ""
echo "=== 3. Running Frontend Verification Vitest Suite (9 files, 47 checks) ==="
(cd frontend && npx vitest run)

echo ""
echo "=== 4. Running 9-Crate Rust Workspace Tests (176 tests) ==="
(cd apodictic_infra && cargo test --workspace)

echo ""
echo "=== 5. Running 100-Case Counterfactual Self-Heal, 16-Worker PG Concurrency & Red-Team Suites ==="
node scripts/agent-self-heal-benchmark.mjs --no-write 2>/dev/null || node scripts/agent-self-heal-benchmark.mjs
[ -x apodictic_infra/target/release/apodictic_pg_proxy ] || (cd apodictic_infra && cargo build --release --bin apodictic_pg_proxy)
node scripts/pg17-concurrency-benchmark.mjs
node scripts/adversarial-redteam-audit.mjs --no-write

echo ""
echo "ALL APODICTIC PROOFS, BENCHMARKS, AND 24/24 CHECKSUMS VERIFIED."
