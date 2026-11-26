# Reproduction Instructions (v3.10.1)

```bash
# 0. Run full automated evidence verification (24/24 SHA-256 manifest, MCP 3-scenario demo, 47 Vitest checks, 176 Rust workspace tests, 16-worker concurrency, 100-case self-heal & adversarial red-team suites)
bash frontend/public/evidence/reproduce.sh

# 1. Run multi-engine adversarial red-team & 64-worker stress proof (40/40 bypass checks, 32x triggers, CASCADE, wrap-odoo, 64w Rust TCP / live PostgreSQL 17 via --pg-url)
node scripts/adversarial-redteam-audit.mjs --no-write
# Or against a live PostgreSQL 17 instance:
# node scripts/adversarial-redteam-audit.mjs --pg-url postgresql://postgres:postgres@127.0.0.1:5432/apodictic_ci --no-write

# 2. Run 16-worker TCP Rust proxy + PostgreSQL 18.7 SAVEPOINT PL/pgSQL trigger concurrency proof
(cd apodictic_infra && cargo build --release --bin apodictic_pg_proxy)
node scripts/pg17-concurrency-benchmark.mjs

# 3. Run 100-case counterfactual self-healing vs blind retry + negative SQL literal clamping benchmark
node scripts/agent-self-heal-benchmark.mjs

# 4. Run 100-case & 10,000-case public Z3 5.4.1 security benchmarks + constraint mutation suite
PYTHONPATH=. python3 apodictic_engine/tests/benchmarks/run_100_case_benchmark.py
PYTHONPATH=. python3 apodictic_engine/tests/benchmarks/run_10k_benchmark.py
PYTHONPATH=. python3 apodictic_engine/tests/benchmarks/run_mutation_suite.py

# 5. Run Python engine 67-test suite (Odoo 20 JSON-2/MCP firewall, ZATCA BR-CO-14, ETA 281, adversarial bypass & negative literal defenses)
PYTHONPATH=. python3 -m unittest discover -s apodictic_engine/tests

# 6. Run SDK & MCP verifier test suites (Zero-Python Z3 5.4.1 WebAssembly, wrap-odoo, & Ed25519 tokens)
node packages/apodictic-sdk/test.mjs
node packages/apodictic-mcp-verifier/test.mjs
APODICTIC_DISABLE_PYTHON=1 node packages/apodictic-mcp-verifier/bin/apodictic-mcp-verifier.mjs demo

# 7. Verify 24-file evidence cryptographic manifest
(cd frontend/public/evidence && shasum -a 256 -c manifest.sha256)

# 8. Type-check, run all 47 Vitest checks across 9 files, and build frontend
(cd frontend && npm run type-check && npx vitest run && npm run build)
```
