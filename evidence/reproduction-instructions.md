# Reproduction Instructions (v3.10.0)

```bash
# 0. Run full automated evidence verification (22/22 SHA-256 manifest, MCP 3-scenario demo, 47 Vitest checks, 176 Rust workspace tests, 16-worker concurrency & 100-case self-heal benchmarks)
bash frontend/public/evidence/reproduce.sh

# 1. Run 16-worker TCP Rust proxy + PostgreSQL 18.7 SAVEPOINT PL/pgSQL trigger concurrency proof
(cd apodictic_infra && cargo build --release --bin apodictic_pg_proxy)
node scripts/pg17-concurrency-benchmark.mjs

# 2. Run 100-case counterfactual self-healing vs blind retry + negative SQL literal clamping benchmark
node scripts/agent-self-heal-benchmark.mjs

# 3. Run 100-case & 10,000-case public Z3 5.4.1 security benchmarks + constraint mutation suite
PYTHONPATH=. python3 apodictic_engine/tests/benchmarks/run_100_case_benchmark.py
PYTHONPATH=. python3 apodictic_engine/tests/benchmarks/run_10k_benchmark.py
PYTHONPATH=. python3 apodictic_engine/tests/benchmarks/run_mutation_suite.py

# 4. Run Python engine 66-test suite (Odoo 20 JSON-2/MCP firewall, ZATCA BR-CO-14, ETA 281, negative literal defenses)
PYTHONPATH=. python3 -m unittest discover -s apodictic_engine/tests

# 5. Run SDK & MCP verifier test suites (Zero-Python Z3 5.4.1 WebAssembly, wrap-odoo, & Ed25519 tokens)
node packages/apodictic-sdk/test.mjs
node packages/apodictic-mcp-verifier/test.mjs
APODICTIC_DISABLE_PYTHON=1 node packages/apodictic-mcp-verifier/bin/apodictic-mcp-verifier.mjs demo

# 6. Verify 22-file evidence cryptographic manifest
(cd frontend/public/evidence && shasum -a 256 -c manifest.sha256)

# 7. Type-check, run all 47 Vitest checks across 9 files, and build frontend
(cd frontend && npm run type-check && npx vitest run && npm run build)
```
