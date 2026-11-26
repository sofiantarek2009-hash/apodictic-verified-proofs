# Reproduction Instructions (v3.11.0)

```bash
# 0. Run full automated evidence verification (26/26 SHA-256 manifest, MCP 3-scenario demo, 49 Vitest checks, 182 Rust workspace tests, 1M wire fuzzer, 16w & 64w PG17 concurrency, 100-case self-heal & adversarial red-team suites)
bash frontend/public/evidence/reproduce.sh

# 1. Run 1,000,000-iteration PostgreSQL v3.0 wire-parser fuzzer & verify offline server-room tarball
(cd apodictic_infra && cargo build --release --bin apodictic_wire_fuzzer --bin apodictic_pg_proxy --bin apodictic_rust_kernel)
./apodictic_infra/target/release/apodictic_wire_fuzzer --iterations 1000000

# 2. Run multi-engine adversarial red-team & 64-worker stress proof (40/40 bypass checks, 32x triggers, CASCADE, wrap-odoo, 64w Rust TCP / live PostgreSQL 17 via --pg-url)
node scripts/adversarial-redteam-audit.mjs --no-write
# Or against a live PostgreSQL 17 instance:
# node scripts/adversarial-redteam-audit.mjs --pg-url postgresql://postgres:postgres@127.0.0.1:5432/apodictic_ci --no-write

# 3. Run 16-worker TCP Rust proxy + PostgreSQL 18.7 SAVEPOINT PL/pgSQL trigger concurrency proof
node scripts/pg17-concurrency-benchmark.mjs

# 4. Run 100-case counterfactual self-healing vs blind retry + negative SQL literal clamping benchmark
node scripts/agent-self-heal-benchmark.mjs

# 5. Run 100-case & 10,000-case public Z3 5.4.1 security benchmarks + constraint mutation suite
PYTHONPATH=. python3 apodictic_engine/tests/benchmarks/run_100_case_benchmark.py
PYTHONPATH=. python3 apodictic_engine/tests/benchmarks/run_10k_benchmark.py
PYTHONPATH=. python3 apodictic_engine/tests/benchmarks/run_mutation_suite.py

# 6. Run Python engine + Odoo 18-20 partner addon 72-test suite
PYTHONPATH=. python3 -m unittest discover -s apodictic_engine/tests

# 7. Run SDK & MCP verifier test suites (Zero-Python Z3 WASM, schema init, audit-report HTML, LangGraph/OpenAI/Vercel AI adapters, Slack/Teams HMAC webhooks)
node packages/apodictic-sdk/test.mjs
node packages/apodictic-mcp-verifier/test.mjs
APODICTIC_DISABLE_PYTHON=1 node packages/apodictic-mcp-verifier/bin/apodictic-mcp-verifier.mjs demo

# 8. Verify 26-file evidence cryptographic manifest
(cd frontend/public/evidence && shasum -a 256 -c manifest.sha256)

# 9. Type-check, run all 49 Vitest checks across 10 files, and build frontend
(cd frontend && npm run type-check && npx vitest run && npm run build)
```
