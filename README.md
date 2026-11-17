# Apodictic — Public Verification Harness & CI Attestations

> **Public verification suite and GitHub Actions CI attestation logs for Apodictic.**
>
> The proprietary Apodictic core engine (`noesis_engine/`, `noesis_infra/` Rust workspace, and enterprise ERP adapters) resides in a private repository. This public repository contains standalone executable Z3 `5.4.1` proof bundles, the public `@apodictic/sdk` & `@apodictic/mcp-verifier` interfaces, and reproducible CI test logs.

## Run Locally
```bash
pip install -r requirements.txt
for f in gists/*/*.py; do echo "=== $f ==="; python3 "$f"; done
```
