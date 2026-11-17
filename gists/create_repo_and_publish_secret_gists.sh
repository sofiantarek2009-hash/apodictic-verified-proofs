#!/usr/bin/env bash
set -euo pipefail

# One-command setup to:
#   1. Authenticate GitHub CLI (if needed) with `repo` and `gist` scopes
#   2. Create a brand-new standalone GitHub repository containing all 9 verified proof bundles
#      plus a GitHub Actions CI workflow that executes every standalone Z3 / Odoo-ETA proof
#   3. Publish all 9 multi-file bundles as GitHub SECRET Gists (unlisted, link-shareable)

GH_BIN="${GH_BIN:-$(command -v gh || echo "$HOME/.local/bin/gh")}"
REPO_NAME="${1:-noesis-verified-proofs}"
VISIBILITY="${2:---public}" # Pass "--private" if you prefer private + Secret Gist links

if [[ ! -x "$GH_BIN" ]]; then
  echo "Error: gh CLI not found. Install https://cli.github.com/ or check ~/.local/bin/gh"
  exit 1
fi

if ! "$GH_BIN" auth status >/dev/null 2>&1; then
  echo "GitHub authentication required. Launching browser OAuth login..."
  "$GH_BIN" auth login --hostname github.com --git-protocol https --web -s gist,repo
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TMP_REPO="$(mktemp -d)"
trap 'rm -rf "$TMP_REPO"' EXIT

cp -R "$REPO_ROOT/gists" "$TMP_REPO/gists"
rm -f "$TMP_REPO/gists/PUBLISHED_SECRET_GISTS.txt"

cat > "$TMP_REPO/requirements.txt" <<'EOF'
z3-solver>=4.13
EOF

cat > "$TMP_REPO/README.md" <<'EOF'
# Apodictic — Verified Architecture & Executable Domain Proofs

> Nine standalone multi-file proof bundles spanning PostgreSQL 3.0 wire interception, Zero-PII bijective sanitization, live Odoo 18 JSON-RPC 2.0 + Egypt ETA v1.0 invoice verification, Z3 `5.4.1` statutory/solvency invariants, multicurrency FX split-brain compensation, ZATCA `BR-CO-14` halala parity, and multi-turn smurfing defense.

See [`gists/README.md`](./gists/README.md) for the complete index, or run every bundle cleanly via:

```bash
pip install -r requirements.txt
for f in gists/*/*.py; do echo "=== $f ==="; python3 "$f"; done
```
EOF

mkdir -p "$TMP_REPO/.github/workflows"
cat > "$TMP_REPO/.github/workflows/verify-proofs.yml" <<'EOF'
name: Verify All Standalone Z3 & Odoo-ETA Proofs
on: [push, pull_request, workflow_dispatch]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: |
          set -e
          for f in gists/*/*.py; do
            echo "=== Running $f ==="
            python3 "$f"
          done
EOF

pushd "$TMP_REPO" >/dev/null
git init -b main
git add -A
git commit -m "feat: add 9 standalone Z3 5.4.1 & live Odoo 18 + Egypt ETA v1.0 proof bundles"
"$GH_BIN" repo create "$REPO_NAME" "$VISIBILITY" --source=. --remote=origin --push
popd >/dev/null

echo ""
echo "Publishing all 9 bundles as GitHub SECRET Gists (unlisted from search engines)..."
GH_BIN="$GH_BIN" PATH="$(dirname "$GH_BIN"):$PATH" bash "$REPO_ROOT/gists/publish_all_gists.sh"

echo ""
echo "Done! Verify each Secret Gist link in an Incognito browser window before sharing:"
cat "$REPO_ROOT/gists/PUBLISHED_SECRET_GISTS.txt"
