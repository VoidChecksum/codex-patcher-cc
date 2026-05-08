#!/usr/bin/env bash
# scripts/dev-verify.sh — run the full local verification stack.
#
# Mirrors what CI runs in .github/workflows/ci.yml so you can catch
# failures before pushing. Exits non-zero on any step failure.
#
# Usage:
#   ./scripts/dev-verify.sh           — run everything
#   ./scripts/dev-verify.sh --quick   — skip pytest (lint + smoke only)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

C_OK="\033[32m✓\033[0m"
C_RUN="\033[34m·\033[0m"
C_ERR="\033[31m✗\033[0m"

step() {
  echo -e "$C_RUN $1"
}

ok() {
  echo -e "$C_OK $1"
}

fail() {
  echo -e "$C_ERR $1" >&2
  exit 1
}

step "AST parse all Python sources"
python3 -m compileall -q ccp tests >/dev/null
ok "  AST clean"

step "Validate patch JSON files"
python3 - <<'EOF'
import json, sys
from pathlib import Path
errs = []
for f in sorted(Path("patches").glob("*.json")):
    try:
        d = json.loads(f.read_text())
        for field in ("id", "description", "type"):
            if field not in d:
                errs.append(f"{f.name}: missing '{field}'")
    except json.JSONDecodeError as e:
        errs.append(f"{f.name}: {e}")
if errs:
    print("\n".join(errs)); sys.exit(1)
print(f"  {len(list(Path('patches').glob('*.json')))} patch files valid")
EOF
ok "  patch JSON valid"

step "CLI smoke (--help, list)"
python3 -m ccp --help >/dev/null
python3 -m ccp list >/dev/null
ok "  CLI loads"

step "Lint (ruff)"
if command -v ruff >/dev/null 2>&1 || python3 -c "import ruff" 2>/dev/null; then
  IGNORE="E501,E701,E702,E731,E741,E221,E222,E225,E226,E227,E228,E231,E241,E251,E261,E265,E266,E271,E272,E275,E301,E302,E303,E305,E306,W291,W292,W293,W391,W605,F401,F541,F841"
  python3 -m ruff check ccp/ tests/ --select F --ignore "$IGNORE" || fail "ruff failed"
  ok "  ruff clean (F-codes only)"
else
  echo "  (ruff not installed — skipping lint; pip install ruff)"
fi

if [ "$QUICK" = "1" ]; then
  ok "dev-verify --quick complete (skipped pytest)"
  exit 0
fi

step "pytest"
python3 -m pytest tests/ -q
ok "  all tests pass"

ok "dev-verify complete"
