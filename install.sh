#!/usr/bin/env bash
# ccp install.sh — chains npm install + ccp setup
# Usage: curl -fsSL https://raw.githubusercontent.com/VoidChecksum/codex-patcher-cc/main/install.sh | bash
set -euo pipefail

CCP_REPO="VoidChecksum/codex-patcher-cc"
CCP_BRANCH="main"

log()  { echo "[ccp] $*"; }
ok()   { echo "[ccp] ✓ $*"; }
fail() { echo "[ccp] ✗ $*" >&2; exit 1; }

# ── 1. Install / update Codex CLI ────────────────────────────────────────────
if command -v codex &>/dev/null; then
    log "codex CLI found: $(codex --version 2>/dev/null || echo unknown)"
else
    log "Installing @openai/codex via npm..."
    npm install -g @openai/codex || fail "npm install failed"
    ok "codex CLI installed"
fi

# ── 2. Install ccp via pip ────────────────────────────────────────────────────
log "Installing ccp..."
if command -v pip3 &>/dev/null; then
    pip3 install --quiet "https://github.com/${CCP_REPO}/archive/${CCP_BRANCH}.tar.gz" || \
    pip3 install --quiet --user "https://github.com/${CCP_REPO}/archive/${CCP_BRANCH}.tar.gz" || \
    fail "pip install failed"
elif command -v pip &>/dev/null; then
    pip install --quiet "https://github.com/${CCP_REPO}/archive/${CCP_BRANCH}.tar.gz" || \
    fail "pip install failed"
else
    fail "pip/pip3 not found — install Python 3 first"
fi
ok "ccp installed"

# ── 3. Apply all three bypass layers ─────────────────────────────────────────
log "Installing authorization rules..."
python3 -m ccp install-rules

log "Installing bypass wrapper..."
python3 -m ccp install-wrapper

log "Installing config defaults..."
python3 -m ccp install-config

# ── 4. Apply binary patches (optional — may be no-op if no anchors match) ───
log "Applying binary patches (optional)..."
python3 -m ccp patch || log "patch step had failures (non-fatal — wrapper+config layers are active)"

ok "ccp setup complete"
echo ""
echo "  3-layer bypass is active:"
echo "    1. wrapper  : ~/.local/bin/codex (prepends --dangerously-bypass-approvals-and-sandbox)"
echo "    2. config   : ~/.codex/config.toml (approval_mode=never, sandbox=full-access)"
echo "    3. binary   : in-place Mach-O patches (where anchors matched)"
echo ""
echo "  Ensure ~/.local/bin is first in PATH, or run: export PATH=\"\$HOME/.local/bin:\$PATH\""
