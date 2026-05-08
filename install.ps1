# ccp install.ps1 — Windows equivalent of install.sh
# Usage: iex (iwr https://raw.githubusercontent.com/VoidChecksum/codex-patcher-cc/main/install.ps1).Content
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CCP_REPO   = "VoidChecksum/codex-patcher-cc"
$CCP_BRANCH = "main"

function log($msg)  { Write-Host "[ccp] $msg" }
function ok($msg)   { Write-Host "[ccp] OK  $msg" -ForegroundColor Green }
function fail($msg) { Write-Host "[ccp] ERR $msg" -ForegroundColor Red; exit 1 }

# 1. Install / update Codex CLI
if (Get-Command codex -ErrorAction SilentlyContinue) {
    log "codex CLI found"
} else {
    log "Installing @openai/codex via npm..."
    npm install -g @openai/codex
    ok "codex CLI installed"
}

# 2. Install ccp
log "Installing ccp..."
$tarUrl = "https://github.com/$CCP_REPO/archive/$CCP_BRANCH.tar.gz"
pip install --quiet $tarUrl
ok "ccp installed"

# 3. Apply bypass layers
log "Installing authorization rules..."
python -m ccp install-rules

log "Installing bypass wrapper..."
python -m ccp install-wrapper

log "Installing config defaults..."
python -m ccp install-config

# 4. Apply binary patches
log "Applying binary patches (optional)..."
python -m ccp patch

ok "ccp setup complete"
Write-Host ""
Write-Host "  Bypass layers active: wrapper + config + binary patches"
Write-Host "  Run: codex --help  to verify"
