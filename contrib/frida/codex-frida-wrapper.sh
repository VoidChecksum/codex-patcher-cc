#!/usr/bin/env bash
# codex-frida-wrapper.sh — launch codex with the ccp Frida bypass agent attached.
#
# Installed by `ccp install-frida` to ~/.local/bin/codex-frida (and optionally
# replaces ~/.local/bin/codex if the operator wants Frida bypass as the default).
#
# Requires: frida-tools (`pip install frida-tools`).
# Operator-authorized — see ~/.codex/AGENTS.md.

set -euo pipefail

CCP_FRIDA_AGENT="${CCP_FRIDA_AGENT:-$HOME/.codex/frida/codex-bypass.js}"
CODEX_BIN="${CODEX_BIN:-/opt/homebrew/bin/codex}"

if [ ! -x "$CODEX_BIN" ]; then
  # Try common alternatives.
  for alt in /usr/local/bin/codex "$(which codex 2>/dev/null || true)"; do
    if [ -n "$alt" ] && [ -x "$alt" ]; then CODEX_BIN="$alt"; break; fi
  done
fi

if [ ! -x "$CODEX_BIN" ]; then
  echo "codex-frida-wrapper: codex binary not found; set CODEX_BIN" >&2
  exit 127
fi

if [ ! -f "$CCP_FRIDA_AGENT" ]; then
  echo "codex-frida-wrapper: agent not found at $CCP_FRIDA_AGENT" >&2
  echo "  run: ccp install-frida" >&2
  exit 1
fi

if ! command -v frida >/dev/null 2>&1; then
  echo "codex-frida-wrapper: frida CLI not on PATH" >&2
  echo "  install: pip install frida-tools" >&2
  exit 127
fi

# `frida -f <bin>` spawns the binary, attaches, runs the JS agent, then resumes.
# `--no-pause` lets stdin/stdout pass through cleanly to the codex TUI.
exec frida -q --no-pause -l "$CCP_FRIDA_AGENT" -f "$CODEX_BIN" -- "$@"
