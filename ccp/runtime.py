"""Frida runtime hook installer for ccp.

`ccp install-frida` writes the codex-bypass.js agent to ~/.codex/frida/
and a launcher wrapper to ~/.local/bin/codex-frida. The wrapper runs
codex under `frida -f`, attaching the agent before the binary executes.

This is layer 4 of the CCP defense stack: when static binary patching
isn't viable (anti-tamper, re-validation) or sufficient (in-process
gates with no string anchor), the Frida agent overrides at runtime.

This module only handles the install-side wiring. The agent itself
lives at contrib/frida/codex-bypass.js and the wrapper at
contrib/frida/codex-frida-wrapper.sh.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FRIDA_DIR_SRC = REPO_ROOT / "contrib" / "frida"
AGENT_SRC = FRIDA_DIR_SRC / "codex-bypass.js"
WRAPPER_SRC = FRIDA_DIR_SRC / "codex-frida-wrapper.sh"

AGENT_DST_DIR = Path.home() / ".codex" / "frida"
AGENT_DST = AGENT_DST_DIR / "codex-bypass.js"

WRAPPER_DST_DIR = Path.home() / ".local" / "bin"
WRAPPER_DST = WRAPPER_DST_DIR / "codex-frida"


def _check_frida_available() -> tuple[bool, str]:
    """Return (ok, message) describing whether the frida CLI is usable."""
    if shutil.which("frida") is None:
        return False, "frida CLI not on PATH (install: pip install frida-tools)"
    try:
        out = subprocess.run(
            ["frida", "--version"], capture_output=True, text=True, timeout=5, check=False
        )
        if out.returncode != 0:
            return False, f"frida --version exit {out.returncode}: {out.stderr.strip()}"
        return True, f"frida {out.stdout.strip()}"
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, f"frida invocation failed: {exc}"


def install_frida(force: bool = False, verbose: bool = True) -> dict:
    """Deploy the Frida agent + wrapper. Returns a result dict."""
    result = {
        "agent_src": str(AGENT_SRC),
        "agent_dst": str(AGENT_DST),
        "wrapper_src": str(WRAPPER_SRC),
        "wrapper_dst": str(WRAPPER_DST),
        "frida": None,
        "agent_installed": False,
        "wrapper_installed": False,
        "agent_skipped": False,
        "wrapper_skipped": False,
        "errors": [],
    }

    ok, msg = _check_frida_available()
    result["frida"] = msg
    if verbose:
        prefix = "  ok " if ok else "  warn "
        sys.stderr.write(f"{prefix}{msg}\n")

    if not AGENT_SRC.is_file():
        result["errors"].append(f"agent source missing: {AGENT_SRC}")
        return result
    if not WRAPPER_SRC.is_file():
        result["errors"].append(f"wrapper source missing: {WRAPPER_SRC}")
        return result

    AGENT_DST_DIR.mkdir(parents=True, exist_ok=True)
    WRAPPER_DST_DIR.mkdir(parents=True, exist_ok=True)

    if AGENT_DST.exists() and not force:
        result["agent_skipped"] = True
        if verbose:
            sys.stderr.write(f"  skip agent (exists): {AGENT_DST}\n")
    else:
        shutil.copy2(AGENT_SRC, AGENT_DST)
        result["agent_installed"] = True
        if verbose:
            sys.stderr.write(f"  ok   agent  {AGENT_SRC} → {AGENT_DST}\n")

    if WRAPPER_DST.exists() and not force:
        result["wrapper_skipped"] = True
        if verbose:
            sys.stderr.write(f"  skip wrapper (exists): {WRAPPER_DST}\n")
    else:
        shutil.copy2(WRAPPER_SRC, WRAPPER_DST)
        os.chmod(WRAPPER_DST, 0o755)
        result["wrapper_installed"] = True
        if verbose:
            sys.stderr.write(f"  ok   wrapper {WRAPPER_SRC} → {WRAPPER_DST}\n")

    if verbose:
        if result["wrapper_installed"] or result["wrapper_skipped"]:
            sys.stderr.write(f"  run: codex-frida exec '<your prompt>'\n")
            if WRAPPER_DST_DIR not in [Path(p) for p in os.environ.get("PATH", "").split(":") if p]:
                sys.stderr.write(
                    f"  warn  {WRAPPER_DST_DIR} is not on PATH; "
                    f"add to ~/.zshrc or use the absolute path\n"
                )

    return result


def uninstall_frida(verbose: bool = True) -> dict:
    """Remove the installed agent + wrapper."""
    result = {"agent_removed": False, "wrapper_removed": False}
    if AGENT_DST.exists():
        AGENT_DST.unlink()
        result["agent_removed"] = True
        if verbose:
            sys.stderr.write(f"  removed {AGENT_DST}\n")
    if WRAPPER_DST.exists():
        WRAPPER_DST.unlink()
        result["wrapper_removed"] = True
        if verbose:
            sys.stderr.write(f"  removed {WRAPPER_DST}\n")
    return result


__all__ = ["install_frida", "uninstall_frida", "AGENT_SRC", "WRAPPER_SRC"]
