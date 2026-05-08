"""Regression test: every CLI subcommand's --help path must succeed.

Argparse silently breaks (exits non-zero, prints traceback) when a new
subcommand is added without a corresponding dispatch entry, or vice
versa. This test exercises every entry registered in __main__.dispatch
and confirms `ccp <cmd> --help` returns 0.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

# Subcommands registered in ccp/__main__.py. Keep alphabetized; updating
# this list is the prompt for "did you wire your new subcommand into
# both the parser AND the dispatch table?"
SUBCOMMANDS = [
    "autoheal",
    "check-updates",
    "doctor",
    "install-config",
    "install-frida",
    "install-rules",
    "install-wrapper",
    "list",
    "patch",
    "rollback",
    "scan",
    "scan-gates",
    "self-update",
    "status",
    "verify",
    "watch",
]


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "ccp", *args],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_top_level_help_lists_every_subcommand():
    out = _run("--help")
    assert out.returncode == 0, out.stderr
    for cmd in SUBCOMMANDS:
        assert cmd in out.stdout, f"{cmd} missing from --help output"


@pytest.mark.parametrize("cmd", SUBCOMMANDS)
def test_subcommand_help_returns_zero(cmd):
    out = _run(cmd, "--help")
    assert out.returncode == 0, (
        f"`ccp {cmd} --help` exit {out.returncode}\n"
        f"stdout: {out.stdout[:200]}\n"
        f"stderr: {out.stderr[:200]}"
    )
    # Subcommand --help contains either 'usage:' or its own metavars.
    assert "usage" in out.stdout.lower(), f"`ccp {cmd} --help` missing 'usage:'"


def test_unknown_subcommand_exits_nonzero():
    out = _run("totally-not-a-command", "--help")
    # argparse exits 2 for unknown args
    assert out.returncode != 0
