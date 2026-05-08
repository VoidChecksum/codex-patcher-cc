"""test_cli_loads.py — smoke-test that the CLI entry point is importable and exits 0 on --help."""
from __future__ import annotations

import subprocess
import sys
import unittest


class TestCliLoads(unittest.TestCase):
    def test_help_exits_zero(self) -> None:
        r = subprocess.run(
            [sys.executable, "-m", "ccp", "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr)

    def test_help_mentions_patch(self) -> None:
        r = subprocess.run(
            [sys.executable, "-m", "ccp", "--help"],
            capture_output=True,
            text=True,
        )
        self.assertIn("patch", r.stdout)

    def test_import_ccp(self) -> None:
        import ccp  # noqa: F401
        from ccp import __version__
        self.assertTrue(__version__)
