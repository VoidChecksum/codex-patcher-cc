"""test_patches_valid_json.py — every patches/*.json must parse cleanly."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

PATCH_DIR = Path(__file__).resolve().parents[1] / "patches"


class TestPatchesValidJson(unittest.TestCase):
    def test_all_json_parses(self) -> None:
        files = sorted(PATCH_DIR.glob("*.json"))
        self.assertTrue(len(files) > 0, "no patch files found")
        for f in files:
            with self.subTest(file=f.name):
                data = json.loads(f.read_text(encoding="utf-8"))
                self.assertIsInstance(data, dict)
