"""test_patches_have_required_fields.py — every patch must have id, description, type."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

PATCH_DIR = Path(__file__).resolve().parents[1] / "patches"
REQUIRED_FIELDS = ("id", "description", "type")


class TestPatchesHaveRequiredFields(unittest.TestCase):
    def test_required_fields_present(self) -> None:
        files = sorted(PATCH_DIR.glob("*.json"))
        self.assertTrue(len(files) > 0, "no patch files found")
        for f in files:
            with self.subTest(file=f.name):
                data = json.loads(f.read_text(encoding="utf-8"))
                for field in REQUIRED_FIELDS:
                    self.assertIn(field, data, msg=f"{f.name} missing '{field}'")

    def test_type_values_known(self) -> None:
        known = {"macho_replace", "config_toml", "wrapper"}
        files = sorted(PATCH_DIR.glob("*.json"))
        for f in files:
            with self.subTest(file=f.name):
                data = json.loads(f.read_text(encoding="utf-8"))
                self.assertIn(data.get("type"), known,
                              msg=f"{f.name} has unknown type {data.get('type')!r}")
