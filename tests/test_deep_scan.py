"""Tests for ccp.deep_scan — pure-Python parts only.

The radare2 integration is tested implicitly when the operator runs
`ccp scan-gates` or imports the module from a notebook; binary-dependent
tests would couple to a specific codex build and break on every release.
"""

from __future__ import annotations

from ccp import deep_scan as ds


def test_gate_mnemonics_arm64_includes_branch_ops():
    arm64 = ds.GATE_MNEMONICS["arm64"]
    for mnem in ("cmp", "tst", "cbz", "cbnz", "tbz", "tbnz", "b.eq", "b.ne"):
        assert mnem in arm64, f"missing arm64 mnemonic: {mnem}"


def test_gate_mnemonics_x86_64_includes_branch_ops():
    x = ds.GATE_MNEMONICS["x86_64"]
    for mnem in ("cmp", "test", "je", "jne", "jz", "jnz"):
        assert mnem in x, f"missing x86_64 mnemonic: {mnem}"


def test_have_r2_returns_bool():
    assert isinstance(ds.have_r2(), bool)


def test_gate_candidate_dataclass_defaults():
    gc = ds.GateCandidate(
        anchor="foo",
        fn_addr=0x100,
        fn_name="bar",
        fn_size=64,
    )
    assert gc.candidate_offsets == []


def test_render_candidates_empty():
    out = ds.render_candidates([])
    assert "no candidates" in out


def test_render_candidates_one_entry():
    gc = ds.GateCandidate(
        anchor="ApprovalDenied",
        fn_addr=0x12340,
        fn_name="codex_core::approval::check",
        fn_size=128,
        candidate_offsets=[(0x10, "cmp w0, w1"), (0x14, "b.eq 0x12380")],
    )
    out = ds.render_candidates([gc])
    assert "ApprovalDenied" in out
    assert "codex_core::approval::check" in out
    assert "cmp w0, w1" in out
    assert "+0x0010" in out


def test_xref_hit_dataclass_optional_fields():
    h = ds.XrefHit(string_addr=0x1, string_value="x", xref_addr=0x2)
    assert h.fn_addr is None
    assert h.fn_name is None
