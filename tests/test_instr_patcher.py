"""Tests for ccp.instr_patcher — arm64 instruction encoders + patch application."""

from __future__ import annotations

import pytest

from ccp import instr_patcher as ip


def test_arm64_nop_encoding():
    assert ip.arm64_nop().hex() == "1f2003d5"


def test_arm64_ret_encoding():
    assert ip.arm64_ret().hex() == "c0035fd6"


def test_arm64_movz_w_zero_into_w0():
    # movz w0, #0 → 0x52800000 little-endian → 00 00 80 52
    assert ip.arm64_movz_w(0, 0).hex() == "00008052"


def test_arm64_movz_w_one_into_w0():
    # movz w0, #1 → 0x52800020 little-endian → 20 00 80 52
    assert ip.arm64_movz_w(0, 1).hex() == "20008052"


def test_arm64_force_return_true_is_8_bytes():
    bs = ip.arm64_force_return_true()
    assert len(bs) == 8
    # movz w0, #1; ret
    assert bs.hex() == "20008052c0035fd6"


def test_arm64_force_return_false_is_8_bytes():
    bs = ip.arm64_force_return_false()
    assert len(bs) == 8
    assert bs.hex() == "00008052c0035fd6"


def test_arm64_b_zero_displacement():
    # b .+0 → 0x14000000 little-endian → 00 00 00 14
    assert ip.arm64_b(0).hex() == "00000014"


def test_arm64_b_displacement_range_validation():
    with pytest.raises(ValueError):
        ip.arm64_b(1 << 25)  # too large
    with pytest.raises(ValueError):
        ip.arm64_b(-(1 << 26))  # too small (use signed range)


def test_arm64_movz_w_register_range_validation():
    with pytest.raises(ValueError):
        ip.arm64_movz_w(31, 0)  # x31 is sp/xzr, not a normal reg target


def test_apply_instr_patch_anchor_not_found():
    data = bytearray(b"hello world")
    applied, reason = ip.apply_instr_patch(
        data,
        arch="arm64",
        anchor="missing_anchor",
        offset_from_anchor=0,
        match_bytes_hex="00000000",
        replace_bytes_hex="1f2003d5",
    )
    assert applied is False
    assert "anchor not found" in reason


def test_apply_instr_patch_byte_mismatch_skips():
    # anchor "FOO" at offset 0, then 4 bytes of garbage
    data = bytearray(b"FOO" + bytes.fromhex("aabbccdd"))
    applied, reason = ip.apply_instr_patch(
        data,
        arch="arm64",
        anchor="FOO",
        offset_from_anchor=3,
        match_bytes_hex="11223344",  # doesn't match aabbccdd
        replace_bytes_hex="1f2003d5",
    )
    assert applied is False
    assert "byte mismatch" in reason
    # data unchanged
    assert bytes(data) == b"FOO" + bytes.fromhex("aabbccdd")


def test_apply_instr_patch_writes_replacement():
    # anchor "FOO" at offset 0; "match" is 4 bytes of cmp w0,w1; replace with nop
    cmp_w0_w1 = bytes.fromhex("1f0001eb")  # cmp w0, w1 (from arm64 ref)
    data = bytearray(b"FOO" + cmp_w0_w1)
    applied, reason = ip.apply_instr_patch(
        data,
        arch="arm64",
        anchor="FOO",
        offset_from_anchor=3,
        match_bytes_hex=cmp_w0_w1.hex(),
        replace_bytes_hex=ip.arm64_nop().hex(),
    )
    assert applied is True
    assert "applied" in reason
    assert bytes(data) == b"FOO" + ip.arm64_nop()


def test_apply_instr_patch_idempotent_via_marker():
    # already-applied state: marker bytes already at target
    nop = ip.arm64_nop()
    data = bytearray(b"FOO" + nop)
    applied, reason = ip.apply_instr_patch(
        data,
        arch="arm64",
        anchor="FOO",
        offset_from_anchor=3,
        match_bytes_hex="1f0001eb",  # cmp w0, w1 (would-be original)
        replace_bytes_hex=nop.hex(),
        applied_marker_hex=nop.hex(),
    )
    assert applied is False
    assert "already applied" in reason


def test_apply_instr_patch_length_mismatch_rejected():
    data = bytearray(b"FOO" + bytes.fromhex("11223344"))
    applied, reason = ip.apply_instr_patch(
        data,
        arch="arm64",
        anchor="FOO",
        offset_from_anchor=3,
        match_bytes_hex="11223344",
        replace_bytes_hex="1122",  # 2 bytes vs 4
    )
    assert applied is False
    assert "length mismatch" in reason


@pytest.mark.skipif(not ip.HAVE_CAPSTONE, reason="capstone not installed")
def test_disasm_nop_recognized():
    insns = list(ip.disasm("arm64", ip.arm64_nop()))
    assert len(insns) == 1
    _addr, mnem, _ops = insns[0]
    assert mnem == "nop"


@pytest.mark.skipif(not ip.HAVE_CAPSTONE, reason="capstone not installed")
def test_disasm_movz_recognized():
    insns = list(ip.disasm("arm64", ip.arm64_force_return_true()))
    assert len(insns) == 2
    assert insns[0][1] == "mov"  # movz wN, #imm decodes as mov
    assert insns[1][1] == "ret"


@pytest.mark.skipif(not ip.HAVE_CAPSTONE, reason="capstone not installed")
def test_disasm_unknown_arch_raises():
    with pytest.raises(ValueError):
        list(ip.disasm("riscv", b"\x00\x00\x00\x00"))
