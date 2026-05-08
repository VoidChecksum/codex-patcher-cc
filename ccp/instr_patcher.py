"""arm64 / x86_64 instruction-level patcher for ccp.

Companion to the string-anchor `macho_replace`/`binary_replace` patcher in
__main__.py. Where a gate is a control-flow comparison (cmp/b.eq, test/jz,
tbz/cbz) rather than a string constant, the string patcher can't reach it.
This module:

  1. Resolves a byte offset from an anchor_strings + offset_from_anchor pair.
  2. Disassembles a small window at that offset using capstone.
  3. Verifies the expected instruction pattern is present (mnemonic + operands).
  4. Writes the length-preserving replacement bytes (e.g., flip `b.eq` → `b.al`,
     replace `cbz x0, .L` with `b .L`, NOP out a guard branch).

The schema is designed to be safe across codex versions: the anchor string is
stable; the offset_from_anchor is small (±64 bytes typically) and is verified
by re-checking the pre-replacement byte sequence before writing. If the
expected bytes don't match, the patch is skipped, not blindly applied.

Schema (in patches/*.json under `type: "instr_replace"`):

    {
      "id": "...",
      "type": "instr_replace",
      "arch": "arm64",                       // or "x86_64"
      "anchor_strings": ["..."],
      "patches": [
        {
          "anchor": "...",                   // string anchor
          "offset_from_anchor": 0x1234,      // signed; from xref site
          "match_bytes_hex": "1f0001eb",     // expected instr bytes (verifies)
          "match_disasm": "cmp w0, w1",      // human-readable, used in log
          "replace_bytes_hex": "1f2003d5",   // length-preserving replacement
          "replace_disasm": "nop",
          "applied_marker_hex": "1f2003d5",  // bytes to detect already-applied
          "description": "..."
        }
      ]
    }

Resolution flow:
  - find anchor in binary text → base address
  - target_offset = base + offset_from_anchor
  - read len(match_bytes) bytes at target_offset
  - if those bytes == applied_marker_hex → already applied (skip)
  - if those bytes == match_bytes_hex     → apply: write replace_bytes_hex
  - otherwise → skip with reason "byte mismatch (anchor drift?)"
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, Optional

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64

    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False


# ---------------------------------------------------------------------------
# arm64 instruction encoders (length-preserving, used for replacement bytes)
# ---------------------------------------------------------------------------


def arm64_nop() -> bytes:
    """4-byte NOP encoding (D503201F little-endian → 1f2003d5)."""
    return bytes.fromhex("1f2003d5")


def arm64_b(disp: int) -> bytes:
    """Unconditional branch with 26-bit signed displacement in instructions.

    `disp` is in instructions (4-byte units), not bytes. Range: ±32 MiB.
    """
    if not (-(1 << 25) <= disp < (1 << 25)):
        raise ValueError(f"arm64 b: displacement {disp} out of range ±33554432")
    instr = (0b000101 << 26) | (disp & ((1 << 26) - 1))
    return struct.pack("<I", instr)


def arm64_b_al(disp: int) -> bytes:
    """Always-take conditional branch (b.al)."""
    return arm64_b_cond(disp, cond=0b1110)  # AL


def arm64_b_cond(disp: int, cond: int) -> bytes:
    """Conditional branch with 19-bit signed displacement in instructions."""
    if not (-(1 << 18) <= disp < (1 << 18)):
        raise ValueError(f"arm64 b.cond: displacement {disp} out of range ±262144")
    instr = (0b01010100 << 24) | ((disp & ((1 << 19) - 1)) << 5) | (cond & 0xF)
    return struct.pack("<I", instr)


def arm64_movz_w(reg: int, imm16: int) -> bytes:
    """movz wN, #imm16 — zero-extends. Used to force a function to return 0."""
    if not 0 <= reg <= 30:
        raise ValueError("arm64 movz: reg out of range")
    if not 0 <= imm16 <= 0xFFFF:
        raise ValueError("arm64 movz: imm16 out of range")
    instr = (0b010100101 << 23) | (imm16 << 5) | reg
    return struct.pack("<I", instr)


def arm64_ret() -> bytes:
    """ret — branch to LR (X30)."""
    return bytes.fromhex("c0035fd6")


def arm64_force_return_true() -> bytes:
    """8 bytes: movz w0, #1; ret — turn a Rust fn into `() -> bool { true }`."""
    return arm64_movz_w(0, 1) + arm64_ret()


def arm64_force_return_false() -> bytes:
    """8 bytes: movz w0, #0; ret — `() -> bool { false }`."""
    return arm64_movz_w(0, 0) + arm64_ret()


# ---------------------------------------------------------------------------
# Disassembly verification
# ---------------------------------------------------------------------------


def disasm(arch: str, data: bytes, addr: int = 0) -> Iterable[tuple[int, str, str]]:
    """Yield (addr, mnemonic, op_str) for each instruction in `data`."""
    if not HAVE_CAPSTONE:
        return
    if arch == "arm64":
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch in ("x86_64", "x64"):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        raise ValueError(f"unsupported arch: {arch}")
    md.detail = False
    for ins in md.disasm(data, addr):
        yield (ins.address, ins.mnemonic, ins.op_str)


def verify_match(arch: str, expected_hex: str, actual: bytes) -> bool:
    """Confirm `actual` bytes match the expected hex."""
    expected = bytes.fromhex(expected_hex)
    return actual == expected


# ---------------------------------------------------------------------------
# Patch application
# ---------------------------------------------------------------------------


def find_anchor(data: bytes, anchor: str) -> Optional[int]:
    """Return the first byte offset where `anchor` appears in `data`, or None."""
    needle = anchor.encode("utf-8")
    pos = data.find(needle)
    return pos if pos >= 0 else None


def apply_instr_patch(
    data: bytearray,
    arch: str,
    anchor: str,
    offset_from_anchor: int,
    match_bytes_hex: str,
    replace_bytes_hex: str,
    applied_marker_hex: Optional[str] = None,
) -> tuple[bool, str]:
    """Try to apply one instruction-level patch in-place to `data`.

    Returns (applied, reason). `applied` is True only when the bytes were
    actually written. `reason` is a short explanation for the audit trail.
    """
    expected = bytes.fromhex(match_bytes_hex)
    replacement = bytes.fromhex(replace_bytes_hex)

    if len(expected) != len(replacement):
        return False, f"length mismatch: expected={len(expected)} replacement={len(replacement)}"

    anchor_pos = find_anchor(bytes(data), anchor)
    if anchor_pos is None:
        return False, f"anchor not found: {anchor!r}"

    target = anchor_pos + offset_from_anchor
    if target < 0 or target + len(expected) > len(data):
        return False, f"target offset {target:#x} out of bounds"

    actual = bytes(data[target : target + len(expected)])

    # Idempotency: already applied?
    if applied_marker_hex:
        marker = bytes.fromhex(applied_marker_hex)
        if actual == marker:
            return False, f"already applied at {target:#x}"

    if actual != expected:
        return (
            False,
            f"byte mismatch at {target:#x}: have={actual.hex()} expected={expected.hex()} (anchor drift?)",
        )

    data[target : target + len(replacement)] = replacement
    return True, f"applied at {target:#x}: {match_bytes_hex} → {replace_bytes_hex}"


__all__ = [
    "HAVE_CAPSTONE",
    "arm64_nop",
    "arm64_b",
    "arm64_b_al",
    "arm64_b_cond",
    "arm64_movz_w",
    "arm64_ret",
    "arm64_force_return_true",
    "arm64_force_return_false",
    "disasm",
    "verify_match",
    "find_anchor",
    "apply_instr_patch",
]
