"""Unit tests for ccp.__main__._binary_format magic-byte detector.

The patcher dispatches to format-specific section parsers based on this
function. Mis-detection means the wrong section bounds, which means the
regex search hits relocation/import-table garbage and either crashes or
produces silent corruption.
"""

from __future__ import annotations

import struct

import pytest

from ccp.__main__ import _binary_format


# ---------------------------------------------------------------------------
# Mach-O magic numbers (Apple's loader.h)
# ---------------------------------------------------------------------------

MH_MAGIC = b"\xFE\xED\xFA\xCE"      # 32-bit big-endian
MH_CIGAM = b"\xCE\xFA\xED\xFE"      # 32-bit little-endian (swapped)
MH_MAGIC_64 = b"\xFE\xED\xFA\xCF"   # 64-bit big-endian
MH_CIGAM_64 = b"\xCF\xFA\xED\xFE"   # 64-bit little-endian (swapped, common arm64/x86_64)

FAT_MAGIC = b"\xCA\xFE\xBA\xBE"     # fat binary
FAT_CIGAM = b"\xBE\xBA\xFE\xCA"
FAT_MAGIC_64 = b"\xCA\xFE\xBA\xBF"
FAT_CIGAM_64 = b"\xBF\xBA\xFE\xCA"

MACHO_MAGICS = [
    MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64,
    FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64,
]


@pytest.mark.parametrize("magic", MACHO_MAGICS)
def test_macho_magic_detected(magic):
    # Pad to 8 bytes (the minimum the function inspects).
    data = magic + b"\x00\x00\x00\x00"
    assert _binary_format(data) == "macho"


def test_elf_magic_detected():
    # ELF magic: 0x7F 'E' 'L' 'F'
    data = b"\x7FELF" + b"\x02\x01\x01\x00"  # 64-bit LE
    assert _binary_format(data) == "elf"


def test_pe_magic_detected():
    # Build a minimal MZ + PE stub: MZ header at 0, e_lfanew at 0x3C points
    # to 'PE\0\0' marker.
    data = bytearray(0x80)
    data[:2] = b"MZ"
    e_lfanew = 0x40
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    assert _binary_format(bytes(data)) == "pe"


def test_pe_with_invalid_lfanew_is_unknown():
    # MZ header but e_lfanew points outside the buffer → not PE.
    data = bytearray(0x80)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0xFFFFFFFF)  # garbage offset
    assert _binary_format(bytes(data)) == "unknown"


def test_pe_with_mz_but_missing_pe_marker_is_unknown():
    # MZ + valid e_lfanew but the bytes there aren't 'PE\0\0'.
    data = bytearray(0x80)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"NOPE"
    assert _binary_format(bytes(data)) == "unknown"


def test_short_input_returns_unknown():
    assert _binary_format(b"") == "unknown"
    assert _binary_format(b"\xCF\xFA") == "unknown"
    assert _binary_format(b"\x7FELF\x00") == "unknown"  # 5 bytes < 8 minimum


def test_random_bytes_return_unknown():
    assert _binary_format(b"\x00" * 32) == "unknown"
    assert _binary_format(b"#!/bin/bash\n") == "unknown"
    assert _binary_format(b"<?xml version=\"1.0\"?>") == "unknown"


def test_bytearray_input_accepted():
    # Function is annotated as accepting bytes | bytearray; verify both work.
    ba = bytearray(b"\xCF\xFA\xED\xFE\x00\x00\x00\x00")
    assert _binary_format(ba) == "macho"
