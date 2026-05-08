"""
ccp.scanner — signature-based offset discovery for the Codex CLI Rust binary.

Anchor strings (stable human-readable tokens) survive minor/patch releases.
SigScanner locates those anchors in the binary string sections,
returns byte offsets, and can regenerate a probable search_regex from
the surrounding window.

Pure stdlib. Zero deps.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any


class SigScanner:
    """Signature-driven anchor locator + regex derivation."""

    def __init__(self, text: str | bytes):
        if isinstance(text, bytes):
            try:
                text = text.decode("utf-8", errors="surrogateescape")
            except Exception:
                text = text.decode("latin1")
        self.text = text

    # anchor location ----------------------------------------------------

    def find_anchor(self, anchors: list[str], max_dist: int = 400) -> int | None:
        """First offset where ALL anchors appear within max_dist bytes of the 1st."""
        if not anchors:
            return None
        first = self.text.find(anchors[0])
        while first >= 0:
            window = self.text[first: first + len(anchors[0]) + max_dist + 200]
            if all(a in window for a in anchors[1:]):
                return first
            first = self.text.find(anchors[0], first + 1)
        return None

    def all_occurrences(self, anchor: str) -> list[int]:
        offs: list[int] = []
        i = self.text.find(anchor)
        while i >= 0:
            offs.append(i)
            i = self.text.find(anchor, i + 1)
        return offs

    # regex derivation ---------------------------------------------------

    def derive_regex(self, anchor: str, before: int = 60, after: int = 60) -> str | None:
        """Escaped regex around `anchor` (context window)."""
        i = self.text.find(anchor)
        if i < 0:
            return None
        ctx = self.text[max(0, i - before): i + len(anchor) + after]
        return re.escape(ctx)

    # patch-file driver --------------------------------------------------

    def scan_patches(self, patches: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for p in patches:
            pid     = p.get("id", "?")
            anchors = p.get("anchor_strings") or []
            sig_regex = None
            markers: list[str] = []
            for sub in p.get("patches", []):
                if not sig_regex:
                    sig_regex = sub.get("search_regex") or sub.get("search")
                m = sub.get("applied_marker")
                if m:
                    markers.append(m)

            anchor_off = self.find_anchor(anchors) if anchors else None
            regex_hit  = False
            if sig_regex:
                try:
                    regex_hit = re.search(sig_regex, self.text, re.DOTALL) is not None
                except re.error:
                    regex_hit = False
            marker_hit = any(m in self.text for m in markers)

            if regex_hit or (anchors and anchor_off is not None) or marker_hit:
                status = "ok"
            elif not anchors and not regex_hit:
                status = "unclassified"
            else:
                status = "drift"

            out.append({
                "id":            pid,
                "anchors":       anchors,
                "anchor_offset": anchor_off,
                "regex_hit":     regex_hit,
                "marker_hit":    marker_hit,
                "status":        status,
            })
        return out


# helpers --------------------------------------------------------------------

def load_text_from_target(target: Path) -> str:
    """
    Extract patchable text from the Codex Rust binary.
    Format-aware: concatenates the format-appropriate string-constant sections.
      - Mach-O : __TEXT.__cstring, __TEXT.__const
      - ELF    : .rodata, .data.rel.ro, .data
      - PE     : .rdata, .data
    Falls back to full file bytes if section parsing fails.
    """
    from . import __main__ as _m
    data   = bytearray(target.read_bytes())
    bounds = _m._binary_string_bounds(data)
    parts: list[str] = []
    for lo, hi in bounds:
        chunk = bytes(data[lo:hi])
        try:
            parts.append(chunk.decode("utf-8", errors="surrogateescape"))
        except Exception:
            parts.append(chunk.decode("latin1"))
    return "\n".join(parts)


def format_scan_report(rows: list[dict[str, Any]], verbose: bool = False) -> str:
    G, Y, R, X = "\033[32m", "\033[33m", "\033[31m", "\033[0m"
    lines = []
    ok = drift = unclassified = 0
    for r in rows:
        status = r["status"]
        if status == "ok":
            mark = f"{G}ok{X}";          ok += 1
        elif status == "drift":
            mark = f"{R}drift{X}";       drift += 1
        else:
            mark = f"{Y}nometa{X}";      unclassified += 1
        off   = r["anchor_offset"]
        off_s = f"@0x{off:08x}" if off is not None else "--"
        line  = f"  {mark:22s}  {r['id']:42s}  {off_s:>14s}  regex={'Y' if r['regex_hit'] else 'N'}"
        lines.append(line)
        if verbose and r["anchors"]:
            lines.append(f"    anchors: {', '.join(r['anchors'])}")
    tail = f"\n  {G}{ok} ok{X}"
    if drift:        tail += f"  {R}{drift} drift{X}"
    if unclassified: tail += f"  {Y}{unclassified} nometa{X}"
    lines.append(tail)
    return "\n".join(lines)


_BINARY_PATCH_TYPES = ("macho_replace", "binary_replace", "elf_replace", "pe_replace")


def load_patches_from_dir(patch_dir: Path, respect_scan_flag: bool = True) -> list[dict[str, Any]]:
    """Load all binary-patchable patches (macho_replace / binary_replace / elf_replace / pe_replace)."""
    out = []
    for f in sorted(patch_dir.glob("*.json")):
        try:
            obj = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if obj.get("type") not in _BINARY_PATCH_TYPES:
            continue
        if obj.get("disabled"):
            continue
        if respect_scan_flag and obj.get("scan_signatures", True) is False:
            continue
        obj["__file"] = str(f)
        out.append(obj)
    return out
