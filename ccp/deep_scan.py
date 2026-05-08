"""r2-based deep scanner — bridges string anchors to instruction offsets.

The string-anchor patches in ccp can locate any byte sequence in the binary
by name. The `instr_replace` patches can rewrite a specific instruction at a
specific byte offset. The missing piece: how do we go from "I have an anchor
string" to "the gate that consumes that string lives at offset 0xABCDE in
the function that starts at offset 0xABC00"?

This module shells out to radare2 and parses its JSON output to walk:

    anchor string → string address → xrefs to that address → enclosing
    function → function entry → relative offsets of cmp / tst / b.eq sites

Output is a list of candidate (anchor, fn_addr, candidate_offsets) tuples.
The operator can then pick the right offset, write an `instr_replace`
patch, and verify it with `apply_instr_patch` before shipping.

This is a development tool, not a runtime requirement. The compiled patches
embed the offsets directly — radare2 isn't needed at patch-apply time.

Requires: radare2 (`r2`) on PATH. Install via Homebrew (`brew install
radare2`) or the upstream installer.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class XrefHit:
    """One xref site for a string anchor."""

    string_addr: int
    string_value: str
    xref_addr: int
    fn_addr: Optional[int] = None
    fn_name: Optional[str] = None


@dataclass
class GateCandidate:
    """A function that consumes an anchor string and contains a gate-like
    instruction pattern (cmp/tst/cbz/tbz/b.eq) before the string emit."""

    anchor: str
    fn_addr: int
    fn_name: str
    fn_size: int
    candidate_offsets: list[tuple[int, str]] = field(default_factory=list)


def have_r2() -> bool:
    return shutil.which("r2") is not None or shutil.which("radare2") is not None


def _r2_cmdj(binary: Path, *cmds: str, timeout: float = 60.0) -> list:
    """Run r2 with -A (full analysis) and a sequence of `j`-suffix commands.

    Returns the parsed JSON of the LAST command's output. r2 commands are
    chained with `;`. Use only `cmdj`-style commands that emit JSON.
    """
    if not have_r2():
        raise RuntimeError("r2 not on PATH (brew install radare2)")

    script = ";".join(cmds)
    out = subprocess.run(
        ["r2", "-q0", "-A", "-c", script, str(binary)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if out.returncode != 0:
        raise RuntimeError(f"r2 exit {out.returncode}: {out.stderr.strip()[:200]}")

    # r2 prints command output then a NUL byte then the prompt. We strip
    # everything after the last `\n` that isn't valid JSON. Simpler: find the
    # last `[` or `{` in stdout and parse from there.
    stdout = out.stdout
    for start_ch in ("[", "{"):
        i = stdout.rfind(start_ch)
        if i >= 0:
            try:
                return json.loads(stdout[i:].split("\x00", 1)[0])
            except json.JSONDecodeError:
                continue
    return []


def find_string_anchor(binary: Path, anchor: str) -> Optional[int]:
    """Resolve `anchor` to its virtual address in the binary via r2 `izj`."""
    rows = _r2_cmdj(binary, "izj")
    for row in rows or []:
        s = row.get("string", "")
        if s == anchor:
            return int(row.get("vaddr", 0))
    return None


def xrefs_to(binary: Path, vaddr: int) -> list[int]:
    """Return the byte addresses that reference `vaddr`."""
    rows = _r2_cmdj(binary, f"axtj @{hex(vaddr)}")
    return [int(r.get("from", 0)) for r in rows or []]


def function_at(binary: Path, vaddr: int) -> Optional[dict]:
    """Return the function dict containing `vaddr` (afij)."""
    rows = _r2_cmdj(binary, f"afij @{hex(vaddr)}")
    if not rows:
        return None
    return rows[0]


def disasm_function(binary: Path, vaddr: int) -> list[dict]:
    """Disassemble the function at `vaddr` (pdfj). Each item has 'offset',
    'opcode' (full instr text), 'type', 'size', etc."""
    obj = _r2_cmdj(binary, f"pdfj @{hex(vaddr)}")
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        return obj.get("ops", [])
    return []


GATE_MNEMONICS = {
    "arm64": {"cmp", "ccmp", "tst", "cbz", "cbnz", "tbz", "tbnz", "b.eq", "b.ne"},
    "x86_64": {"cmp", "test", "je", "jne", "jz", "jnz"},
}


def find_gate_candidates(
    binary: Path,
    anchor: str,
    arch: str = "arm64",
    max_hits_per_anchor: int = 3,
) -> list[GateCandidate]:
    """High-level: locate the anchor string, walk xrefs to enclosing fns,
    find candidate gate instructions in those fns. Returns up to
    `max_hits_per_anchor` GateCandidate entries."""
    sa = find_string_anchor(binary, anchor)
    if sa is None:
        return []

    xrefs = xrefs_to(binary, sa)
    candidates: list[GateCandidate] = []

    seen_fns: set[int] = set()
    for xa in xrefs:
        fn = function_at(binary, xa)
        if not fn:
            continue
        fn_addr = int(fn.get("offset", 0))
        if fn_addr in seen_fns:
            continue
        seen_fns.add(fn_addr)

        ops = disasm_function(binary, fn_addr)
        gates = []
        for op in ops:
            mnem = op.get("opcode", "").split(maxsplit=1)[0].lower()
            if mnem in GATE_MNEMONICS.get(arch, set()):
                rel = int(op.get("offset", 0)) - fn_addr
                gates.append((rel, op.get("opcode", "")))

        if gates:
            candidates.append(
                GateCandidate(
                    anchor=anchor,
                    fn_addr=fn_addr,
                    fn_name=fn.get("name", f"fn_{fn_addr:x}"),
                    fn_size=int(fn.get("size", 0)),
                    candidate_offsets=gates[:8],
                )
            )

        if len(candidates) >= max_hits_per_anchor:
            break

    return candidates


def render_candidates(cands: Iterable[GateCandidate]) -> str:
    """Pretty-print candidates for human review."""
    lines = []
    for c in cands:
        lines.append(f"# anchor: {c.anchor!r}")
        lines.append(f"  fn      : {c.fn_name} @ {c.fn_addr:#x} (size={c.fn_size})")
        for rel, opcode in c.candidate_offsets:
            lines.append(f"    +{rel:#06x}  {opcode}")
        lines.append("")
    return "\n".join(lines) or "no candidates\n"


__all__ = [
    "have_r2",
    "find_string_anchor",
    "xrefs_to",
    "function_at",
    "disasm_function",
    "find_gate_candidates",
    "render_candidates",
    "GateCandidate",
    "XrefHit",
    "GATE_MNEMONICS",
]
