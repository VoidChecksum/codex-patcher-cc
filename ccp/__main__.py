"""
ccp — Codex CLI Patcher
Rust Mach-O binary patches + wrapper + config installer for OpenAI Codex CLI.
Regex-signature patches survive minor/patch releases.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import shutil
import struct as _struct
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from . import updater as _updater
from . import scanner as _scanner

ROOT       = Path(__file__).resolve().parent.parent
PATCH_DIR  = ROOT / "patches"
BACKUP_DIR = Path.home() / ".ccp" / "backups"

G, Y, R, B, X = "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[0m"

# ── console encoding safety ───────────────────────────────────────────────────
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:
    pass

_enc = (getattr(sys.stdout, "encoding", None) or "").lower()
if "utf" not in _enc:
    CHECK, CROSS, WARN_ICON, ARROW, DOT = "[ok]", "[X]", "[!]", "->", "*"
    G = Y = R = B = X = ""
else:
    CHECK, CROSS, WARN_ICON, ARROW, DOT = "✓", "✗", "⚠", "→", "·"

_PKG = "@openai/codex"

# Platform sub-packages — distribution model for Codex CLI Rust binary
_PLATFORM_PKGS = [
    "@openai/codex-linux-x64",
    "@openai/codex-linux-arm64",
    "@openai/codex-darwin-x64",
    "@openai/codex-darwin-arm64",
    "@openai/codex-win32-x64",
    "@openai/codex-win32-arm64",
]

# Vendor path pattern inside each platform package:
# <pkg>/vendor/<triple>/codex/codex  (or codex.exe on Windows)
_VENDOR_SUBDIRS = [
    "vendor/aarch64-apple-darwin/codex/codex",
    "vendor/x86_64-apple-darwin/codex/codex",
    "vendor/aarch64-unknown-linux-gnu/codex/codex",
    "vendor/x86_64-unknown-linux-gnu/codex/codex",
    "vendor/aarch64-pc-windows-msvc/codex/codex.exe",
    "vendor/x86_64-pc-windows-msvc/codex/codex.exe",
]


# ── target discovery ──────────────────────────────────────────────────────────

def _npm_global_roots() -> list[Path]:
    roots: list[Path] = []
    try:
        r = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            roots.insert(0, Path(r.stdout.strip()))
    except Exception:
        pass
    home = Path.home()
    roots += [
        home / ".npm-global/lib/node_modules",
        home / ".local/lib/node_modules",
        Path("/opt/homebrew/lib/node_modules"),
        Path("/usr/local/lib/node_modules"),
        Path("/usr/lib/node_modules"),
    ]
    return roots


def find_target() -> Path | None:
    """
    Locate the Codex CLI Rust binary. Walks npm global roots looking for:
      <root>/@openai/codex/node_modules/@openai/codex-{platform}/vendor/.../codex
    Returns Path to binary or None.
    """
    for npm_root in _npm_global_roots():
        codex_pkg = npm_root / _PKG
        if not codex_pkg.is_dir():
            continue
        # Walk platform sub-packages nested under main package
        node_mods = codex_pkg / "node_modules"
        for plat_pkg in _PLATFORM_PKGS:
            plat_dir = node_mods / plat_pkg
            if not plat_dir.is_dir():
                continue
            for vendor_suffix in _VENDOR_SUBDIRS:
                p = plat_dir / vendor_suffix
                if p.exists() and p.stat().st_size > 1_000_000:
                    return p
        # Also check vendor directly under codex-{platform} (flat layout)
        for plat_pkg in _PLATFORM_PKGS:
            # Look for platform-named dirs adjacent to node_modules
            pkg_name = plat_pkg.split("/")[-1]  # e.g. codex-darwin-arm64
            plat_dir2 = npm_root / plat_pkg
            if not plat_dir2.is_dir():
                continue
            for vendor_suffix in _VENDOR_SUBDIRS:
                p = plat_dir2 / vendor_suffix
                if p.exists() and p.stat().st_size > 1_000_000:
                    return p

    # Last resort: resolve `which codex` from PATH and check for sibling binary
    try:
        r = subprocess.run(["which", "codex"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            launcher = Path(r.stdout.strip()).resolve()
            # codex.js is a launcher; look for the Rust binary in adjacent node_modules
            candidate_root = launcher.parent.parent / "lib" / "node_modules"
            if candidate_root.is_dir():
                codex_pkg = candidate_root / _PKG
                node_mods = codex_pkg / "node_modules"
                for plat_pkg in _PLATFORM_PKGS:
                    plat_dir = node_mods / plat_pkg
                    if not plat_dir.is_dir():
                        continue
                    for vendor_suffix in _VENDOR_SUBDIRS:
                        p = plat_dir / vendor_suffix
                        if p.exists() and p.stat().st_size > 1_000_000:
                            return p
    except Exception:
        pass

    return None


def sha256_short(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:12]


# ── Mach-O section helpers ────────────────────────────────────────────────────

def _macho_sections(data: bytes | bytearray) -> list[tuple[str, str, int, int]]:
    """
    Parse a Mach-O binary (arm64 or x86_64, possibly fat) and return a list of
    (segname, sectname, offset, size) for every section.
    Handles fat binaries by picking the first 64-bit slice.
    """
    sections: list[tuple[str, str, int, int]] = []
    if len(data) < 8:
        return sections

    magic = _struct.unpack_from(">I", data, 0)[0]

    # Fat binary — recurse into first arm64 or x86_64 slice
    if magic in (0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA):
        big = magic in (0xCAFEBABE, 0xCAFEBABF)
        fmt = ">I" if big else "<I"
        nfat = _struct.unpack_from(fmt, data, 4)[0]
        entry_size = 20 if magic in (0xCAFEBABE, 0xBEBAFECA) else 32
        for i in range(nfat):
            base = 8 + i * entry_size
            off = _struct.unpack_from(fmt, data, base + 8)[0]
            sub = bytes(data[off:])
            subs = _macho_sections(sub)
            # Return offset-adjusted sections
            for seg, sec, sec_off, sec_size in subs:
                sections.append((seg, sec, off + sec_off, sec_size))
            if sections:
                return sections
        return sections

    if magic not in (0xFEEDFACF, 0xCFFAEDFE, 0xFEEDFACE, 0xCEFAEDFE):
        return sections  # not Mach-O

    is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    end = ">" if magic in (0xFEEDFACF, 0xFEEDFACE) else "<"

    ncmds = _struct.unpack_from(end + "I", data, 16)[0]
    hdr_size = 32 if is_64 else 28
    cur = hdr_size

    LC_SEGMENT_64 = 0x19
    LC_SEGMENT    = 0x01

    for _ in range(ncmds):
        if cur + 8 > len(data):
            break
        cmd, cmdsize = _struct.unpack_from(end + "II", data, cur)
        if cmd == LC_SEGMENT_64:
            segname = bytes(data[cur + 8: cur + 24]).split(b"\x00", 1)[0].decode("ascii", errors="replace")
            nsects  = _struct.unpack_from(end + "I", data, cur + 64)[0]
            sect_base = cur + 72
            for j in range(nsects):
                s = sect_base + j * 80
                if s + 80 > len(data):
                    break
                sectname = bytes(data[s: s + 16]).split(b"\x00", 1)[0].decode("ascii", errors="replace")
                sec_size = _struct.unpack_from(end + "Q", data, s + 40)[0]
                sec_off  = _struct.unpack_from(end + "I", data, s + 48)[0]
                sections.append((segname, sectname, sec_off, sec_size))
        elif cmd == LC_SEGMENT:
            segname = bytes(data[cur + 8: cur + 24]).split(b"\x00", 1)[0].decode("ascii", errors="replace")
            nsects  = _struct.unpack_from(end + "I", data, cur + 48)[0]
            sect_base = cur + 56
            for j in range(nsects):
                s = sect_base + j * 68
                if s + 68 > len(data):
                    break
                sectname = bytes(data[s: s + 16]).split(b"\x00", 1)[0].decode("ascii", errors="replace")
                sec_size = _struct.unpack_from(end + "I", data, s + 36)[0]
                sec_off  = _struct.unpack_from(end + "I", data, s + 40)[0]
                sections.append((segname, sectname, sec_off, sec_size))
        cur += cmdsize if cmdsize >= 8 else 8

    return sections


def _string_section_bounds(data: bytes | bytearray) -> list[tuple[int, int]]:
    """
    Return (offset, end) pairs for __TEXT.__cstring and __TEXT.__const sections
    (the regions that hold string constants in a Rust Mach-O binary).
    Falls back to full file if no sections found.
    """
    sects = _macho_sections(data)
    bounds: list[tuple[int, int]] = []
    for seg, sec, off, size in sects:
        if seg == "__TEXT" and sec in ("__cstring", "__const") and size > 0:
            bounds.append((off, off + size))
    if not bounds:
        # Fallback: patch entire file (length-preserving, safe)
        bounds.append((0, len(data)))
    return bounds


def codesign(path: Path) -> tuple[bool, str]:
    """Ad-hoc re-sign a Mach-O binary. Required on macOS after byte modification."""
    if sys.platform != "darwin":
        return True, "n/a (non-darwin)"
    r = subprocess.run(
        ["codesign", "--force", "--sign", "-", str(path)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or "").strip()
    return True, "ok"


def patch_macho_inplace(binary: Path, patches: list[dict]) -> dict:
    """
    In-place Rust Mach-O byte patcher.
    - Reads the binary, locates __TEXT.__cstring + __TEXT.__const sections.
    - Applies length-preserving regex/literal replacements (space-pad if shorter).
    - Writes to a .tmp sibling, codesigns, runs --version to verify, atomic renames.
    Returns dict: {ok, applied, skipped, err?, per_patch}.
    """
    mode = binary.stat().st_mode & 0o7777
    original_size = binary.stat().st_size
    data = bytearray(binary.read_bytes())

    bounds = _string_section_bounds(data)
    applied_total = 0
    skipped_total = 0
    per_patch: list[dict] = []

    for p in patches:
        applied_n = 0
        skipped_n = 0
        for sub in p.get("patches", []):
            search_regex = sub.get("search_regex")
            search       = sub.get("search")
            replace      = sub.get("replace", "")
            marker       = sub.get("applied_marker")

            # Idempotency: check marker in any string section
            if marker:
                marker_b = marker.encode("utf-8", "surrogateescape")
                already  = any(
                    data.find(marker_b, lo, hi) >= 0
                    for lo, hi in bounds
                )
                if already:
                    continue

            if search_regex:
                try:
                    pat = re.compile(
                        search_regex.encode("utf-8", "surrogateescape"), re.DOTALL
                    )
                except re.error:
                    skipped_n += 1
                    continue
                for lo, hi in bounds:
                    section_view = bytes(data[lo:hi])
                    for m in pat.finditer(section_view):
                        mb = m.group(0)
                        try:
                            rb = m.expand(replace.encode("utf-8", "surrogateescape"))
                        except Exception:
                            skipped_n += 1
                            continue
                        if len(rb) > len(mb):
                            skipped_n += 1
                            continue
                        if len(rb) < len(mb):
                            rb = rb + b" " * (len(mb) - len(rb))
                        abs_start = lo + m.start()
                        data[abs_start: abs_start + len(mb)] = rb
                        applied_n += 1
            elif search:
                s_b = search.encode("utf-8", "surrogateescape")
                r_b = replace.encode("utf-8", "surrogateescape")
                if len(r_b) > len(s_b):
                    skipped_n += 1
                    continue
                if len(r_b) < len(s_b):
                    r_b = r_b + b" " * (len(s_b) - len(r_b))
                for lo, hi in bounds:
                    pos = lo
                    while True:
                        j = data.find(s_b, pos, hi)
                        if j < 0:
                            break
                        data[j: j + len(s_b)] = r_b
                        applied_n += 1
                        pos = j + len(s_b)

        per_patch.append({"id": p.get("id", "?"), "applied": applied_n, "skipped": skipped_n})
        applied_total += applied_n
        skipped_total += skipped_n

    if len(data) != original_size:
        return {
            "ok": False,
            "err": f"size drift {len(data)} vs {original_size}",
            "applied": 0,
            "skipped": skipped_total,
            "per_patch": per_patch,
        }

    if applied_total == 0:
        return {"ok": True, "noop": True, "applied": 0, "skipped": skipped_total, "per_patch": per_patch}

    # Atomic swap: write tmp -> codesign -> verify -> rename
    tmp_bin = binary.parent / f".{binary.name}.ccptmp-{os.getpid()}"
    try:
        tmp_bin.write_bytes(bytes(data))
        tmp_bin.chmod(mode)

        # macOS: must re-sign or hardened runtime will SIGKILL
        ok_sign, sign_msg = codesign(tmp_bin)
        if not ok_sign:
            tmp_bin.unlink(missing_ok=True)
            return {
                "ok": False,
                "err": f"codesign failed: {sign_msg}",
                "applied": applied_total,
                "skipped": skipped_total,
                "per_patch": per_patch,
            }

        r = subprocess.run(
            [str(tmp_bin), "--version"],
            capture_output=True, text=True, timeout=20,
        )
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0 or not out.strip():
            tmp_bin.unlink(missing_ok=True)
            return {
                "ok": False,
                "err": f"verify failed: {out[:120]!r} rc={r.returncode}",
                "applied": applied_total,
                "skipped": skipped_total,
                "per_patch": per_patch,
            }

        binary.unlink()
        tmp_bin.rename(binary)
        binary.chmod(mode)
        # Re-sign the installed binary
        codesign(binary)

    except Exception as e:
        tmp_bin.unlink(missing_ok=True)
        return {"ok": False, "err": f"write failed: {e}", "applied": 0, "skipped": skipped_total}

    return {"ok": True, "applied": applied_total, "skipped": skipped_total, "per_patch": per_patch}


# ── patch loading ─────────────────────────────────────────────────────────────

def load_patches() -> list[dict[str, Any]]:
    patches = []
    for f in sorted(PATCH_DIR.glob("*.json")):
        try:
            p = json.loads(f.read_text(encoding="utf-8"))
            if p.get("disabled"):
                continue
            patches.append(p)
        except json.JSONDecodeError as e:
            print(f"{R}{CROSS} {f.name}: invalid JSON — {e}{X}", file=sys.stderr)
    return patches


def backup(target: Path) -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dst   = BACKUP_DIR / f"codex.{stamp}.{sha256_short(target)}.bak"
    shutil.copy2(target, dst)
    # Keep last 10 backups
    for old in sorted(BACKUP_DIR.glob("codex.*.bak"))[:-10]:
        old.unlink(missing_ok=True)
    return dst


# ── config/toml patches ───────────────────────────────────────────────────────

def _apply_toml_defaults(p: dict, dry_run: bool = False) -> tuple[bool, str]:
    """
    config_toml patch type: write default keys into ~/.codex/config.toml.
    Only sets keys that are absent — never overwrites operator-set values.
    Uses simple line-based TOML writer (no external deps).
    """
    config_path = Path(p.get("config_path", "~/.codex/config.toml")).expanduser()
    defaults: dict[str, str] = p.get("defaults", {})
    if not defaults:
        return True, "no-op (no defaults defined)"

    config_path.parent.mkdir(parents=True, exist_ok=True)
    existing_text = ""
    if config_path.is_file():
        existing_text = config_path.read_text(encoding="utf-8")

    added = []
    for key, val in defaults.items():
        # Simple check: key = ... already present as a top-level entry
        pattern = re.compile(r"^\s*" + re.escape(key) + r"\s*=", re.MULTILINE)
        if pattern.search(existing_text):
            continue
        added.append(f'{key} = {val}')

    if not added:
        return True, "no-op (already applied)"
    if dry_run:
        return True, f"would add {len(added)} key(s): {', '.join(k.split('=')[0].strip() for k in added)}"

    # Prepend new keys with a comment
    insert = f"\n# ccp: bypass defaults\n" + "\n".join(added) + "\n"
    config_path.write_text(existing_text.rstrip("\n") + insert, encoding="utf-8")
    return True, f"{len(added)} key(s) added"


def _apply_wrapper(p: dict, target: Path | None, dry_run: bool = False) -> tuple[bool, str]:
    """wrapper patch type: install a shell wrapper script."""
    wrapper_path = Path(p.get("wrapper_path", "~/.local/bin/codex")).expanduser()
    content = p.get("content", "")
    MARKER = p.get("marker", "# ccp-wrapper")

    if not content:
        return False, "no content defined"

    if wrapper_path.exists() and not wrapper_path.is_symlink():
        try:
            if MARKER in wrapper_path.read_text(encoding="utf-8"):
                return True, "no-op (already applied)"
        except Exception:
            pass

    if dry_run:
        return True, f"would install wrapper at {wrapper_path}"

    wrapper_path.parent.mkdir(parents=True, exist_ok=True)
    wrapper_path.unlink(missing_ok=True)
    wrapper_path.write_text(content, encoding="utf-8")
    wrapper_path.chmod(0o755)
    return True, f"wrapper installed at {wrapper_path}"


# ── commands ──────────────────────────────────────────────────────────────────

def cmd_patch(args) -> int:
    patches = load_patches()
    target  = find_target()

    binary_patches = [p for p in patches if p.get("type") == "macho_replace"]
    meta_patches   = [p for p in patches if p.get("type") not in ("macho_replace",)]

    print(f"{B}ccp patch — {len(patches)} patches{X}")
    if target:
        print(f"  target : {target}")
        print(f"  sha    : {sha256_short(target)}")
        print(f"  size   : {target.stat().st_size // 1024 // 1024} MB")
        if not args.dry_run:
            bkp = backup(target)
            print(f"  backup : {bkp}")
    else:
        print(f"  {Y}target not found — binary patches will be skipped{X}")

    ok = fail = skip = 0

    # ── binary patches ─────────────────────────────────────────────────────
    if not target:
        for p in binary_patches:
            print(f"  {Y}skip{X} {p.get('id','?'):40s}  target not found")
            skip += 1
    elif args.dry_run:
        for p in binary_patches:
            data = bytearray(target.read_bytes())
            bounds = _string_section_bounds(data)
            applied_n = 0
            for sub in p.get("patches", []):
                marker = sub.get("applied_marker")
                if marker:
                    marker_b = marker.encode("utf-8", "surrogateescape")
                    if any(data.find(marker_b, lo, hi) >= 0 for lo, hi in bounds):
                        continue
                sr = sub.get("search_regex") or sub.get("search") or ""
                if not sr:
                    continue
                try:
                    if sub.get("search_regex"):
                        pat = re.compile(sr.encode("utf-8", "surrogateescape"), re.DOTALL)
                        for lo, hi in bounds:
                            applied_n += sum(1 for _ in pat.finditer(bytes(data[lo:hi])))
                    else:
                        s_b = sr.encode("utf-8", "surrogateescape")
                        for lo, hi in bounds:
                            applied_n += bytes(data[lo:hi]).count(s_b)
                except re.error:
                    pass
            msg = "no-op (already applied)" if applied_n == 0 else f"would apply {applied_n} in-place"
            print(f"  {G}ok{X}    {p.get('id','?'):40s}  {msg}")
            ok += 1
        print(f"  {Y}dry-run: binary not modified{X}")
    else:
        result = patch_macho_inplace(target, binary_patches)
        if not result["ok"]:
            print(f"  {R}fail{X}  [macho-inplace]  {result.get('err','unknown')}")
            fail += len(binary_patches)
        else:
            for pr in result.get("per_patch", []):
                n   = pr["applied"]
                msg = "no-op (already applied)" if n == 0 else f"{n} in-place replacement(s)"
                print(f"  {G}ok{X}    {pr['id']:40s}  {msg}")
                ok += 1
            if not result.get("noop"):
                print(f"  {G}verified in-place{X}  (ran binary --version, output confirmed)")

    # ── meta patches ───────────────────────────────────────────────────────
    for p in meta_patches:
        t = p.get("type")
        if t == "config_toml":
            success, msg = _apply_toml_defaults(p, dry_run=args.dry_run)
        elif t == "wrapper":
            success, msg = _apply_wrapper(p, target, dry_run=args.dry_run)
        else:
            print(f"  {Y}skip{X} {p.get('id','?'):40s}  type={t} (unknown)")
            skip += 1
            continue
        mark = f"{G}ok{X}" if success else f"{R}fail{X}"
        print(f"  {mark}   {p.get('id','?'):40s}  {msg}")
        ok   += success
        fail += not success

    print(f"\n{B}{ok} ok {DOT} {fail} failed {DOT} {skip} skipped{X}")

    if target and not args.dry_run and not fail:
        try:
            _updater.save_state(last_codex_sha=sha256_short(target))
        except Exception:
            pass

    return 1 if fail else 0


def cmd_verify(args) -> int:
    target = find_target()
    if not target:
        print(f"{R}codex binary not found{X}")
        return 2

    data   = bytearray(target.read_bytes())
    bounds = _string_section_bounds(data)

    missing = 0
    for p in load_patches():
        if p.get("type") != "macho_replace":
            continue
        for sub in p.get("patches", []):
            if not sub.get("required", True):
                continue
            marker = sub.get("applied_marker")
            if marker:
                marker_b = marker.encode("utf-8", "surrogateescape")
                found    = any(data.find(marker_b, lo, hi) >= 0 for lo, hi in bounds)
                if not found:
                    print(f"{R}{CROSS}{X} {p.get('id','?')}")
                    missing += 1
                    break

    if missing:
        print(f"\n{R}{missing} patches missing{X}")
        return 1
    print(f"{G}{CHECK} all patches verified{X}")
    return 0


def cmd_rollback(args) -> int:
    target = find_target()
    if not target:
        print(f"{R}codex binary not found{X}")
        return 2
    baks = sorted(BACKUP_DIR.glob("codex.*.bak"))
    if not baks:
        print(f"{R}no backups in {BACKUP_DIR}{X}")
        return 1
    latest = baks[-1]
    mode   = target.stat().st_mode & 0o7777
    target.unlink()
    shutil.copy2(latest, target)
    target.chmod(mode)
    if sys.platform == "darwin":
        ok_s, s_msg = codesign(target)
        if not ok_s:
            print(f"  {Y}{WARN_ICON} codesign after rollback failed: {s_msg}{X}")
    print(f"{G}{CHECK} restored{X} {target} <- {latest.name}")
    return 0


def cmd_status(args) -> int:
    target  = find_target()
    patches = load_patches()
    print(f"{B}ccp status{X}")
    print(f"  patches : {len(patches)}")
    if target:
        print(f"  target  : {target}")
        print(f"  sha256  : {sha256_short(target)}")
        print(f"  size    : {target.stat().st_size // 1024 // 1024} MB")
    else:
        print(f"  target  : {R}NOT FOUND{X}")
        print(f"  hint    : install codex via 'npm install -g @openai/codex'")
    baks = sorted(BACKUP_DIR.glob("codex.*.bak"))
    print(f"  backups : {len(baks)}  ({BACKUP_DIR})")
    state = _updater.load_state()
    last_sha = state.get("last_codex_sha")
    if last_sha and target:
        cur = sha256_short(target)
        drift = cur != last_sha
        print(f"  drift   : {'YES — binary changed since last patch' if drift else 'no'}")
    return 0


def cmd_list(args) -> int:
    patches = load_patches()
    if not patches:
        print(f"  {Y}no patches in {PATCH_DIR}{X}")
        return 0
    for p in patches:
        tid = p.get("type", "?")
        req = "" if p.get("required", True) else f" [{Y}optional{X}]"
        print(f"  {p.get('id','?'):45s}  [{tid}]{req}  {p.get('description','')}")
    return 0


def cmd_scan(args) -> int:
    """Signature-based offset discovery. Prints anchor offsets + regex hit status."""
    target = find_target()
    if not target:
        print(f"{R}codex binary not found{X}")
        return 2

    try:
        text = _scanner.load_text_from_target(target)
    except Exception as e:
        print(f"{R}extract failed: {e}{X}")
        return 2

    patches = _scanner.load_patches_from_dir(PATCH_DIR)
    sc      = _scanner.SigScanner(text)
    rows    = sc.scan_patches(patches)

    print(f"{B}ccp scan — {len(rows)} macho_replace patches{X}")
    print(f"  target : {target}")
    print(f"  text   : {len(text)} bytes extracted")
    print(f"  sha    : {sha256_short(target)}")
    print()
    print(_scanner.format_scan_report(rows, verbose=args.verbose))

    return 1 if any(r["status"] == "drift" for r in rows) else 0


def cmd_doctor(args) -> int:
    """Full health report."""
    target  = find_target()
    patches = load_patches()
    from . import __version__ as _ver
    print(f"{B}ccp doctor{X}")
    print(f"  ccp ver    : {_ver}")
    print(f"  patches    : {len(patches)}")
    if not target:
        print(f"  target     : {R}NOT FOUND{X}")
        return 2
    print(f"  target     : {target}")
    print(f"  sha256     : {sha256_short(target)}")
    print(f"  size       : {target.stat().st_size // 1024 // 1024} MB")

    # sig scan
    try:
        text = _scanner.load_text_from_target(target)
        rows = _scanner.SigScanner(text).scan_patches(_scanner.load_patches_from_dir(PATCH_DIR))
        drift = [r["id"] for r in rows if r["status"] == "drift"]
        if drift:
            print(f"  {R}sig drift  : {len(drift)} {DOT} {', '.join(drift[:3])}{X}")
        else:
            print(f"  {G}sig drift  : 0{X}")
    except Exception as e:
        print(f"  {R}sig scan   : failed — {e}{X}")

    # verify markers
    try:
        rc_v = cmd_verify(type("A", (), {})())
    except SystemExit:
        rc_v = 1
    print(f"  applied    : {'all' if rc_v == 0 else 'partial/none'}")

    # backups
    baks = sorted(BACKUP_DIR.glob("codex.*.bak"))
    print(f"  backups    : {len(baks)} in {BACKUP_DIR}")

    # upstream
    try:
        info = _updater.upstream_status(PATCH_DIR)
        if info["drift"]:
            print(f"  {Y}upstream   : behind — run 'ccp self-update'{X}")
        elif info["remote_commit"]:
            print(f"  {G}upstream   : current{X}")
        else:
            print(f"  upstream   : unreachable")
    except Exception:
        print(f"  upstream   : error")

    return 0


def cmd_watch(args) -> int:
    """Daemon: poll binary mtime+sha; on change autoheal."""
    import time
    target = find_target()
    if not target:
        print(f"{R}codex binary not found{X}")
        return 2
    print(f"{B}ccp watch — polling every {args.interval}s{X}")
    print(f"  target: {target}")
    last_sha   = sha256_short(target)
    last_mtime = target.stat().st_mtime
    print(f"  sha   : {last_sha}")
    try:
        while True:
            time.sleep(args.interval)
            try:
                target = find_target()
                if not target:
                    print(f"{Y}  target vanished — waiting{X}")
                    continue
                m = target.stat().st_mtime
                if m == last_mtime:
                    continue
                cur_sha = sha256_short(target)
                if cur_sha == last_sha:
                    last_mtime = m
                    continue
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"\n{Y}[{ts}] codex changed: {last_sha} -> {cur_sha}{X}")
                backup(target)
                class _A:
                    force = False; quiet = False
                rc = cmd_autoheal(_A())
                print(f"  autoheal rc={rc}")
                last_sha   = sha256_short(target)
                last_mtime = target.stat().st_mtime
            except Exception as e:
                print(f"{R}  watch loop error: {e}{X}")
    except KeyboardInterrupt:
        print(f"\n{B}watch stopped{X}")
        return 0


def cmd_autoheal(args) -> int:
    return _updater.autoheal(
        find_target=find_target,
        sha256_short=sha256_short,
        load_patches=load_patches,
        cmd_verify_fn=cmd_verify,
        cmd_patch_fn=cmd_patch,
        cmd_rollback_fn=cmd_rollback,
        patch_dir=PATCH_DIR,
        force=getattr(args, "force", False),
        quiet=getattr(args, "quiet", False),
    )


def cmd_self_update(args) -> int:
    """Pull latest patches/*.json from GitHub and re-apply."""
    print(f"{B}ccp self-update{X}  <- {_updater.REPO}@{_updater.BRANCH}")
    remote = _updater.remote_head_sha("patches")
    if not remote:
        print(f"{R}could not reach GitHub API{X}")
        return 2
    state = _updater.load_state()
    local = state.get("patches_commit")
    print(f"  local  : {local or '(unknown)'}")
    print(f"  remote : {remote}")
    if local == remote and not getattr(args, "force", False):
        print(f"{G}{CHECK} already up to date{X}")
        return 0
    if getattr(args, "dry_run", False):
        print(f"{Y}dry-run: would sync{X}")
        return 0
    changed, sha_or_err = _updater.sync_patches(PATCH_DIR, remote)
    if changed < 0:
        print(f"{R}{CROSS} sync failed — {sha_or_err}{X}")
        return 2
    print(f"{G}{CHECK} synced{X}  {changed} file(s) updated @ {sha_or_err[:7]}")
    if changed and not getattr(args, "no_reapply", False):
        print(f"\n{B}re-applying patches{X}")
        class _P:
            dry_run = False
        return cmd_patch(_P())
    return 0


def cmd_check_updates(args) -> int:
    info = _updater.upstream_status(PATCH_DIR)
    print(f"{B}ccp check-updates{X}")
    print(f"  local commit  : {info['local_commit'] or '(unknown)'}")
    print(f"  remote commit : {info['remote_commit'] or '(unreachable)'}")
    print(f"  local files   : {info['local_files']}")
    if info["drift"]:
        print(f"{Y}{WARN_ICON} update available — run 'ccp self-update'{X}")
        return 1
    if not info["local_commit"] and info["remote_commit"]:
        print(f"{Y}{WARN_ICON} no sync state — run 'ccp self-update' to pin current{X}")
        return 1
    if info["remote_commit"]:
        print(f"{G}{CHECK} up to date{X}")
    return 0


# ── install-rules ─────────────────────────────────────────────────────────────

_CCP_MD_START = "<!-- ccp:authorization:start -->"
_CCP_MD_END   = "<!-- ccp:authorization:end -->"


def _deep_merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if k in dst and isinstance(dst[k], dict) and isinstance(v, dict):
            _deep_merge(dst[k], v)
        elif k in dst and isinstance(dst[k], list) and isinstance(v, list):
            merged = list(dst[k])
            for item in v:
                if item not in merged:
                    merged.append(item)
            dst[k] = merged
        else:
            dst[k] = v
    return dst


def cmd_install_rules(args) -> int:
    """Deploy contrib/rules/AUTHORIZATION.md into ~/.codex/ as hooks context."""
    src_dir = ROOT / "contrib" / "rules"
    if not src_dir.exists():
        print(f"{R}contrib/rules/ missing{X}")
        return 2

    codex_dir = Path.home() / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)

    # Write AUTHORIZATION.md into ~/.codex/
    auth_src = (src_dir / "AUTHORIZATION.md").read_text(encoding="utf-8")
    auth_dst = codex_dir / "AUTHORIZATION.md"
    auth_dst.write_text(auth_src, encoding="utf-8")
    print(f"  {G}{CHECK}{X} AUTHORIZATION.md {ARROW} {auth_dst}")

    print(f"\n{G}{CHECK} authorization rules installed{X}")
    return 0


def cmd_install_wrapper(args) -> int:
    """Install contrib/wrappers/codex to ~/.local/bin/codex."""
    src_dir = ROOT / "contrib" / "wrappers"
    wrapper_src = src_dir / "codex"
    if not wrapper_src.exists():
        print(f"{R}contrib/wrappers/codex missing{X}")
        return 2

    dst = Path.home() / ".local" / "bin" / "codex"
    dst.parent.mkdir(parents=True, exist_ok=True)

    content = wrapper_src.read_text(encoding="utf-8")
    MARKER = "# ccp-wrapper"
    if dst.exists() and not dst.is_symlink():
        try:
            if MARKER in dst.read_text(encoding="utf-8"):
                print(f"  {G}no-op{X}  wrapper already installed at {dst}")
                return 0
        except Exception:
            pass
    dst.unlink(missing_ok=True)
    dst.write_text(content, encoding="utf-8")
    dst.chmod(0o755)
    print(f"  {G}{CHECK}{X} wrapper {ARROW} {dst}")
    print(f"\n{G}{CHECK} wrapper installed{X}")
    print(f"  Ensure ~/.local/bin is first in PATH")
    return 0


def cmd_install_config(args) -> int:
    """Merge contrib/rules/codex-config.toml defaults into ~/.codex/config.toml."""
    src = ROOT / "contrib" / "rules" / "codex-config.toml"
    if not src.exists():
        print(f"{R}contrib/rules/codex-config.toml missing{X}")
        return 2

    config_path = Path.home() / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    existing_text = ""
    if config_path.is_file():
        existing_text = config_path.read_text(encoding="utf-8")

    template = src.read_text(encoding="utf-8")
    added: list[str] = []
    MARKER = "# ccp: bypass defaults"

    if MARKER in existing_text:
        print(f"  {G}no-op{X}  ccp defaults already in config.toml")
        return 0

    # Parse key=value lines from template, skip section headers and comments
    for line in template.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("["):
            continue
        if "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        pattern = re.compile(r"^\s*" + re.escape(key) + r"\s*=", re.MULTILINE)
        if pattern.search(existing_text):
            continue  # operator already set this
        added.append(line)

    if not added:
        print(f"  {G}no-op{X}  all keys already present")
        return 0

    insert = f"\n{MARKER}\n" + "\n".join(added) + "\n"
    config_path.write_text(existing_text.rstrip("\n") + insert, encoding="utf-8")
    print(f"  {G}{CHECK}{X} {len(added)} key(s) added to {config_path}")
    print(f"\n{G}{CHECK} config installed{X}")
    return 0


# ── entry ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="ccp",
        description="Codex CLI Patcher — Rust Mach-O patches + wrapper + config for OpenAI Codex CLI",
    )
    sub = ap.add_subparsers(dest="cmd", metavar="command")

    p_patch = sub.add_parser("patch", help="Apply all patches to the Codex binary + config")
    p_patch.add_argument("--dry-run", "-n", action="store_true")

    sub.add_parser("verify",   help="Check that binary patches are applied")
    sub.add_parser("rollback", help="Restore binary from most recent backup")
    sub.add_parser("status",   help="Show install state and binary location")
    sub.add_parser("list",     help="List all patches in catalog")
    sub.add_parser("doctor",   help="Full health report: target, patches, sig drift, upstream")

    p_sc = sub.add_parser("scan", help="Signature-based anchor discovery in binary string sections")
    p_sc.add_argument("--verbose", "-v", action="store_true")

    p_su = sub.add_parser("self-update",
        help="Pull latest patches/*.json from GitHub and re-apply")
    p_su.add_argument("--dry-run", "-n", action="store_true")
    p_su.add_argument("--force", "-f", action="store_true")
    p_su.add_argument("--no-reapply", action="store_true")

    p_ah = sub.add_parser("autoheal",
        help="Detect binary drift; self-update + re-patch if broken")
    p_ah.add_argument("--force", "-f", action="store_true")
    p_ah.add_argument("--quiet", "-q", action="store_true")

    sub.add_parser("check-updates", help="Show if remote patches differ from local")

    p_w = sub.add_parser("watch", help="Daemon: poll binary, autoheal on update")
    p_w.add_argument("--interval", "-i", type=int, default=10,
        help="Poll interval in seconds (default 10)")

    sub.add_parser("install-rules",
        help="Deploy operator-authorization rules to ~/.codex/")
    sub.add_parser("install-wrapper",
        help="Install bypass wrapper to ~/.local/bin/codex")
    sub.add_parser("install-config",
        help="Merge bypass defaults into ~/.codex/config.toml")

    args = ap.parse_args()
    if args.cmd is None:
        ap.print_help()
        return 0

    dispatch = {
        "patch":           cmd_patch,
        "verify":          cmd_verify,
        "rollback":        cmd_rollback,
        "status":          cmd_status,
        "list":            cmd_list,
        "doctor":          cmd_doctor,
        "scan":            cmd_scan,
        "self-update":     cmd_self_update,
        "autoheal":        cmd_autoheal,
        "check-updates":   cmd_check_updates,
        "watch":           cmd_watch,
        "install-rules":   cmd_install_rules,
        "install-wrapper": cmd_install_wrapper,
        "install-config":  cmd_install_config,
    }
    fn = dispatch.get(args.cmd)
    if fn is None:
        print(f"{R}unknown command: {args.cmd}{X}", file=sys.stderr)
        return 1
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())
