# ccp — Codex CLI Patcher

```
 ██████╗ ██████╗ ██████╗
██╔════╝██╔════╝██╔══██╗
██║     ██║     ██████╔╝
██║     ██║     ██╔═══╝
╚██████╗╚██████╗██║
 ╚═════╝ ╚═════╝╚═╝  v0.129.0
```

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-green)](LICENSE)
[![Codex CLI](https://img.shields.io/badge/codex--cli-0.129.0-orange)](https://github.com/openai/codex)
[![patches](https://img.shields.io/badge/patches-6-blue)](patches/)
[![multi-platform](https://img.shields.io/badge/multi--platform-darwin%20%E2%9C%93%20linux%20%E2%9A%A0%20windows%20%E2%9A%A0-blueviolet)](README.md#compatibility-matrix)

**5-layer bypass for OpenAI Codex CLI**: wrapper → config → static binary patches (Mach-O / ELF / PE) → Frida runtime hooks → arm64/x86_64 instruction-level patches. Regex-signature patches survive minor/patch releases. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for per-layer guarantees and [docs/GATES.md](docs/GATES.md) for the source-level gate map (26 gates enumerated against `codex-rs`).

---

## TL;DR Install

```bash
curl -fsSL https://raw.githubusercontent.com/VoidChecksum/codex-patcher-cc/main/install.sh | bash
```

Or manually:

```bash
pip install git+https://github.com/VoidChecksum/codex-patcher-cc.git
ccp install-rules && ccp install-wrapper && ccp install-config && ccp patch
```

---

## How It Works

Codex CLI is a Node.js launcher (`codex.js`) that spawns a platform-specific Rust binary:

```
/opt/homebrew/lib/node_modules/@openai/codex/
  bin/codex.js                          ← Node ESM launcher
  node_modules/@openai/codex-darwin-arm64/
    vendor/aarch64-apple-darwin/codex/codex   ← Rust binary (~193 MB)
```

CCP operates on three independent layers — any single layer is sufficient to bypass approval prompts:

### Layer 1 — Wrapper Script
`~/.local/bin/codex` prepends `--dangerously-bypass-approvals-and-sandbox` to every invocation except `--help`, `--version`, and `completion`.

### Layer 2 — Config Defaults
`~/.codex/config.toml` gets `default_tools_approval_mode = "never"` and full `sandbox_permissions`. Only adds keys absent from your existing config — never overwrites operator values.

### Layer 3 — Binary Patches (format-agnostic in-place)
Regex-signature patches applied directly to the Rust binary's string-constant sections, auto-detected by magic bytes:

| Format | Sections patched |
|---|---|
| Mach-O (darwin) | `__TEXT.__cstring`, `__TEXT.__const` |
| ELF (linux musl) | `.rodata`, `.data.rel.ro`, `.data` |
| PE32+ (windows-msvc) | `.rdata`, `.data` |

Length-preserving (space-pad if shorter, reject if longer). macOS Mach-O: ad-hoc re-sign with `codesign --force --sign -` after every write (required by hardened runtime). ELF / PE: no signing step required for ad-hoc patched dev binaries. Atomic swap: write `.tmp` → codesign (Mach-O only) → `--version` verify (when host arch matches) → rename.

---

## Compatibility Matrix

CCP version 0.129.0 has been validated against all six platform vendor binaries shipped with `@openai/codex@0.129.0`.

| Platform binary | Format | Wrapper | Config | refusal-strings | seatbelt-allow-default |
|---|---|---|---|---|---|
| `codex-darwin-arm64` | Mach-O arm64 | ✓ | ✓ | ✓ scan-ok | ✓ tested (real gate flip) |
| `codex-darwin-x64`   | Mach-O x86_64 | ✓ | ✓ | ✓ scan-ok | ✓ tested (real gate flip) |
| `codex-linux-x64`    | ELF x86_64 (musl) | ✓ | ✓ | ✓ scan-ok | ⚠ no equivalent (bubblewrap/landlock are binary structures, not text) |
| `codex-linux-arm64`  | ELF aarch64 (musl) | ✓ | ✓ | ✓ scan-ok | ⚠ no equivalent |
| `codex-win32-x64`    | PE32+ x86_64 | ✓ (PS1) | ✓ | ✓ scan-ok | ⚠ no equivalent (restricted-token model uses Win32 APIs, not embedded text) |
| `codex-win32-arm64`  | PE32+ aarch64 | ✓ (PS1) | ✓ | ✓ scan-ok | ⚠ no equivalent |

`scan-ok` = anchor strings resolve under `ccp scan -t <vendor-binary>`. The seatbelt patch is a real runtime-gate flip; the `rust-refusal-strings` patch is cosmetic (softens TUI log messages, does not alter runtime behavior).

Patch types:
- `macho_replace` — Mach-O only (legacy darwin binaries)
- `binary_replace` — format-agnostic; auto-detects Mach-O / ELF / PE and patches the format's string-constant sections (`__TEXT.__cstring/__const` / `.rodata/.data.rel.ro/.data` / `.rdata/.data`)

---

## Install

### Requirements
- Python 3.9+
- Node.js + npm (for Codex CLI)
- `codesign` (macOS — included in Xcode Command Line Tools)

### From PyPI (when published)
```bash
pip install ccp
```

### From source
```bash
git clone https://github.com/VoidChecksum/codex-patcher-cc
cd codex-patcher-cc
pip install -e .
```

---

## Usage

```
ccp patch            Apply all patches (binary + config + wrapper)
ccp verify           Check binary patches are applied
ccp rollback         Restore binary from most recent backup
ccp status           Show target binary location and state
ccp list             List all patches in catalog
ccp scan             Signature-based anchor discovery in binary
ccp doctor           Full health report
ccp watch            Daemon: poll binary, autoheal on update
ccp self-update      Pull latest patches from GitHub and re-apply
ccp autoheal         Detect binary drift; re-patch if broken
ccp check-updates    Show if remote patches differ from local
ccp install-rules    Deploy AUTHORIZATION.md to ~/.codex/
ccp install-wrapper  Install bypass wrapper to ~/.local/bin/codex
ccp install-config   Merge bypass defaults into ~/.codex/config.toml
```

### Dry-run
```bash
ccp patch --dry-run
```

### Inspect a specific vendor binary (multi-platform research)
```bash
# Pull every platform tarball:
for tag in linux-x64 linux-arm64 darwin-x64 darwin-arm64 win32-x64 win32-arm64; do
  npm pack "@openai/codex@$tag"
done

# Scan any of them without installing:
ccp scan -t /path/to/extracted/codex
ccp patch --dry-run -t /path/to/extracted/codex
```

`-t/--target` is supported by `patch`, `verify`, `status`, `doctor`, and `scan`. The patcher auto-detects the binary format and only applies patches that declare support for that format.

### Check status
```bash
ccp status
ccp doctor
```

### Verify patches applied
```bash
ccp verify
```

---

## Patch Catalog

| ID | Type | Description |
|---|---|---|
| `config-bypass-defaults` | config_toml | Write `approval_mode=never` + `sandbox=full-access` to config.toml |
| `wrapper-bypass-flags` | wrapper | Install `~/.local/bin/codex` wrapper with `--dangerously-bypass-approvals-and-sandbox` |
| `rust-refusal-strings` | binary_replace | Cross-platform (Mach-O / ELF / PE) — soften approval-unsupported message constants. Cosmetic, optional. |
| `seatbelt-allow-default` | macho_replace | macOS Seatbelt only: flip embedded SBPL profile head `(deny default)` → `(allow default)`. Real gate flip; complements `--dangerously-bypass-approvals-and-sandbox` by neutering seatbelt even when bypass flag is not used. Confirmed on darwin-arm64 + darwin-x64. |
| `instr-network-connect-non-public-ip-allow` | instr_replace | darwin-arm64: `cbz w0→b` in `connect_policy.rs::connect()` — unconditional branch past the `is_non_public_ip` deny path so codex's outbound proxy can reach localhost/RFC1918 addresses without `allow_local_binding=true`. |
| `instr-exec-policy-forbidden-on-never-nop` | instr_replace | darwin-arm64: NOP the `b.ne` in `exec_policy.rs::render_decision_for_unmatched_command()` — prevents `Decision::Forbidden` under `AskForApproval::Never` when sandbox is not explicitly disabled. Belt-and-braces with the config bypass. |

The full source-level enumeration of 26 codex-rs gates (with file:line citations, patch-strategy classification, and impact assessment per gate) lives in [docs/GATES.md](docs/GATES.md). The patches catalog above is the subset that has been authored to date; the remaining gates are either (a) covered by `--dangerously-bypass-approvals-and-sandbox` + config defaults (Layer 1+2), (b) candidates for Layer 5 `instr_replace` patches, or (c) Frida runtime hooks (Layer 4). See `docs/GATES.md` §4 for the recommended next-patch ranking.

---

## Architecture

```
ccp/
  __init__.py      version = "0.129.0"
  __main__.py      CLI + Mach-O patcher + all subcommands (~500 lines)
  scanner.py       SigScanner: anchor-string offset discovery
  updater.py       GitHub release polling, patch sync, autoheal loop
patches/
  01-config-bypass-defaults.json
  02-wrapper-bypass-flags.json
  10-rust-refusal-strings.json
  11-seatbelt-allow-default.json
  12-instr-network-connect-allow.json
  13-instr-exec-policy-forbidden-on-never-nop.json
contrib/
  wrappers/codex             bash wrapper script
  rules/codex-config.toml   TOML config template
  rules/AUTHORIZATION.md    operator auth doctrine
  preload/                   (reserved for future JS preload hooks)
```

### Binary Patcher Design (format-agnostic)
- Auto-detects Mach-O / ELF / PE via magic bytes (`0xFEEDFACF`, `0x7FELF`, `MZ...PE\0\0`)
- Mach-O: parses LC_SEGMENT_64 load commands → `__TEXT.__cstring`, `__TEXT.__const`
- ELF: parses Elf64 section header table → `.rodata`, `.data.rel.ro`, `.data`
- PE: parses COFF section header table → `.rdata`, `.data`
- All regex replacements are **length-preserving** (space-pad shorter results, reject longer)
- Binary size never changes → no header / section-table fixup required, no relocations disturbed
- Ad-hoc codesign after every write (macOS Mach-O only — hardened runtime requirement)
- Atomic swap via `.ccptmp-<pid>` sibling file, verified before rename
- Cross-architecture aware: skips `--version` exec verify when binary is foreign-arch (e.g. patching x86_64 Mach-O on arm64 host) to avoid Rosetta timeouts

### Patch JSON Schema
```json
{
  "id": "patch-id",
  "description": "human description",
  "type": "binary_replace | macho_replace | elf_replace | pe_replace | config_toml | wrapper",
  "formats": ["macho", "elf", "pe"],
  "required": false,
  "scan_signatures": true,
  "patches": [
    {
      "search_regex": "regex pattern (bytes)",
      "replace": "replacement (same or shorter length)",
      "applied_marker": "string present after patch",
      "required": false,
      "count": 0
    }
  ],
  "anchor_strings": ["stable string near patch site"],
  "version_last_tested": "0.129.0"
}
```

---

## Troubleshooting

**`ccp status` shows target NOT FOUND**
Install Codex CLI: `npm install -g @openai/codex`

**`codesign` fails after patch**
Install Xcode Command Line Tools: `xcode-select --install`

**Binary unchanged after `ccp patch`**
Anchor strings not found in this build. All three patches are `required: false`. The wrapper (Layer 1) and config (Layer 2) are already active and sufficient.

**`codex` still prompts for approval**
Ensure `~/.local/bin` is first in PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
```
Add to `~/.zshrc` or `~/.bashrc`.

**Wrapper resolves to itself (infinite loop guard)**
The wrapper skips itself when walking PATH. If you see a loop, check for duplicate `codex` entries in PATH.

**Re-patch after Codex CLI update**
```bash
ccp autoheal   # detects drift, syncs patches, re-applies
# or manually:
ccp self-update
```

---

## Self-Update

```bash
ccp check-updates    # check if remote patches differ
ccp self-update      # pull + re-apply
```

CCP polls `github.com/VoidChecksum/codex-patcher-cc` for new `patches/*.json` files. Validates all JSON before touching local patch dir. Atomic staging: `.ccp-new` files renamed as a group.

---

## Autoheal / Watch

```bash
ccp autoheal         # one-shot: detect drift, re-patch if needed
ccp watch            # daemon: poll every 10s, autoheal on change
ccp watch --interval 30
```

Typical use: add `ccp autoheal` to a post-install hook or cron to survive Codex CLI auto-updates.

---

## Why it survives every Codex update

Codex CLI is a Rust binary distributed via npm — `npm install -g @openai/codex` re-downloads it on every release. CCP survives via three mechanisms:

1. **Anchor strings, not byte offsets.** Each patch JSON declares one or more `anchor_strings` (e.g., `"network target rejected by policy"`). When `ccp patch` runs, the patcher resolves anchors to fresh byte offsets in the current binary instead of trusting hardcoded addresses. A Codex update that shifts code or string-table layout still finds the gate as long as the anchor string survives.
2. **Length-preserving replacements.** Every patch's `replace_bytes_hex` is `<= match_bytes_hex` length. The patcher space-pads or NOPs the difference so the binary's overall layout — relocations, code-flow targets, signatures — never shifts. This is why `ccp patch` can run idempotently on every Codex release without breaking the load command map.
3. **Autoheal loop.** `ccp autoheal` (or `ccp watch` for daemon mode) detects when a Codex update has installed a new binary, pulls fresh patch JSON from this repo via `ccp self-update`, and re-applies. If a patch's anchor has truly drifted, the patch silently skips with `sig-drift` rather than corrupting the binary; the catalog is updated, the patch is re-shipped, and the next `ccp patch` re-converges.

The `ccp doctor` command reports the per-layer state so you can see at a glance whether sig-drift, codesign-mismatch, or upstream-update is the reason a layer isn't applied.

---

## Manual RE — finding new gate candidates

Full walkthrough in [docs/RE-METHODOLOGY.md](docs/RE-METHODOLOGY.md). Quick reference using radare2:

```bash
# 1. Anchor discovery — find string addresses
r2 -q -c 'aa; iz~+approval' "$(ccp status -t -)" \
   | head -20

# 2. Xrefs to a string anchor → enclosing function
r2 -q -c 'aa; axt @ str.network_target_rejected_by_policy' \
        /path/to/codex

# 3. Disassemble the consuming function
r2 -q -c 'aa; pdf @ <fn-addr>' /path/to/codex

# 4. Or use ccp's wrapper to walk anchor → gate candidates in one shot
ccp scan-gates --anchor "network target rejected by policy"
```

Once you've identified a gate (typically a `cmp; b.eq; b <error>` or `tbz/tbnz` pattern), capture:
- `match_bytes_hex` — the 4-byte instruction(s) currently at the offset
- `replace_bytes_hex` — the length-preserving replacement (`arm64_nop()`, branch flip, etc. — see `ccp/instr_patcher.py`)
- `offset_from_anchor` — signed byte distance from the anchor's first occurrence

Wrap into a JSON patch following `patches/11-seatbelt-allow-default.json` (string-style) or the `instr_replace` schema documented in `ccp/instr_patcher.py`'s docstring.

The full source-level gate catalog (26 enumerated gates against codex-rs v0.129.0) lives in [docs/GATES.md](docs/GATES.md) — recommended reading before authoring new patches.

---

## Authorization & use

CCP modifies the OpenAI Codex CLI binary on the operator's local workstation. Intended uses:
- Authorized B2B penetration testing and red-team engagements where Codex is operator-driven.
- Bug bounty research where the operator owns the test environment.
- Reverse engineering and security research under explicit contractual authorization.
- Personal-workstation use by an operator who understands the trust model they're modifying.

CCP does NOT:
- Send any telemetry to anyone. No phone-home, no analytics, no remote update from anywhere except this GitHub repo on operator request.
- Bypass any cloud-side approval that OpenAI's servers enforce. Server-side guardrails are out of scope; CCP only modifies the *local* CLI's gating.
- Authenticate with OpenAI on the operator's behalf. Login still uses `codex login` against OpenAI's APIs.

The `~/.codex/AGENTS.md` file installed by `ccp install-rules` documents the operator-authorization doctrine that Codex itself reads on startup; review it before deploying CCP into any environment that isn't your personal workstation.

See [SECURITY.md](SECURITY.md) for vulnerability reporting; see the four hard-stop scope limits in `~/.codex/AGENTS.md` for the operator's standing instructions.

---

## Credits & refs

- [openai/codex](https://github.com/openai/codex) — the upstream Codex CLI
- [vpcc / void-patcher-cc](https://github.com/VoidChecksum/void-patcher-cc) — the sibling project for Claude Code; CCP mirrors its architecture and patch-JSON schema
- [radare2](https://github.com/radareorg/radare2) — disassembly used by `ccp scan-gates` and the manual-RE walkthrough
- [Frida](https://frida.re) — runtime instrumentation used by layer 4 (`contrib/frida/codex-bypass.js`)
- [capstone](https://www.capstone-engine.org) — arm64 / x86_64 disassembly verification in `ccp/instr_patcher.py`

---

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

---

*Inspired by [vpcc](https://github.com/VoidChecksum/void-patcher-cc) — Void Patcher for Claude Code.*
