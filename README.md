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

**3-layer bypass for OpenAI Codex CLI**: wrapper script + config defaults + in-place Rust Mach-O binary patches. Regex-signature patches survive minor/patch releases.

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

### Layer 3 — Binary Patches (Mach-O in-place)
Regex-signature patches applied directly to `__TEXT.__cstring` and `__TEXT.__const` sections of the Rust binary. Length-preserving (space-pad if shorter). macOS: ad-hoc re-sign with `codesign --force --sign -` after every write (required by hardened runtime). Atomic swap: write `.tmp` → codesign → `--version` verify → rename.

---

## Compatibility Matrix

| Codex CLI version | Wrapper | Config | Binary patches |
|---|---|---|---|
| 0.129.x | ✓ | ✓ | ✓ (tested) |
| 0.130.x+ | ✓ | ✓ | likely ✓ (regex-sig) |
| Windows | ✓ (PS1) | ✓ | placeholder |
| Linux x64/arm64 | ✓ | ✓ | planned |

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
| `rust-refusal-strings` | macho_replace | Soften approval-unsupported messages in `__TEXT.__cstring` (optional) |

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
contrib/
  wrappers/codex             bash wrapper script
  rules/codex-config.toml   TOML config template
  rules/AUTHORIZATION.md    operator auth doctrine
  preload/                   (reserved for future JS preload hooks)
```

### Mach-O Patcher Design
- Parses LC_SEGMENT_64 load commands to locate `__TEXT.__cstring` and `__TEXT.__const` sections
- All regex replacements are **length-preserving** (space-pad shorter results, reject longer)
- Binary size never changes → no Mach-O header fixup required
- Ad-hoc codesign after every write (macOS hardened runtime requirement)
- Atomic swap via `.ccptmp-<pid>` sibling file, verified before rename

### Patch JSON Schema
```json
{
  "id": "patch-id",
  "description": "human description",
  "type": "macho_replace | config_toml | wrapper",
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

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

---

*Inspired by [vpcc](https://github.com/VoidChecksum/void-patcher-cc) — Void Patcher for Claude Code.*
