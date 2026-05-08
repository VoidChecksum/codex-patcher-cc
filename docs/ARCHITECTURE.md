# CCP Architecture — five-layer bypass model

CCP doesn't rely on any single technique. Each layer covers a different
failure mode of the others. From cheapest/most-fragile to most-invasive/
most-resilient:

```
                Layer 1 — Wrapper
                ├── Layer 2 — Config
                │   ├── Layer 3 — Static binary patches
                │   │   ├── Layer 4 — Frida runtime hooks
                │   │   │   └── Layer 5 — Instruction-level patches
```

## Layer 1 — Wrapper (`~/.local/bin/codex`)

A tiny bash script that prepends `--dangerously-bypass-approvals-and-sandbox`
(and any other relevant flags) to every codex invocation, then `exec`s the
real codex binary. Lives at `contrib/wrappers/codex`.

**Strengths:**
- Trivial. No binary modification. Survives every codex update.
- Removes itself if `~/.local/bin` is removed from PATH.
- Composable with other wrappers via the `which codex` chain.

**Weaknesses:**
- Only affects invocations that pass through `~/.local/bin/codex`. Calls
  to the absolute Homebrew/npm path bypass the wrapper.
- Bypass flag must be supported by the codex version you have. New flag
  names land here first; binary patches need updating later.

**Installed by:** `ccp install-wrapper`

## Layer 2 — Config (`~/.codex/config.toml`)

Codex reads `~/.codex/config.toml` on every launch and merges values into
its in-process configuration. CCP writes a known-permissive baseline:

```toml
default_tools_approval_mode = "never"
sandbox_permissions = ["disk-full-access", "network-full-access"]
# (full key set in contrib/rules/codex-config.toml)
```

**Strengths:**
- Affects every codex launch regardless of how the binary is invoked.
- Survives codex updates as long as the keys don't change names.
- Documented, supported config surface — least likely to break under
  future codex updates.

**Weaknesses:**
- Codex's own validator may downgrade values it considers "disallowed by
  requirements" (e.g., enterprise managed-policy MDM). The static
  binary patch layer covers this.
- Requires user-writable `~/.codex/`.

**Installed by:** `ccp install-config`

## Layer 3 — Static binary patches (regex / byte rewrite)

Length-preserving regex search/replace inside the codex Mach-O / ELF / PE
binary, applied via `ccp patch`. Targets:

- Embedded sandbox profile heads (`(deny default)` → `(allow default)` —
  the seatbelt patch).
- Hardcoded enum-discriminant defaults that survive the config layer.
- Refusal/denial message templates that train the model away from
  retrying.

**Strengths:**
- Affects every code path inside the binary, not just CLI/config-derived
  state.
- Auto-coded with `applied_marker` for idempotency.
- Sig-scan recovers anchor offsets after each codex update; only patches
  whose anchors drift need re-authoring.

**Weaknesses:**
- macOS hardened-runtime requires `codesign --force --sign -` re-sign
  after every patch (CCP handles this automatically).
- Length-preservation forces creative replacement strings; long
  refusals paddable with whitespace, short ones harder.
- Can't reach gates that aren't expressed as string constants.

**Implemented in:** `ccp/__main__.py` (`type: "macho_replace"` /
`"binary_replace"`).

## Layer 4 — Frida runtime hooks

A Frida agent (`contrib/frida/codex-bypass.js`) is injected at codex
launch via the `codex-frida` wrapper. It intercepts:

- `posix_spawn` / `posix_spawnp` / `execvp` — when codex spawns a child
  under `/usr/bin/sandbox-exec` or `codex-linux-sandbox`, the agent
  rewrites argv to drop the wrapper and exec the inner command directly.
  Bypasses the kernel-level sandbox without any binary modification.
- `sandbox_init` (defense in depth) — if a future codex sandboxes itself
  in-process, the agent short-circuits the syscall to success.

**Strengths:**
- Reversible per launch — close the wrapper terminal, the next codex
  launch is back to default.
- Bypasses anti-tamper / re-validation gates that block on-disk
  modifications.
- Can hook in-process Rust gates given offsets (e.g., approval-mode
  checks, network policy enforcement).

**Weaknesses:**
- Requires `frida-tools` installed (Python, ~10 MB).
- macOS may prompt for Developer Tools authorization on first injection.
- Hook offsets for in-process gates need maintenance across codex
  versions; string-anchor resolution mitigates.

**Installed by:** `ccp install-frida`

## Layer 5 — Instruction-level patches

For gates that aren't expressed as string constants and where Frida's
runtime cost / dependency is unwanted, CCP supports an `instr_replace`
patch type (`ccp/instr_patcher.py`). It uses radare2 to resolve
anchor strings to byte offsets, then writes length-preserving
arm64/x86_64 instruction bytes.

Examples of gates that fit this layer:

- `is_dangerously_bypass_approvals_and_sandbox()` returning `false` in
  the default branch — flip to `movz w0, #1; ret`.
- Conditional `b.eq` after `cmp w0, #ApprovalMode::Never as discriminant`
  — flip to unconditional `b` to the allow path.
- `tbz` test-branch on a "managed by enterprise MDM" flag — NOP it.

**Strengths:**
- Reaches gates that have no string anchor at all.
- Same persistence model as Layer 3: applied to bytes on disk, codesign
  re-applied automatically.
- Anchor-relative offsets self-heal across codex updates within reason
  (function layout typically stable; complete rewrites of the gate
  require re-authoring).

**Weaknesses:**
- Hardest layer to author. Each patch needs an RE pass to identify the
  gate's instruction sequence.
- Verification by `match_bytes_hex` means the patch silently skips on
  any function-body change — quieter than Layer 3 mismatches but the
  patch becomes a no-op until re-authored.
- macOS hardened-runtime + codesign requirement still applies.

**Discovery helper:** `ccp/deep_scan.py` shells out to radare2 to walk
anchor → xref → function → candidate-instruction sequences for an
operator to review.

## Cross-layer guarantees

| Property                          | L1 wrapper | L2 config | L3 static | L4 Frida | L5 instr |
|-----------------------------------|:----------:|:---------:|:---------:|:--------:|:--------:|
| Survives codex update             | ✅         | ✅        | ⚠ sig-scan | ⚠ offset re-resolve | ⚠ verify-bytes |
| Idempotent                        | ✅         | ✅        | ✅         | ✅       | ✅       |
| Reversible without uninstall      | ✅         | ⚠         | ❌ (rollback) | ✅    | ❌ (rollback) |
| Works under hardened-runtime      | ✅         | ✅        | ✅ (re-sign) | ✅    | ✅ (re-sign) |
| Bypasses kernel sandbox           | ❌         | ⚠         | ✅         | ✅       | ✅       |
| Reaches in-process Rust gates     | ❌         | ⚠         | ⚠         | ✅       | ✅       |

`ccp doctor` reports per-layer install state.

## Why all five

A stripped Rust binary with hardened runtime, MDM-managed config, and
upstream classifier gating in the cloud is a hostile patching target.
Each layer covers a residual:

- L1+L2 alone: 90% of operator workflows.
- L3 adds: gates that default differently than `--dangerously-bypass`
  flag overrides.
- L4 adds: bypass without on-disk modification (anti-tamper-friendly,
  reversible, lets you toggle per session).
- L5 adds: in-process gates with no string surface.

When all layers are installed, a codex update breaks at most one layer
at a time — usually L3 sig-drift, which `ccp autoheal` re-applies from
github after the upstream patch JSON catches the new version.
