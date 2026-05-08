# Codex RE Methodology (CCP)

This is the workflow used to enumerate the gates documented in
`GATES.md`. Future patches should follow the same flow so that every
binary modification is traceable to a specific source-level predicate.

## 1. Anchor the binary in the source tree

The shipped darwin-arm64 build embeds full source paths in DWARF /
panic location strings. Pull them out:

```bash
BIN=/opt/homebrew/lib/node_modules/@openai/codex/node_modules/\
@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/codex/codex

strings "$BIN" \
  | grep -oE 'codex-rs/[^"[:space:]]+\.rs' \
  | sort -u > /tmp/binary-source-paths.txt
wc -l /tmp/binary-source-paths.txt   # ~1500 paths in v0.129.0
```

Clone the public source at the closest tag:

```bash
git clone --depth 1 https://github.com/openai/codex.git /tmp/codex
```

Cross-check the path list against the cloned tree:

```bash
comm -12 \
  <(sort /tmp/binary-source-paths.txt) \
  <(cd /tmp/codex && find codex-rs -name '*.rs' | sort) \
  | wc -l
```

If >90% of the embedded paths exist in the clone, the binary is built
from a HEAD-near revision and snippets in the cloned source are
faithful for predicate analysis.

## 2. Enumerate gates by grep, then read

Approval / sandbox / policy code lives in a small set of crates:

```bash
grep -rln -E "AskForApproval|SandboxPolicy::|require_approval|\
is_dangerously_bypass|NetworkDecision::|Decision::Forbidden" \
  /tmp/codex/codex-rs/{core,sandboxing,network-proxy,exec,execpolicy,\
mcp-server}/src/ 2>/dev/null
```

Open each match. For every gate, capture:

* file:line of the predicate
* the function name
* a 2-5 line snippet showing the condition
* the default behavior
* the documented bypass (CLI flag, env var, config key)

## 3. Verify each gate exists in the shipped binary

The Rust source uses string constants (`const FOO: &str = ...`) that
land in `__TEXT.__const` of the Mach-O. These are durable anchors
across rustc versions because the source string is verbatim in the
binary.

Quick check:

```bash
strings -n 30 "$BIN" | grep -F "<string from source>"
```

Anchored address with r2 (note: `iz` only scans data sections, `izz`
scans the whole binary which is needed for many embedded-include cases):

```bash
r2 -q -e bin.cache=true -c 'izz' "$BIN" \
  | grep -F "<exact string>"
```

Output line format:

```
<index>  0x<paddr>  0x<vaddr>  <len>  <maxlen>  <section>  ascii  <content>
```

Record `0x<vaddr>` as the gate anchor.

## 4. Classify the gate

Three patch tiers, in order of preference:

### 4.1 Static `__cstring` rewrite

The simplest gate. Source has `const X: &str = "..."` and the binary
has the bytes verbatim in a string section. Use `macho_replace` patch
type with a regex over the bytes. *Length must be preserved.* Common
tricks for byte parity:

* `(deny default)\n` (15 B) -> `(allow default)` (15 B; trailing `\n`
  consumed but next byte is also `\n`, syntax remains valid).
* `deny` (4 B) -> `allow` (5 B): drop a preceding space inside the
  paren, or pad after.
* "rejected by policy" (informational) -> "(bypassed by ccp)" + spaces.

### 4.2 Instruction-level `b.cond` / `tbz` flip

When the predicate compiles to a small conditional branch:

```text
cmp     w<x>, #<discriminant>
b.eq    <reject path>
... <allow path> ...
```

Find the address with r2:

```bash
r2 -q -e bin.cache=true -c "axt @0x<anchor>" "$BIN"   # xrefs to anchor
r2 -q -e bin.cache=true -c "pdf @0x<func>" "$BIN"     # disassemble caller
```

Common length-preserving edits:

* `b.eq` <-> `b.ne` (flip bit 0 of the condition field — single byte).
* `tbz` <-> `tbnz` (toggle bit 24 of the encoding — single byte).
* `b.cond <Lreject>` -> `nop` (full 4-byte rewrite, but allows the
  function to fall through to the allow path).

CCP `macho_replace` regex must match the exact 4-byte instruction (or
8-16 bytes covering the cmp+b.cond pair) and replace with the new
encoding. Always verify via `r2 -q -c 'pd 4 @<addr>'` after patching.

### 4.3 Frida runtime override

For gates that consume runtime values (config-driven booleans, hash
lookups, async results), static patches are infeasible. Use a Frida
script anchored by:

* an exported / weak symbol's mangled name, or
* an `Address.findExportByName(...)` of a constant that the function
  references (e.g. one of our string anchors).

Replace strategy:

```javascript
const fn = Module.findExportByName(null, "<mangled>");
Interceptor.replace(fn, new NativeCallback((/*args*/) => {
    return ALLOW_DISCRIMINANT;   // 0 for Decision::Allow, etc.
}, 'int', [/*arg types*/]));
```

For Rust enum returns by value, the discriminant is in `w0` (32-bit)
or `x0` for tagged unions; verify with a short `pdf` of the original
function before scripting.

## 5. Cross-reference and document

Every patch JSON in `patches/` must reference:

* the source file:line that produced the gate,
* the binary anchor address (visible via `r2 izz | grep`),
* the SHA / version of the codex binary the patch was tested against.

Add an entry to `docs/GATES.md` whenever a new gate is enumerated, even
if not yet patched, so the coverage matrix stays current.

## 6. Useful one-liners

```bash
# Strings inside a function (for enum-discriminant disassembly):
r2 -q -e bin.cache=true -c 'pdf @sym.<mangled>' "$BIN" | grep -A2 "0x<addr>"

# All xrefs to an anchor string:
r2 -q -e bin.cache=true -c 'axt @0x<vaddr>' "$BIN"

# Bytes around an offset (for hand-crafting a regex):
r2 -q -e bin.cache=true -c 'pX 64 @0x<vaddr>' "$BIN"

# Confirm a patch survived re-signing (codesign flags should match):
codesign -dvvv "$BIN" 2>&1 | head -10
```

## 7. Anti-patterns

* **Do not** rewrite `Decision::Forbidden` integer literals without
  confirming Rust's chosen discriminant ordering. Layout is not stable
  across rustc versions.
* **Do not** target inlined functions by name search alone. Use the
  string-anchored xref method.
* **Do not** ship a static patch when the only matched bytes are inside
  a `tracing::info!` or `eprintln!` template. Those are cosmetic.
* **Do** mark every patch with `required: false` if its anchor is
  fragile, so future builds don't fail wholesale when a string drifts.
