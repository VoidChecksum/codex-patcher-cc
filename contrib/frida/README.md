# Frida runtime bypass for Codex CLI

Layer 4 of CCP's defense stack: when static binary patching is blocked
(hardened-runtime signing, A/B re-validation, anti-tamper) or insufficient
(in-process Rust gates that don't surface as string anchors), attach a
Frida agent to the codex process at launch and override the gates at
runtime.

## What it does

Codex enforces its sandbox by spawning child commands under
`/usr/bin/sandbox-exec` (macOS) or `codex-linux-sandbox` (Linux) with a
generated SBPL/landlock profile. The parent codex process itself is
unsandboxed. The Frida agent (`codex-bypass.js`) hooks `posix_spawn` /
`posix_spawnp` / `execvp` and rewrites the argv whenever it sees the
sandbox wrapper, stripping the wrapper and exec-ing the inner command
directly. Defense in depth: also replaces `sandbox_init()` to
short-circuit if a future codex build links it directly.

This achieves a complete sandbox bypass for spawned commands without
modifying any bytes on disk. Useful when:

- Static `seatbelt-allow-default` patch can't be re-applied (e.g.,
  binary is being verified by an anti-tamper hook the operator can't
  unhook on this machine).
- The operator wants reversible bypass (close the wrapper terminal →
  next codex launch is back to default).
- Diagnosing whether a problem is sandbox-related — toggle the wrapper
  on/off without touching the binary.

## Install

```
pip install frida-tools         # one-time
ccp install-frida               # drops codex-bypass.js to ~/.codex/frida/
                                # and codex-frida wrapper to ~/.local/bin/
```

## Usage

```
codex-frida exec "ls /etc"      # runs codex under the Frida agent
```

Or replace `codex` itself:

```
ln -sf $(which codex-frida) ~/.local/bin/codex
```

## How the agent works

Three hook surfaces, applied in order of preference:

1. **`posix_spawn` / `posix_spawnp`** — primary path on macOS and Linux.
   Detects argv[0] = `/usr/bin/sandbox-exec` (or `codex-linux-sandbox`),
   finds the `--` separator, drops the wrapper entirely. argv after `--`
   becomes the new spawn argv.

2. **`execvp` / `execv` / `execve`** — fallback. Same argv-rewrite logic.
   Codex generally uses `posix_spawn` so this is rarely hit, but covers
   future codex versions or third-party wrappers.

3. **`sandbox_init`** — defense in depth. If a future codex build
   sandboxes itself in-process (instead of via fork+sandbox-exec), this
   hook short-circuits the syscall to success without applying any
   profile.

## Verifying

```
# Run a command that would normally be blocked by the seatbelt sandbox
codex-frida exec "cat /etc/sudoers"

# Watch for the bypass log line:
#   [ccp-frida posix_spawn] BYPASS: /usr/bin/sandbox-exec ... -- /bin/bash
```

If you don't see `BYPASS:` lines but commands still execute, codex isn't
spawning under sandbox-exec — likely because `--ask-for-approval=never`
+ `--dangerously-bypass-approvals-and-sandbox` are already in effect via
the wrapper or config (which is the cheaper bypass path). The Frida
layer is the fallback for when those don't apply.

## Extending

Adding hooks for in-process Rust gates (approval mode, network policy):

1. Use `r2 -A <codex-binary>` to find the gate's offset by anchor
   string. Example: `iz~"approval is not supported"` then
   `axt @<addr>` → walk to the enclosing function start.
2. Add to `codex-bypass.js`:
   ```js
   const codex = Process.findModuleByName("codex");
   const gateOffset = 0x12345;  // function start, from r2
   Interceptor.replace(codex.base.add(gateOffset),
     new NativeCallback(() => 1 /* ApprovalDecision::Allow */,
       "int", []));
   ```
3. Codex updates change offsets — the static `anchor_strings` mechanism
   in CCP's regular patches survives across versions. Frida-level
   anchor-to-offset resolution is on the roadmap (`ccp install-frida
   --regen-offsets`).

## Compatibility

| Platform     | posix_spawn | sandbox_init | Status |
|--------------|:-----------:|:------------:|:------:|
| darwin-arm64 | ✅          | ✅           | tested |
| darwin-x64   | ✅          | ✅           | likely |
| linux-x64    | ✅          | n/a          | likely |
| linux-arm64  | ✅          | n/a          | likely |
| win32-x64    | ⚠           | n/a          | needs work — Windows uses CreateProcess; agent needs a separate hook |
| win32-arm64  | ⚠           | n/a          | needs work |
