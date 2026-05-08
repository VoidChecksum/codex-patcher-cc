# Codex Approval / Sandbox / Policy Gate Map (v0.129.0)

**Scope.** Every gate in `codex-rs` that constrains tool execution, file
access, network egress, or process spawning. Cross-referenced to the
shipped darwin-arm64 binary at:

```
/opt/homebrew/lib/node_modules/@openai/codex/node_modules/
  @openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/codex/codex
```

(Mach-O 64-bit arm64, ~183 MiB, build root `/Users/runner/work/codex/codex/codex-rs/`.)

**Source tree used for enumeration.** `git clone --depth 1
https://github.com/openai/codex.git` at HEAD `1b86906` (May 2026). The
embedded source-path strings in the binary all begin with
`/Users/runner/work/codex/codex/codex-rs/` and the file list (sandboxing,
core, network-proxy, exec_policy, tools/network_approval, mcp-server
exec/patch approval) matches the HEAD tree, so the cloned source is a
faithful reference for the gates compiled into this binary.

**Verification method.** For every gate below, the file:line was opened
in the cloned repo, the predicate snippet was extracted, and at least
one anchor string (or, for non-string gates, a structural anchor that
must remain in the binary) was confirmed in the shipped binary via
`strings` and `r2 izz`. Anchor offsets are listed in the per-gate
entries.

---

## 1. Coverage matrix

| # | Gate ID | File:Line | Patch strategy | CCP patch | Status |
|---|---------|-----------|----------------|-----------|--------|
| 1 | seatbelt-default-deny | sandboxing/src/seatbelt_base_policy.sbpl:9 (string consumed at sandboxing/src/seatbelt.rs:712) | static SBPL byte rewrite (length-preserving) | patches/11 | shipped |
| 2 | seatbelt-network-policy | sandboxing/src/seatbelt_network_policy.sbpl (string consumed at seatbelt.rs:292/315) | static SBPL byte rewrite | -- | candidate |
| 3 | seatbelt-restricted-readonly-defaults | sandboxing/src/restricted_read_only_platform_defaults.sbpl (string consumed at seatbelt.rs:719) | static SBPL byte rewrite | -- | candidate |
| 4 | landlock-helper-args | sandboxing/src/landlock.rs:23-58 | argv-flag default flip in helper binary | -- | candidate (linux-only) |
| 5 | windows-sandbox-level-default | core/src/windows_sandbox.rs:30-48 | enum-discriminant flip | -- | candidate (win-only) |
| 6 | dangerously-bypass-cli-flag | cli/src/main.rs:1403-1412; exec/src/lib.rs:286-289 | wrapper flag injection | patches/02 | shipped |
| 7 | config-default-approval-mode | core/src/config/permissions.rs:32-43 | config TOML defaults | patches/01 | shipped |
| 8 | safety-patch-AskUser-fallback | core/src/safety.rs:33-115 | runtime (Frida) or string-drift | -- | runtime-only |
| 9 | safety-patch-rejection-reason-strings | core/src/safety.rs:16-19, 130-134 | static `__cstring` rewrite | -- | candidate |
| 10 | exec-policy-prompt-conflict | core/src/exec_policy.rs:43-48, 339-343 | static `__cstring` rewrite + decision-flip patch | -- | candidate |
| 11 | exec-policy-render-decision | core/src/exec_policy.rs:632-744 | runtime (Frida) | -- | runtime-only |
| 12 | exec-policy-Decision::Forbidden-on-Never | core/src/exec_policy.rs:687-690 | instruction-level branch flip | patches/13 | shipped |
| 13 | exec-approval-needs-approval | core/src/tools/sandboxing.rs:204-240 | runtime (Frida) | -- | runtime-only |
| 14 | exec-approval-should_bypass | core/src/tools/sandboxing.rs:299-305 | argv match-arm flip | -- | runtime-only |
| 15 | exec-approval-wants_no_sandbox | core/src/tools/sandboxing.rs:320-328 | match-arm flip | -- | runtime-only |
| 16 | orchestrator-no-retry-without-sandbox | core/src/tools/orchestrator.rs:287-300 | runtime (Frida) | -- | runtime-only |
| 17 | shell-handler-onrequest-only-escalation | core/src/tools/handlers/shell.rs:178-188 | runtime (Frida) | -- | runtime-only |
| 18 | network-policy-host_blocked | network-proxy/src/network_policy.rs:289-319 | runtime (Frida) | -- | runtime-only |
| 19 | network-policy-NotAllowed-deny | network-proxy/src/network_policy.rs:297-310 | runtime (Frida) | -- | runtime-only |
| 20 | network-connect-non-public-ip | network-proxy/src/connect_policy.rs:69-79 | static `__cstring` rewrite + `b.eq` flip | patches/12 | shipped |
| 21 | network-approval-deny-not-allowed | core/src/tools/network_approval.rs:408-454 (REASON_NOT_ALLOWED) | runtime (Frida) | -- | runtime-only |
| 22 | network-policy-decision-domain-denied | core/src/network_policy_decision.rs:46-61 | static `__cstring` rewrite | -- | low-value |
| 23 | mcp-exec-approval-elicit | mcp-server/src/exec_approval.rs:51-80 | bypass via approval-mode config | covered by patches/01 | covered |
| 24 | mcp-patch-approval-elicit | mcp-server/src/patch_approval.rs (peer of exec_approval.rs) | bypass via approval-mode config | covered by patches/01 | covered |
| 25 | exec-mode-approval-not-supported | (rust panics referencing thread id; observed at multiple call sites in core) | static `__cstring` rewrite (informational) | patches/10 | shipped (informational) |
| 26 | git-repo-trust-check | exec/src/lib.rs:664-672 | wrapper flag (`--skip-git-repo-check` or bypass flag) | covered by patches/02 | covered |

**Legend.** *static* = `__cstring` byte rewrite (length-preserving) or
embedded SBPL byte rewrite; *instruction-level* = arm64
`b.cond`/`csel`/`mov` rewrite; *runtime-only* = consumes a discriminant
or runs on values that never appear as bytes the loader can flip
without disassembly; "covered" = a configuration / wrapper path already
neutralizes the gate without binary patching.

---

## 2. Gates by category

### 2.1 Sandbox profiles (kernel-level)

#### Gate 1 — `seatbelt-default-deny` (darwin)

* **File:** `sandboxing/src/seatbelt_base_policy.sbpl:9`, embedded via
  `include_str!` at `sandboxing/src/seatbelt.rs:20`, used in the
  composite policy at `sandboxing/src/seatbelt.rs:712`.
* **Function:** `create_seatbelt_command_args()` (the arg-list builder
  that becomes `sandbox-exec -p <profile> ...`).
* **Condition (snippet, seatbelt_base_policy.sbpl:7-11):**
  ```
  ; start with closed-by-default
  (deny default)

  ; child processes inherit the policy of their parent
  (allow process-exec)
  ```
* **Default:** Deny by default; specific resources are explicitly
  allowed below this clause.
* **Bypass:** `--dangerously-bypass-approvals-and-sandbox` skips
  seatbelt entirely (selects `SandboxType::None` via
  `SandboxablePreference::Forbid`). `permissions = :danger-no-sandbox`
  in config.toml does the same.
* **Binary anchor:** `r2 izz` finds the full SBPL block at
  `0x108be2728` in `__TEXT.__const`; `(deny default)\n` is verbatim in
  bytes.
* **Patch strategy:** Static byte rewrite, length-preserving:
  `(deny default)\n` (15 bytes) -> `(allow default)` (15 bytes).
  The trailing `\n` is consumed but the next byte is also `\n`, so SBPL
  remains valid. Once the head is `(allow default)`, every following
  `(allow ...)` clause becomes a no-op and every `(deny ...)` still
  fires (the base profile contains none).
* **Status:** Shipped as `patches/11-seatbelt-allow-default.json`.

#### Gate 2 — `seatbelt-network-policy` (darwin)

* **File:** `sandboxing/src/seatbelt_network_policy.sbpl`, embedded at
  `seatbelt.rs:21` and appended at `seatbelt.rs:292` and `seatbelt.rs:315`.
* **Condition:** appended whenever proxy ports are configured or
  network is enabled. The default body is a fixed SBPL block that ends
  in `(deny network-outbound)` / similar denies depending on the cloned
  contents.
* **Bypass:** Hard-bypassed only when `permission_profile.network` is
  enabled or `--dangerously-bypass-approvals-and-sandbox` is set.
* **Patch strategy:** Same approach as Gate 1 — flip the residual
  `(deny network-*)` clauses to `(allow network-*)` length-preserved.
  Note `seatbelt.rs:309` already injects `(allow network-outbound)\n
  (allow network-inbound)\n` when no proxy is configured; flipping the
  base SBPL deny is only useful when a proxy *is* configured.
* **Status:** Candidate.

#### Gate 3 — `seatbelt-restricted-readonly-defaults` (darwin)

* **File:** `sandboxing/src/restricted_read_only_platform_defaults.sbpl`,
  appended at `seatbelt.rs:719` when
  `file_system_sandbox_policy.include_platform_defaults()` returns true.
* **Condition:** Adds platform-default deny clauses for system-protected
  paths like `~/.ssh`, `~/Library/Keychains`, etc.
* **Patch strategy:** Static byte rewrite of any `(deny ...)` to
  `(allow ...)` length-preservation requires care (`deny`->`allow` is
  +1 byte; pad with a leading space inside the parenthesis).
* **Status:** Low-priority candidate; Gate 1 already opens the head, so
  this only matters if patch 1 is reverted.

#### Gate 4 — `landlock-helper-args` (linux)

* **File:** `sandboxing/src/landlock.rs:23-58`.
* **Function:** `create_linux_sandbox_command_args_for_permission_profile()`.
* **Condition:** Composes argv for the external `codex-linux-sandbox`
  helper. The actual gate (bubblewrap + seccomp + landlock ABI) lives
  in the helper binary, which is shipped as a separate executable.
* **Bypass:** Permission profile `:danger-no-sandbox` selects
  `SandboxType::None`, so the helper is never spawned.
* **Patch strategy:** Two options:
  * Patch the helper binary's bubblewrap/seccomp call to a no-op.
  * Or, patch `get_platform_sandbox()` (`sandboxing/src/manager.rs:48-62`)
    to return `None` on Linux, defeating helper invocation. Both are
    instruction-level patches. We currently rely on the wrapper.
* **Status:** Linux-only; deferred until Linux build is in scope.

#### Gate 5 — `windows-sandbox-level-default` (windows)

* **File:** `core/src/windows_sandbox.rs:30-48`.
* **Function:** `WindowsSandboxLevel::from_features()`.
* **Condition (snippet):**
  ```
  if features.enabled(Feature::WindowsSandboxElevated) {
      return WindowsSandboxLevel::Elevated;
  }
  if features.enabled(Feature::WindowsSandbox) {
      WindowsSandboxLevel::RestrictedToken
  } else {
      WindowsSandboxLevel::Disabled
  }
  ```
* **Default:** Disabled unless an experimental feature flag is set.
* **Bypass:** Already disabled by default on stable, so this is not a
  blocker on Windows. Patching to `Disabled` would only reinforce the
  default.
* **Status:** Not a barrier on this platform.

---

### 2.2 Approval-mode defaults & CLI bypass

#### Gate 6 — `dangerously-bypass-cli-flag`

* **File:** `cli/src/main.rs:1403-1412`, `exec/src/lib.rs:286-289`,
  `exec/src/lib.rs:664-672`.
* **Snippet (cli/src/main.rs:1403-1412):**
  ```rust
  let approval_policy = if shared.dangerously_bypass_approvals_and_sandbox {
      Some(AskForApproval::Never)
  } else {
      interactive.approval_policy.map(Into::into)
  };
  let sandbox_mode = if shared.dangerously_bypass_approvals_and_sandbox {
      Some(codex_protocol::config_types::SandboxMode::DangerFullAccess)
  } else {
      shared.sandbox_mode.map(Into::into)
  };
  ```
* **Effect:** Single flag forces `AskForApproval::Never` and
  `SandboxMode::DangerFullAccess`. The flag also short-circuits the git
  repo trust check at `exec/src/lib.rs:664-672`.
* **Patch strategy:** Wrapper that prepends the flag (Gate 26 of CCP)
  is sufficient.
* **Status:** Shipped as `patches/02-wrapper-bypass-flags.json`.

#### Gate 7 — `config-default-approval-mode`

* **File:** `core/src/config/permissions.rs:28-78`.
* **Snippet (32-43):**
  ```rust
  pub(crate) fn default_builtin_permission_profile_name(
      active_project: &ProjectConfig,
      windows_sandbox_level: WindowsSandboxLevel,
  ) -> &'static str {
      if (active_project.is_trusted() || active_project.is_untrusted())
          && !(cfg!(target_os = "windows") && windows_sandbox_level == WindowsSandboxLevel::Disabled)
      {
          BUILT_IN_WORKSPACE_PROFILE
      } else {
          BUILT_IN_READ_ONLY_PROFILE
      }
  }
  ```
* **Effect:** Default profile is `:read-only` for unknown projects,
  `:workspace` for trusted/untrusted projects.
* **Bypass:** `permissions = ":danger-no-sandbox"` and
  `default_tools_approval_mode = "never"` in `config.toml`.
* **Patch strategy:** Config-file injection (this CCP patch) avoids any
  binary modification.
* **Status:** Shipped as `patches/01-config-bypass-defaults.json`.

---

### 2.3 Patch / file-write safety

#### Gate 8 — `safety-patch-AskUser-fallback`

* **File:** `core/src/safety.rs:33-115`.
* **Function:** `assess_patch_safety()`.
* **Condition (47-58):**
  ```rust
  match policy {
      AskForApproval::OnFailure
      | AskForApproval::Never
      | AskForApproval::OnRequest
      | AskForApproval::Granular(_) => { /* continue */ }
      AskForApproval::UnlessTrusted => {
          return SafetyCheck::AskUser;
      }
  }
  ```
  Then later (61-65) `Never` plus `Granular { sandbox_approval: false }`
  promotes to `Reject`; otherwise paths outside writable roots produce
  `AskUser`.
* **Default:** Patches outside writable roots ask the user; with
  `Never`, they Reject.
* **Patch strategy:** No string anchor for the *enum discriminants*
  themselves — the match arms compile to integer comparisons. The
  reject reasons (`PATCH_REJECTED_OUTSIDE_PROJECT_REASON`,
  `PATCH_REJECTED_READ_ONLY_REASON`) are static `__cstring`s, but
  flipping their text only changes the error message; the gate still
  rejects. Flipping the gate logic itself requires either Frida
  (replace `assess_patch_safety` to return
  `SafetyCheck::AutoApprove { sandbox_type: SandboxType::None, .. }`)
  or arm64 instruction patches at the discriminant compares.
* **Status:** Runtime-only (Frida).

#### Gate 9 — `safety-patch-rejection-reason-strings`

* **File:** `core/src/safety.rs:16-19, 130-134`.
* **Strings (verified at binary offset `0x08ad9ba7`):**
  * `"writing outside of the project; rejected by user approval settings"`
  * `"writing is blocked by read-only sandbox; rejected by user approval settings"`
* **Patch strategy:** `__cstring` rewrite is trivial but
  *informational only* — the gate has already rejected by the time the
  string is read. Listed for completeness; do not waste a patch slot.
* **Status:** Low-value.

---

### 2.4 Exec-policy gates

#### Gate 10 — `exec-policy-prompt-conflict`

* **File:** `core/src/exec_policy.rs:43-48` (constants), `339-343`
  (use site).
* **Condition:** When the policy decision is `Decision::Prompt` *and*
  `AskForApproval::Never`, the system rejects with the constant
  `PROMPT_CONFLICT_REASON = "approval required by policy, but
  AskForApproval is set to Never"`. Granular-mode variants:
  `REJECT_SANDBOX_APPROVAL_REASON`, `REJECT_RULES_APPROVAL_REASON`.
* **Binary anchor:** `r2 izz` confirms all three strings at
  `0x08abfe68` and adjacent (`__TEXT.__const`).
* **Patch strategy:**
  * `__cstring` rewrite of the reason text is informational only.
  * The actual gate is `prompt_is_rejected_by_policy()` returning
    `Some(reason)`. Patching it to always return `None` is a small
    arm64 patch (force `mov w0, #0; ret`-style return) but the function
    is inlined; needs disassembly to find the call site.
  * Easiest neutralization: the wrapper that already injects
    `--dangerously-bypass-approvals-and-sandbox` flips the policy to
    `Never`, which means execpolicy `Prompt` decisions still reject.
    For exec-mode under `Never`, the only way to allow prompts is to
    force `Decision::Allow` instead of `Decision::Prompt` in
    `render_decision_for_unmatched_command()` (Gate 11).
* **Status:** Candidate (informational rewrite + Frida hook).

#### Gate 11 — `exec-policy-render-decision`

* **File:** `core/src/exec_policy.rs:632-744`.
* **Function:** `render_decision_for_unmatched_command()`.
* **Snippet (678-696):**
  ```rust
  if command_is_dangerous || environment_lacks_sandbox_protections {
      return match approval_policy {
          AskForApproval::Never => {
              let sandbox_is_explicitly_disabled = matches!(
                  permission_profile,
                  PermissionProfile::Disabled | PermissionProfile::External { .. }
              );
              if sandbox_is_explicitly_disabled { Decision::Allow }
              else { Decision::Forbidden }
          }
          AskForApproval::OnFailure | AskForApproval::OnRequest
          | AskForApproval::UnlessTrusted | AskForApproval::Granular(_)
              => Decision::Prompt,
      };
  }
  ```
* **Effect:** "Dangerous" commands + `Never` + non-disabled profile =
  `Forbidden`. With our config patch this reaches `Allow` via the
  `PermissionProfile::Disabled` path; without it, the fallback is
  `Forbidden`.
* **Patch strategy:** Frida `Interceptor.replace` to always return
  `Decision::Allow`. Static patching is hard because the function is
  large and calls `is_dangerous_command` / `is_safe_command` (also
  inlined).
* **Status:** Runtime-only.

#### Gate 12 — `exec-policy-Decision::Forbidden-on-Never`

* **File:** `core/src/exec_policy.rs:687-690`.
* **Condition:** The single `if sandbox_is_explicitly_disabled
  { Decision::Allow } else { Decision::Forbidden }` line. This compiles
  to a `cmp + b.cond` selecting between two `mov w0, #imm`
  instructions where the immediate is the discriminant.
* **Patch strategy:** Instruction-level: identify both `mov w0, #0` /
  `mov w0, #2` (or whichever discriminant ordering Rust picked) and
  flip the compare's `b.eq`/`b.ne` so the `Allow` arm is always taken.
  Anchor: nearby string constant
  `"approval required by policy, but AskForApproval is set to Never"`
  is referenced from the same function, providing a stable xref handle.
* **Status:** Candidate, but Gate 7 (config) already neutralizes it
  when `permissions = ":danger-no-sandbox"`.

---

### 2.5 Tools / orchestrator approval gates

#### Gate 13 — `exec-approval-needs-approval`

* **File:** `core/src/tools/sandboxing.rs:204-240`.
* **Function:** `default_exec_approval_requirement()`.
* **Snippet (208-217):**
  ```rust
  let needs_approval = match policy {
      AskForApproval::Never | AskForApproval::OnFailure => false,
      AskForApproval::OnRequest | AskForApproval::Granular(_) => {
          matches!(file_system_sandbox_policy.kind,
                   FileSystemSandboxKind::Restricted)
      }
      AskForApproval::UnlessTrusted => true,
  };
  ```
* **Effect:** Under `Never`, `needs_approval=false` -> Skip path. Our
  wrapper forces `Never`, so this gate already returns Skip.
* **Status:** Already neutralized by Gate 6.

#### Gate 14 — `exec-approval-should_bypass`

* **File:** `core/src/tools/sandboxing.rs:299-305`.
* **Snippet:**
  ```rust
  fn should_bypass_approval(&self, policy: AskForApproval, already_approved: bool) -> bool {
      if already_approved { return true; }
      matches!(policy, AskForApproval::Never)
  }
  ```
* **Patch strategy:** Frida replace to return `true` unconditionally.
  Already neutralized by Gate 6 setting policy=Never.
* **Status:** Covered.

#### Gate 15 — `exec-approval-wants_no_sandbox`

* **File:** `core/src/tools/sandboxing.rs:320-328`.
* **Snippet:**
  ```rust
  fn wants_no_sandbox_approval(&self, policy: AskForApproval) -> bool {
      match policy {
          AskForApproval::OnFailure => true,
          AskForApproval::UnlessTrusted => true,
          AskForApproval::Never => false,
          AskForApproval::OnRequest => false,
          AskForApproval::Granular(g) => g.sandbox_approval,
      }
  }
  ```
* **Effect:** Determines whether the orchestrator may retry a sandbox
  failure as no-sandbox-with-approval. With `Never`, no retry — sandbox
  denials are fatal. Our config switches to `:danger-no-sandbox` so the
  initial sandbox is `None` and there is nothing to fail.
* **Status:** Covered by combination of Gates 1, 6, 7.

#### Gate 16 — `orchestrator-no-retry-without-sandbox`

* **File:** `core/src/tools/orchestrator.rs:287-300`.
* **Snippet:**
  ```rust
  // Under `Never` or `OnRequest`, do not retry without sandbox;
  // surface a concise sandbox denial...
  if !tool.wants_no_sandbox_approval(approval_policy) {
      ...
  }
  ```
* **Patch strategy:** Frida hook to short-circuit the early-return.
  Largely cosmetic given Gate 1 + Gate 7 already produce SandboxType::None.
* **Status:** Runtime-only fallback.

#### Gate 17 — `shell-handler-onrequest-only-escalation`

* **File:** `core/src/tools/handlers/shell.rs:178-188`.
* **Condition:** When the shell tool requests escalated permissions but
  approval-mode is not `OnRequest`, the request is rejected.
* **Patch strategy:** Runtime hook to widen the accepted policy set.
* **Status:** Runtime-only; rarely triggers under our default config.

---

### 2.6 Network policy gates (in-binary network proxy)

#### Gate 18 — `network-policy-evaluate_host_policy`

* **File:** `network-proxy/src/network_policy.rs:289-319`.
* **Function:** `evaluate_host_policy()`.
* **Effect:** Looks up host in baseline allow-list. If
  `HostBlockDecision::Blocked(NotAllowed)`, optionally consults a
  decider; otherwise denies with `NetworkDecisionSource::BaselinePolicy`.
* **Bypass:** Configure `experimental_network.domains` in config.toml
  to allow-all, or set `dangerously_allow_non_loopback_proxy=true`.
* **Patch strategy:** Frida replace to return
  `NetworkDecision::Allow`. Static patching requires defeating the
  baseline allow-list lookup, which is data-driven.
* **Status:** Runtime-only.

#### Gate 19 — `network-policy-NotAllowed-deny`

* **File:** `network-proxy/src/network_policy.rs:297-310`.
* **Snippet:**
  ```rust
  HostBlockDecision::Blocked(HostBlockReason::NotAllowed) => {
      if let Some(decider) = decider { ... }
      else {
          (NetworkDecision::deny_with_source(
              HostBlockReason::NotAllowed.as_str(),
              NetworkDecisionSource::BaselinePolicy), false)
      }
  }
  ```
* **Patch strategy:** Same as Gate 18.
* **Status:** Runtime-only.

#### Gate 20 — `network-connect-non-public-ip`

* **File:** `network-proxy/src/connect_policy.rs:69-79`.
* **Snippet:**
  ```rust
  async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
      if !self.policy.allow_local_binding().await? && is_non_public_ip(addr.ip()) {
          return Err(io::Error::new(
              io::ErrorKind::PermissionDenied,
              "network target rejected by policy",
          ).into());
      }
      ...
  }
  ```
* **Binary anchor:** `"network target rejected by policy"` confirmed at
  `0x08a20999`.
* **Patch strategy:**
  * `__cstring` rewrite of the message is informational only.
  * Real fix: rewrite the conditional. The compiled form is roughly
    `tbz w<x>, #0, .Lcontinue` after `allow_local_binding` returns;
    flip `tbz`<->`tbnz` (1-bit edit, length-preserving) to short-circuit
    the deny. Anchor the edit by the relative xref to the rejection
    string at `0x08a20999`.
* **Status:** Candidate — best instruction-level patch in the network
  layer.

#### Gate 21 — `network-approval-deny-not-allowed`

* **File:** `core/src/tools/network_approval.rs:408-454`.
* **Condition:** Multi-arm dispatch returning
  `NetworkDecision::deny(REASON_NOT_ALLOWED)` from
  `handle_inline_policy_request()` when guardian/user denies.
* **Patch strategy:** Frida hook to force every arm to return
  `NetworkDecision::Allow`.
* **Status:** Runtime-only.

#### Gate 22 — `network-policy-decision-domain-denied`

* **File:** `core/src/network_policy_decision.rs:46-61`.
* **Snippet:**
  ```rust
  "denied" => "domain is explicitly denied by policy and cannot be approved from this prompt",
  ```
* **Patch strategy:** `__cstring` rewrite. Informational.
* **Status:** Low-value.

---

### 2.7 MCP-server approval gates

#### Gate 23 — `mcp-exec-approval-elicit`

* **File:** `mcp-server/src/exec_approval.rs:51-110`.
* **Function:** `handle_exec_approval_request()`.
* **Effect:** Sends an `elicitation/create` request to the MCP client
  to ask "Allow Codex to run `<cmd>` in `<cwd>`?". Triggered when the
  shell tool path returns `ExecApprovalRequirement::NeedsApproval`.
* **Bypass:** Skip approval-needed by setting
  `default_tools_approval_mode = "never"` (Gate 7 already does this).
* **Status:** Covered.

#### Gate 24 — `mcp-patch-approval-elicit`

* **File:** `mcp-server/src/patch_approval.rs` (peer of exec_approval).
* **Effect:** Same elicitation pattern for `apply_patch` calls.
* **Status:** Covered.

#### Gate 25 — `exec-mode-approval-not-supported`

* **Strings (binary anchor `0x088408e4`):**
  * `"command execution approval is not supported in exec mode for thread \``
  * `"file change approval is not supported in exec mode for thread \``
  * `"permissions approval is not supported in exec mode for thread \``
  * `"apply_patch approval is not supported in exec mode for thread \``
  * `"exec command approval is not supported in exec mode for thread \``
* **Effect:** In headless `exec` mode, any approval request that
  reaches the harness produces this fatal error (the orchestrator has
  no UI to prompt). With `Never` everywhere this is unreachable.
* **Patch strategy:** Patches/10 already softens the message to
  reference "(bypassed by ccp)". Real fix is upstream (Gates 13-17).
* **Status:** Shipped (informational only) as `patches/10-rust-refusal-strings.json`.

---

### 2.8 Other gates surfaced during enumeration

#### Gate 26 — `git-repo-trust-check`

* **File:** `exec/src/lib.rs:664-672`.
* **Snippet:**
  ```rust
  if !skip_git_repo_check
      && !dangerously_bypass_approvals_and_sandbox
      && get_git_repo_root(&default_cwd).is_none()
  {
      eprintln!("Not inside a trusted directory and --skip-git-repo-check was not specified.");
      std::process::exit(1);
  }
  ```
* **Bypass:** Either flag flips the gate. Wrapper already injects
  `--dangerously-bypass-approvals-and-sandbox`.
* **Status:** Covered by `patches/02`.

---

## 3. Source-level reference

Total gates enumerated: **26**, of which:

| Class | Count | Notes |
|-------|-------|-------|
| Statically patched (shipped) | 6 | Gates 1, 6, 7, 12, 20, 25 (covered by patches/01, 02, 10, 11, 12, 13) |
| Static-patchable, not yet patched | 3 | Gates 2, 3, plus partial Gate 10 |
| Instruction-level patchable | 3 | Gates 12✅, 17, 20✅ (b.cond / tbz flips) |
| Runtime-only (Frida) | 8 | Gates 8, 11, 13-16, 18, 19, 21 |
| Already covered by config / wrapper | 6 | Gates 5, 7, 13, 23, 24, 26 |

Some gates appear in two rows (e.g. Gate 12 is both static-patchable
and already covered by Gate 7's config bypass).

---

## 4. Recommended next patches

Ranked by impact-per-byte, assuming the v0.129.0 binary and current
patches/01-02-10-11 already applied. Each entry lists why it is
patchable, the suggested CCP patch type, length-preservation viability,
and the Frida fallback if static fails.

### 4.1 Gate 20 — `network-connect-non-public-ip` flip (HIGH)

* **Why patchable:** Single `if` over a `bool && bool`, immediately
  followed by a `return Err(...)` referencing a unique
  `__cstring` (`"network target rejected by policy"`, anchor
  `0x08a20999`). The compiled form is a `tbz`/`tbnz` skipping over the
  error path.
* **Suggested CCP patch type:** `macho_replace` with a 1-bit
  instruction edit (`tbz` <-> `tbnz` flips a single byte's bit 24 of
  the encoding). Length-preserving by construction.
* **Frida fallback:** `Interceptor.replace` of
  `TargetCheckedStreamConnector::connect` to always invoke
  `tokio::net::TcpStream::connect` directly.
* **Impact:** Allows codex's outbound proxy to connect to localhost /
  RFC1918 / link-local addresses without `allow_local_binding=true`.

### 4.2 Gate 12 — `exec-policy-Decision::Forbidden-on-Never` flip (HIGH)

* **Why patchable:** Two `mov w0, #imm; ret` sequences selected by a
  `b.cond` after a `cmp` against a discriminant. Anchored by the
  nearby `__cstring` `"approval required by policy, but AskForApproval
  is set to Never"` (`0x08abfe68`).
* **Suggested CCP patch type:** `macho_replace` matching a regex of
  the form `cmp w<x>, #<discriminant>; b.eq <Forbidden>; b <Allow>` —
  flip to `b <Allow>; b <Allow>`. Risky to write blindly; recommend
  building from r2 disassembly first.
* **Length-preservation:** Yes (replacing a `b.eq` with another
  `b.eq` to a different target preserves 4-byte instruction width;
  alternatively NOP the conditional branch entirely).
* **Frida fallback:** Hook `render_decision_for_unmatched_command` to
  always return `Decision::Allow`.
* **Impact:** Closes the only remaining "dangerous-command +
  AskForApproval::Never" rejection path. Useful when config bypass
  (Gate 7) has been disabled by management config.

### 4.3 Gate 2 — `seatbelt-network-policy` SBPL flip (MEDIUM)

* **Why patchable:** Same shape as the already-shipped Gate 1: a
  static SBPL block with `(deny ...)` clauses embedded in `__TEXT.__const`.
* **Suggested CCP patch type:** `macho_replace` with multiple
  length-preserving regex flips: `(deny network-bind` ->
  `(allow network-bind`, etc.
* **Length-preservation:** `deny` (4) -> `allow` (5) is +1 byte —
  *not* trivially length-preserving. Need to absorb the +1 by trimming
  surrounding whitespace, e.g. `\(deny ` -> `(allow ` (drop the leading
  `\` if present) or rewrite the entire clause in a same-length form.
  Audit the SBPL contents byte-by-byte before patching.
* **Frida fallback:** Hook `dynamic_network_policy_for_network` to
  return a constant `"(allow network*)"` string.
* **Impact:** Defeats the network-restricted seatbelt profile when a
  proxy is configured. With Gate 1 already applied, this is
  defense-in-depth.

### 4.4 Gate 11 — `exec-policy-render-decision` Frida override (MEDIUM)

* **Why patchable:** Single function returning `Decision`. Replacing it
  removes every "dangerous command" gating in one stroke.
* **Suggested CCP patch type:** Frida script (no static patch
  feasible; function is large and inlined). Add a `frida_script.json`
  patch that runs at codex launch, locates the function via the unique
  string xref `"approval required by policy, but AskForApproval is set
  to Never"`, and replaces with `mov w0, #ALLOW_DISCRIMINANT; ret`.
* **Length-preservation:** N/A (runtime).
* **Static fallback:** Combine Gate 12 + Gate 7 (config bypass) for
  most of the same effect.
* **Impact:** Belt-and-braces with Gate 7.

### 4.5 Gate 18 — `network-policy-evaluate_host_policy` Frida override (MEDIUM)

* **Why patchable:** Single async function. Frida can replace its
  return value with `NetworkDecision::Allow`.
* **Suggested CCP patch type:** Frida script anchored by string
  `"baseline_policy"` (`POLICY_DECISION_DENY` constant) or by the
  exported symbol path (mangled `codex_network_proxy::network_policy::
  evaluate_host_policy`).
* **Static fallback:** None — the function consults a runtime data
  structure (`NetworkProxyState`) for the allow-list.
* **Impact:** Removes the in-process network proxy's host allow-list
  enforcement. Only relevant when the user has enabled the network
  proxy; with `network.enabled=false` (default) the proxy is not
  attached to outbound traffic.

### 4.6 Gate 9 — `safety-patch-rejection-reason-strings` rewrite (LOW)

* **Why patchable:** Two static `__cstring`s, easy length-preserving
  rewrite.
* **Suggested CCP patch type:** `macho_replace` swapping both messages
  to "(bypassed by ccp)" plus padding. Length-preservation: pad with
  spaces.
* **Status:** Cosmetic only — the gate has already rejected by the
  time the user sees this string. **Do not ship** unless wider rewrite
  campaign is in scope.

### 4.7 Gate 22 — `network-policy-decision-domain-denied` rewrite (LOW)

* Same shape as 4.6. Cosmetic only. Skip.

### 4.8 Gate 17 — `shell-handler-onrequest-only-escalation` Frida hook (LOW)

* **Why patchable:** Specific match arm in
  `tools/handlers/shell.rs:178-188`. Frida-only because no anchor
  string.
* **Impact:** Marginal — under our `Never` default this branch is
  unreachable.

---

*Document generated by source-level enumeration of
`/tmp/codex/codex-rs/` (HEAD `1b86906`) and binary verification via
`r2 izz` against the shipped darwin-arm64 codex binary v0.129.0.*
