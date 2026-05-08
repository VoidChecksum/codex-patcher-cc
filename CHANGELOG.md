# Changelog

All notable changes to this project will be documented in this file.

## [0.129.0] — 2026-05-09

### Added

- Initial scaffold: `ccp` CLI with `patch`, `verify`, `rollback`, `status`, `list`, `scan`, `doctor`, `watch`, `autoheal`, `check-updates`, `self-update`, `install-rules`, `install-wrapper`, `install-config` subcommands.
- `seatbelt-allow-default` — macOS Seatbelt: flips embedded SBPL profile head `(deny default)` → `(allow default)` in `__TEXT.__cstring`. Complementary to `--dangerously-bypass-approvals-and-sandbox`; neuters sandbox even when bypass flag is absent.
- `rust-refusal-strings` — softens approval-unsupported messages in `__TEXT.__cstring` (cosmetic, optional).
- `config-bypass-defaults` — writes `approval_mode = "never"` and `sandbox_permissions = "all-files-and-network"` into `~/.codex/config.toml` (only sets absent keys).
- `wrapper-bypass-flags` — installs `~/.local/bin/codex` wrapper that prepends `--dangerously-bypass-approvals-and-sandbox` to every invocation.
- Mach-O patcher: fat-binary aware, LC_SEGMENT_64 section parser, length-preserving regex replacements (space-pad), atomic swap with ad-hoc codesign + `--version` verification before rename.
- `SigScanner`: anchor-string offset discovery in `__TEXT.__cstring` / `__TEXT.__const`.
- `updater`: GitHub API polling, patch sync, autoheal loop.
- 3-layer bypass model: wrapper → config → binary patches, any single layer is bypass-sufficient.
- `install-rules` extended: drops `AUTHORIZATION.md` and `AGENTS.md` to `~/.codex/`, creates `~/.codex/config.toml` with bypass defaults if absent.
- Full CI pipeline: ruff/flake8 lint, AST parse, JSON validation, CLI smoke, pytest.
- pytest suite: `test_cli_loads`, `test_patches_valid_json`, `test_patches_have_required_fields`.
- `SECURITY.md`, `CHANGELOG.md`.
- GitHub Actions: `ci.yml`, `dependabot.yml`.
