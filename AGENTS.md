# Agent project notes (Codex / Gemini / Antigravity)

This repo already has the detailed agent setup in [CLAUDE.md](CLAUDE.md) and `.claude/`.
Do not duplicate that machinery here. Defer to the existing Claude-oriented docs whenever possible.

## Read first

- [CLAUDE.md](CLAUDE.md) is the primary project orientation: contract, invariants,
  conventions, docs map, task lifecycle, and recommended checks.
- [docs/architecture/agent-rules.md](docs/architecture/agent-rules.md) captures retros and
  failure modes that apply to all agent work.
- [docs/spec/](docs/spec/) is the in-repo implementation spec. Update the relevant spec doc in
  the same change when behavior changes.
- [docs/CONTRACT.md](docs/CONTRACT.md) is the frozen v1 contract. Do not break it without a
  contract bump.

## Non-Claude Agent Defaults (Codex, Gemini, Antigravity)

- **Session Initialization**: Run `./scripts/session-start.sh` at the beginning of each session. This script registers the session lock (so that concurrency checks and task branching/worktree allocation work properly) and pulls relevant retros into the terminal.
- **Git Hooks**: Run `python3 scripts/setup-hooks.py` to wire the `.claude/scripts` hooks into native Git hooks.
- **Task Lifecycle**: Respect the task discipline in `CLAUDE.md`. Run `scripts/start-task.sh <NNN> <slug>` to switch to a task branch or worktree before making changes.
- Keep changes minimal and aligned with the existing Go standard-library-only design.
- Preserve the hash-chain invariants: `Verify()` reads from disk, canonicalization stays byte-stable, audited events avoid floats, and IPC errors keep the shared `{error:{code,message,retryable}}` shape.
- Use `go fmt ./...`, `go test ./...`, and `go build ./...` (or `make fmt`, `make test`, `make build`) for ordinary verification.
- For integrity-sensitive edits, especially in `chain.go` or `canonical.go`, do an explicit security-focused review.
- For runtime-visible changes, run the binary path and report the observed output.

## Hooks Compatibility & Verification

## Hooks Compatibility & Verification

For non-Claude agent hosts (like Codex), we bridge them via native Git hooks (`setup-hooks.py`) and manual discipline. 

For **Google Antigravity**, the platform natively supports workspace-local hooks via [.agents/hooks.json](.agents/hooks.json), which we have fully configured to mirror the Claude setup!

| Hook Type / Script | Claude Trigger | Git / Agent Bridge | Antigravity Support | Status / Action Needed |
|-------------------|----------------|--------------------|---------------------|------------------------|
| `no-commit-on-main.py` | Pre-bash tool | Git `pre-commit` | Natively Supported | **Works Automatically** via Git Hook & `.agents/hooks.json` |
| `spec-coverage-check.py` | Pre-bash tool | Git `pre-commit` | Natively Supported | **Works Automatically** via Git Hook & `.agents/hooks.json` |
| `block-no-verify.py` | Pre-bash tool | Git `pre-commit` | Natively Supported | **Works Automatically** (unless `--no-verify` is used) |
| `auto-cleanup-merge.py` | Post-bash tool | Git `post-merge` | Natively Supported | **Works Automatically** via Git Hook & `.agents/hooks.json` |
| `protect-secrets.py` | Pre-write/edit | None | Natively Supported | **Works Automatically** via `.agents/hooks.json` |
| `config-protection.py` | Pre-write/edit | None | Natively Supported | **Works Automatically** via `.agents/hooks.json` |
| `protect-checkout.py` | Pre-bash tool | None | Natively Supported | **Works Automatically** via `.agents/hooks.json` (supports `run_command`) |
| `session-lock.py` | Session start | `session-start.sh` | Natively Supported | **Runs via Startup Script** & `.agents/hooks.json` |
| `inject-retros.py` | Session start | `session-start.sh` | Natively Supported | **Runs via Startup Script** & `.agents/hooks.json` |
| Stop / Compaction hooks | Session end/idle | None | Natively Supported | **Works Automatically** via `.agents/hooks.json` |
