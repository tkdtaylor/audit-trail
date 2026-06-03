# Codex project notes

This repo already has the detailed agent setup in [CLAUDE.md](CLAUDE.md) and `.claude/`.
Do not duplicate that machinery here. Treat this file as the Codex entry point and defer to
the existing Claude-oriented docs whenever possible.

## Read first

- [CLAUDE.md](CLAUDE.md) is the primary project orientation: contract, invariants,
  conventions, docs map, task lifecycle, and recommended checks.
- [docs/architecture/agent-rules.md](docs/architecture/agent-rules.md) captures retros and
  failure modes that also apply to Codex work.
- [docs/spec/](docs/spec/) is the in-repo implementation spec. Update the relevant spec doc in
  the same change when behavior changes.
- [docs/CONTRACT.md](docs/CONTRACT.md) is the frozen v1 contract. Do not break it without a
  contract bump.

## Codex defaults

- Keep changes minimal and aligned with the existing Go standard-library-only design.
- Preserve the hash-chain invariants: `Verify()` reads from disk, canonicalization stays
  byte-stable, audited events avoid floats, and IPC errors keep the shared
  `{error:{code,message,retryable}}` shape.
- Use `go fmt ./...`, `go test ./...`, and `go build ./...` for ordinary verification. The
  Makefile aliases are `make fmt`, `make test`, and `make build`.
- For integrity-sensitive edits, especially in `chain.go` or `canonical.go`, do an explicit
  security-focused review before calling the work done.
- For runtime-visible changes, run the binary path and report the observed output, not just the
  unit-test result.
- When `CLAUDE.md` recommends a Claude model tier such as Opus, Sonnet, or Haiku, use the
  closest available Codex model for the same job size and risk profile.
- Respect the task discipline in `CLAUDE.md`: task work should live on a task branch created by
  `scripts/start-task.sh <NNN> <slug>` unless the user asks for a small scaffold or main-only
  maintenance change.

## Reuse the Claude setup

- Prefer the existing docs, scripts, and conventions over creating Codex-specific copies.
- The `.claude/scripts/` hooks are Claude-specific automation, but their behavior documents the
  project guardrails. If a guardrail matters to a Codex task, run the nearest existing script or
  perform the equivalent check manually.
- Keep this file short. Add only durable Codex-specific guidance here; put broader project
  lessons in [docs/architecture/agent-rules.md](docs/architecture/agent-rules.md).
