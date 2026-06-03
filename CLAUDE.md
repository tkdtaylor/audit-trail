# audit-trail — project instructions

Hash-chained, append-only forensic log. The **spine** every other ecosystem block emits to.
Go, standard library only (crypto/sha256, encoding/json, net). PolyForm Noncommercial 1.0.0.

## What this block is

A tamper-evident event log: `hash = SHA256(prev_hash + JCS(event))`; `verify()` walks the
chain and detects any byte-level change. It does **not** detect/prevent/alert — it records.
Forensic archive, not telemetry.

## Contract (frozen at v1 — do not break without a contracts bump)

- `emit(event) -> {seq, hash}` ; `verify() -> {valid, tamper_detected_at, message}`
- Canonicalization is **RFC 8785 (JCS)**. Keep floats OUT of audited events (the one place
  a naive serializer diverges from JCS — see [canonical.go](canonical.go)).
- Two transports, same verbs: **CLI** (`emit`/`verify`) and **Unix-socket IPC** (`serve`).

The authoritative spec lives in the planning hub:
the project's internal design notes and
`interface-contracts.md` (v1). Validated by the tracer-bullet reference.

## Conventions

- `go build ./...` and `go test ./...` must stay green (or `make build` / `make test`).
- `Verify()` MUST read from disk (never an in-memory copy) — that is what catches a tamper.
- Errors over IPC use the shared shape `{error:{code,message,retryable}}`.

### Go conventions
- Errors are values — return them, don't panic. Wrap with `fmt.Errorf("op: %w", err)`.
- No `else` after `return` — keep the happy path unindented (early-return pattern).
- `defer` for cleanup (close files, unlock) — runs even on panic.
- No global mutable state — chain state lives on the `Chain` struct, guarded by its mutex.
  All writes go through that single mutex (single-writer invariant).
- Table-driven tests with `t.Run`; use `t.TempDir()` for per-test logfiles.
- Anything touching `canonical()` is integrity-critical: keep it byte-stable (sorted keys, no
  insignificant whitespace, no floats). A change here silently re-keys every hash.

## Project docs & structure

The authoritative current-state spec is now in-repo (this supersedes pointing at the planning
hub for day-to-day work):

- [docs/spec/](docs/spec/) — authoritative snapshot: [SPEC.md](docs/spec/SPEC.md),
  [behaviors.md](docs/spec/behaviors.md), [architecture.md](docs/spec/architecture.md),
  [data-model.md](docs/spec/data-model.md), [interfaces.md](docs/spec/interfaces.md),
  [configuration.md](docs/spec/configuration.md), [fitness-functions.md](docs/spec/fitness-functions.md).
- [docs/architecture/overview.md](docs/architecture/overview.md) + [diagrams.md](docs/architecture/diagrams.md)
  — prose tour + C4/sequence diagrams.
- [docs/architecture/decisions/](docs/architecture/decisions/) — ADRs.
  [ADR-001](docs/architecture/decisions/001-foundational-stack.md) consolidates the existing
  stack/architecture decisions as a baseline; future decisions get their own ADR.
- [docs/CONTRACT.md](docs/CONTRACT.md) — the frozen v1 contract (mirrors the planning hub).
- [docs/tasks/](docs/tasks/) — `active/` · `backlog/` · `completed/` + `test-specs/coverage-tracker.md`.

The external planning hub (``, validated by `tracer-bullet reference`)
remains the cross-ecosystem source of truth for the *contract*; the in-repo `docs/spec/`
describes *this implementation*. When behavior changes, update the relevant `docs/spec/` file
in the same commit.

### Task lifecycle

Implementation runs through the `task-executor` agent, which calls `scripts/start-task.sh <NNN>
<slug>` to branch (`task/NNN-<slug>`) — never commit task work on `main`. Lifecycle:
🟡 feat commit → `spec-verifier` → ✅ verify commit → merge → auto-cleanup. Commit and push
after every milestone; never start the next task before committing the current one.

## Roadmap (v1+)

Signed checkpoints (RFC 6962 STH) · witness/Rekor anchoring · log rotation/checkpointing ·
indexed query API · pluggable backends (Rekor/immudb/Postgres). Keep these behind the
emit/verify seam — don't leak backend specifics into the contract.

## Recommended tooling

### Agents (`.claude/agents/`)
- **architect** (opus) — invoke for the v1+ roadmap items (checkpoints, backends). They all
  sit behind the emit/verify seam and need design judgment + an ADR. Also runs spec/code drift
  audits and proposes fitness functions.
- **security-auditor** (opus) — this *is* a security primitive; run before any change to
  `chain.go`/`canonical.go`. Focus: can a tamper slip past `verify()`, can canonicalization
  diverge, are the socket/logfile perms right.
- **spec-verifier** (sonnet) — gate completed tasks against their test spec before the verify commit.
- **code-reviewer** (sonnet) — review diffs against the conventions above before commit.
- **task-executor** (haiku) — scoped implementation of a single task file.

### Skills
- **security-review** — trigger before shipping integrity-affecting changes: "run a security
  review of the pending changes".
- **code-review** — `/code-review` on the current diff for correctness + cleanup.
- **simplify** — quality pass on changed code after heavier work.

### Hooks (already wired in `.claude/settings.json`)
- `no-commit-on-main` blocks commits on `main`; `protect-secrets` / `config-protection` guard
  edits; `spec-coverage-check` enforces test refs on active tasks at commit. Manage via
  `/update-config`.

### Fitness functions (proposed — not yet wired)
The highest-value unenforced invariant is **FF-004: no floats reach canonicalization** (today a
documented convention, not a guard). See [docs/spec/fitness-functions.md](docs/spec/fitness-functions.md).
A `make fitness` umbrella target does not exist yet; adding the first rule means adding it.

### External tools
- Standard Go toolchain only (`go`, `gofmt`). No third-party deps by design (ADR-001 D1) — keep
  it that way; if a dep is ever proposed, run it past **dependency-auditor** first.
