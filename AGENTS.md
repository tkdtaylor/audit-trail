# audit-trail — Agent briefing (canonical)

This is the **canonical, harness-neutral briefing** for audit-trail. It is the
single source of truth for project context, the frozen contract, commands,
conventions, the task workflow, verification expectations, commit rules, and the
load-bearing process rules every agent must follow.

Every coding-agent harness loads this file:

- **Codex** auto-loads `AGENTS.md` (this file).
- **Antigravity / Gemini** load it via `GEMINI.md` (a symlink to this file). Those
  hosts also bridge the project hooks — see *Harness notes* at the end.
- **Claude Code** loads `CLAUDE.md`, which imports this file (`@AGENTS.md`) and adds
  the Claude-specific mechanics (skills, subagents, hook profiles).

Keep this file harness-neutral. Anything that only one harness understands belongs
in that harness's layer (`CLAUDE.md` for Claude Code), not here.

## What this block is

audit-trail is a hash-chained, append-only forensic log — the **spine** every other
ecosystem block emits to. A tamper-evident event log:
`hash = SHA256(prev_hash + JCS(event))`; `verify()` walks the chain and detects any
byte-level change. It does **not** detect/prevent/alert — it records. Forensic
archive, not telemetry.

Go, standard library only (`crypto/sha256`, `encoding/json`, `net`). Apache-2.0.

## Contract (frozen at v1 — do not break without a contracts bump)

- `emit(event) -> {seq, hash}` ; `verify() -> {valid, tamper_detected_at, message}`
- Canonicalization is **RFC 8785 (JCS)**. Keep floats OUT of audited events (the one
  place a naive serializer diverges from JCS — see [canonical.go](canonical.go)).
- Two transports, same verbs: **CLI** (`emit`/`verify`) and **Unix-socket IPC**
  (`serve`).

The authoritative contract statement is [docs/CONTRACT.md](docs/CONTRACT.md) (v1),
validated by the ecosystem tracer-bullet. The
in-repo `docs/spec/` describes *this implementation*. When behavior changes, update
the relevant `docs/spec/` file in the same commit.

## Commands

```bash
go build ./...                    # compile everything (or: make build)
go test ./...                     # run tests (or: make test)
go fmt ./...                      # format (or: make fmt)
```

`go build ./...` and `go test ./...` must stay green. A `make fitness` umbrella
target does not exist yet; adding the first fitness rule means adding it (see
[docs/spec/fitness-functions.md](docs/spec/fitness-functions.md)).

## Conventions

- `Verify()` MUST read from disk (never an in-memory copy) — that is what catches a
  tamper.
- Errors over IPC use the shared shape `{error:{code,message,retryable}}`.

### Go conventions

- Errors are values — return them, don't panic. Wrap with `fmt.Errorf("op: %w", err)`.
- No `else` after `return` — keep the happy path unindented (early-return pattern).
- `defer` for cleanup (close files, unlock) — runs even on panic.
- No global mutable state — chain state lives on the `Chain` struct, guarded by its
  mutex. All writes go through that single mutex (single-writer invariant).
- Table-driven tests with `t.Run`; use `t.TempDir()` for per-test logfiles.
- Anything touching `canonical()` is integrity-critical: keep it byte-stable (sorted
  keys, no insignificant whitespace, no floats). A change here silently re-keys every
  hash.

## Integrity invariants (load-bearing — this is a security primitive)

Violating one of these can let a tamper slip past `verify()`. Treat them as
non-negotiable:

- `Verify()` reads from disk, never an in-memory copy.
- Canonicalization stays byte-stable (RFC 8785 / JCS — sorted keys, no insignificant
  whitespace, no floats).
- Audited events avoid floats.
- IPC errors keep the shared `{error:{code,message,retryable}}` shape.
- For integrity-sensitive edits, especially in `chain.go` or `canonical.go`, do an
  explicit security-focused review before commit.
- For runtime-visible changes, run the binary path and report the observed output.

## Design principles

This project follows **Unix philosophy** as its default design approach — favoring
**composability over monolithic design**. Complex behavior should emerge from
combining small, independent components that communicate through standardized
interfaces, not by growing one large one. The short version is four structural
properties to design for:

- **Modularity** — independent units that can be built, understood, and changed on
  their own
- **Interface standardization** — stable, well-defined contracts between components
  (the frozen emit/verify seam, plain-text formats)
- **Maintainability** — changes in one module should not cascade across unrelated
  ones
- **Reusability** — components should be liftable into another project without
  entanglement

Derived working rules: one thing well; small composable pieces over large
configurable ones; plain text for configs and interchange; explicit over implicit;
fail fast and crash loudly on unexpected state; test in isolation; defer premature
decisions. Keep the v1+ roadmap items behind the emit/verify seam — don't leak
backend specifics into the contract.

## Project docs & structure

The authoritative current-state spec is in-repo:

- [docs/spec/](docs/spec/) — authoritative snapshot: [SPEC.md](docs/spec/SPEC.md),
  [behaviors.md](docs/spec/behaviors.md), [architecture.md](docs/spec/architecture.md),
  [data-model.md](docs/spec/data-model.md), [interfaces.md](docs/spec/interfaces.md),
  [configuration.md](docs/spec/configuration.md),
  [fitness-functions.md](docs/spec/fitness-functions.md).
- [docs/architecture/overview.md](docs/architecture/overview.md) +
  [diagrams.md](docs/architecture/diagrams.md) — prose tour + C4/sequence diagrams.
- [docs/architecture/decisions/](docs/architecture/decisions/) — ADRs.
  [ADR-001](docs/architecture/decisions/001-foundational-stack.md) consolidates the
  existing stack/architecture decisions as a baseline; future decisions get their own
  ADR.
- [docs/CONTRACT.md](docs/CONTRACT.md) — the frozen v1 contract (mirrors the planning
  hub).
- [docs/ROADMAP.md](docs/ROADMAP.md) — v1+ items with dependency ordering + per-item
  risk flags.
- [docs/tasks/](docs/tasks/) — `active/` · `backlog/` · `completed/` +
  `test-specs/coverage-tracker.md`.
- [docs/agent-rules.md](docs/agent-rules.md) — process rules + project retros (the
  growing log of lessons; its essentials are inlined below).

## Roadmap (v1+)

Signed checkpoints (RFC 6962 STH) · witness/Rekor anchoring · log
rotation/checkpointing · indexed query API · pluggable backends
(Rekor/immudb/Postgres). Keep these behind the emit/verify seam — don't leak backend
specifics into the contract.

Dependency ordering + per-item risk flags: [docs/ROADMAP.md](docs/ROADMAP.md). Detail
per item goes in an ADR when it's picked up — not inline here.

## Working in this project

Every task lives on its own branch (or worktree under concurrent sessions). Working
directly on `main` is blocked by the `no-commit-on-main` hook — `scripts/start-task.sh`
is how you pick the right isolation for the moment.

1. Start each session by reading the relevant task file (including its
   **Verification plan**) and its test spec.
2. Check [docs/architecture/overview.md](docs/architecture/overview.md) for system
   context.
3. Write the test spec before any implementation code.
4. Implement via your harness's task-execution flow. Its Step 0 runs
   `scripts/start-task.sh <NNN> <slug>` to set up either:
   - `BRANCH task/NNN-<slug>` (solo session — the common case), or
   - `WORKTREE .claude/worktrees/NNN-<slug>/` (concurrent session detected; `cd` in).

   Commit at status **🟡 (code merged)** on the task branch.
5. After the executor returns, run the **spec-verifier** role on the task — it returns
   APPROVE or BLOCK based on per-assertion evidence.
6. If spec-verifier APPROVEs **and** the verification plan's L5/L6 evidence is
   recorded, promote the row to **✅ (verified)** in `coverage-tracker.md` in a
   **separate commit** titled `verify: confirm task NNN — <evidence>` (still on the
   task branch).
7. **Merge to main** when ready: `git checkout main && git merge task/NNN-<slug>`. The
   `auto-cleanup-merge` hook then deletes the task branch and removes the worktree
   automatically.
8. **Commit and push after each milestone** — never start the next task without
   committing the current one first.

The separation between the task branch and `main` is the load-bearing rule for
multi-session safety. The separation between 🟡 (feat commit) and ✅ (verify commit)
is the load-bearing rule that keeps "merged" and "verified" two distinct artifacts in
git history. **Never** mark ✅ in the same commit as the feature work.

## Commit rules

**You must commit and push after every milestone.** Do not batch multiple tasks into
one commit. Do not continue to the next task until the current one is committed and
pushed.

All commits land on the **task branch** (`task/NNN-<slug>`), never on `main` directly.
The merge to `main` happens after the verify step, in a separate explicit operation.

| Milestone | What to stage | Message | Branch |
|-----------|--------------|---------|--------|
| ADR written | `docs/architecture/decisions/NNN-*.md`, any superseded spec entries rewritten in `docs/spec/` | `docs: add ADR NNN — <decision title>` | task branch |
| Test spec written | `docs/tasks/test-specs/NNN-*-test-spec.md`, updated `coverage-tracker.md` | `test: add spec for task NNN — <name>` | task branch |
| Task code merged (🟡) | source changes, moved task file, `coverage-tracker.md` row set to **🟡**, **and any affected `docs/spec/` files** | `feat: complete task NNN — <name>` | task branch |
| Task verified (✅) | `coverage-tracker.md` row promoted 🟡 → ✅ with `Verified by` filled | `verify: confirm task NNN — <evidence>` | task branch |
| Diagram updated | `docs/architecture/diagrams.md` (with date bump) | `docs: refresh diagrams — <what changed>` | task branch (or `[allow-main]` for standalone doc fixes) |
| Spec rewritten standalone | `docs/spec/<file>.md` | `spec: <what changed and why now>` | task branch (or `[allow-main]` for standalone doc fixes) |
| Merged into main | (after `git merge task/NNN-<slug>` on `main`) | (default `Merge branch …` message) | `main` |

Do **not** add a `Co-Authored-By` line to commits unless explicitly asked.

## Load-bearing process rules

These are the rules that exist specifically to stop a preventable mistake. The
**full treatment, with the incident that motivated each, lives in
[docs/agent-rules.md](docs/agent-rules.md)** — read it. The essentials, so they reach
you even without that file loaded:

- **Commit after every milestone — now, not "after the next task too."** Batched
  commits are impossible to untangle. One task, one commit.
- **Test spec before implementation — always.** No "this is too small for a spec."
  The spec defines done; without it you're guessing.
- **Never work directly on the default branch.** First action of any task is
  `scripts/start-task.sh <NNN> <slug>`, which puts you on `task/NNN-<slug>` or in a
  worktree. When it prints `WORKTREE <path>`, your **next command must be `cd
  <path>`** — editing the parent repo while believing you're isolated is the silent
  failure.
- **"Done" means operationally verified, not "code merged."** The verification
  ladder: (1) code merged → (2) unit tests pass → (3) fitness checks pass → (4) CI →
  (5) validation harness exercises the live path → (6) live binary observed. Levels
  1–4 are 🟡; only 5 or 6 flips a row to ✅. Never claim a level you did not reach.
- **Trace producer→consumer before declaring done on cross-module state.** A test
  that sets a field by hand proves the gate works *given* the field; it does not prove
  the field is ever set on the live path. Grep the write site and the read site and
  identify the live path.
- **No smoke tests where the spec asks for assertions.** If the spec says "returns
  `{valid:false}` with a tamper offset", the test must verify that, not merely that
  the call doesn't panic. If constructing the state is hard, that's a blocker to
  report — not a license to downgrade the test.
- **No new warnings self-justified away.** A change that adds a linter/vet warning
  over baseline must fix the root cause or stop and report. Use an explicit
  suppression with a reason, or escalate — don't unilaterally label it acceptable.
- **Run it when the change is runtime-visible.** Logging, CLI/exit codes, IPC output,
  file outputs, side effects — `go test` is not full verification. Run the binary path
  and quote the output.
- **Never `git checkout -- <path>` over uncommitted work.** It silently overwrites and
  the reflog cannot recover it. Use `git stash`, `git worktree add <ref>`, or
  `git diff <ref> -- <path>` / `git show <ref>:<path>` instead. A `protect-checkout`
  hook blocks this; the rule stands even if the hook is off.
- **Git status must be clean before declaring a task complete.** `git status` must
  report `nothing to commit, working tree clean`. The common miss: `cp` instead of
  `git mv` when moving a task file leaves the original undeleted.

## Boundaries

### Always
- Write the test spec before any implementation code.
- Fill in the **Verification plan** of the task file *before* writing code.
- Commit and push after every milestone.
- Read the task file (including its Verification plan) and test spec before starting.
- Create an ADR for significant design decisions.
- **Update `docs/spec/` in the same commit** as any code change that alters
  externally-visible behavior, data model, interfaces, or configuration.
- **Update `docs/architecture/diagrams.md` in the same commit** as any code change
  that moves a component boundary or alters a diagrammed runtime flow.
- **Default new task status to 🟡 on the feat commit; ✅ only after spec-verifier
  APPROVE + recorded L5/L6 evidence, in a separate `verify:` commit.**
- **Run `spec-verifier` on every task** before promoting to ✅.
- **Start every task on its own branch via `scripts/start-task.sh <NNN> <slug>`.**

### Ask first
- Modifying files in `docs/plans/`, `docs/tasks/`, or `docs/architecture/decisions/`.
- Deleting or renaming existing source files.
- Adding dependencies — the design is standard-library-only (ADR-001 D1); run any
  proposed dep past **dependency-auditor** first.
- Changing the project structure beyond what a task requires.
- Reorganizing `docs/spec/` (splitting files, renaming sections) — the structure is a
  stable contract.

### Never
- Create source files without a corresponding task and test spec.
- Combine unrelated changes in one task or commit.
- Skip the test spec — even for "small" changes.
- Force push or rewrite published git history.
- Add a `Co-Authored-By` line to commits unless explicitly asked.
- Append to spec entries instead of rewriting them (the ADR keeps history; the spec is
  a snapshot).
- Add future-tense statements to the spec (the spec is what *is*).
- Mark a task ✅ on the same commit as the feature work.
- Claim a verification level you did not actually reach.
- Commit directly to `main` (use `[allow-main]` in the message for genuine main-only
  fixes — standalone doc fixes, hotfixes).
- Run `git checkout -- <path>` over a dirty working tree.
- Break the frozen v1 contract without a contracts bump.

## External tools

Standard Go toolchain only (`go`, `gofmt`). No third-party deps by design
(ADR-001 D1) — keep it that way; if a dep is ever proposed, audit it first.

## Harness notes — Codex / Gemini / Antigravity

Non-Claude hosts do not auto-run the Claude SessionStart/PreTool hooks. Bridge them:

- **Session start:** run `./scripts/session-start.sh` at the beginning of each
  session. It registers the session lock (so concurrency checks and task
  branching/worktree allocation work) and pulls relevant retros into the terminal.
- **Git hooks:** run `python3 scripts/setup-hooks.py` to wire the `.claude/scripts`
  hooks into native Git hooks (`pre-commit`, `post-merge`).
- **Antigravity** natively supports workspace-local hooks via
  [.agents/hooks.json](.agents/hooks.json), configured to mirror the Claude setup
  (no-commit-on-main, spec-coverage-check, block-no-verify, auto-cleanup-merge,
  protect-secrets, config-protection, protect-checkout, session-lock, inject-retros,
  stop/compaction).

The `.claude/agents/*.md` files are role prompts (task-executor, spec-verifier,
code-reviewer, architect, security-auditor, dependency-auditor). On a non-Claude host
they are not auto-available subagents — read the relevant role prompt and mirror its
intent manually, or spawn a subagent with it as the role prompt where the host
supports that.
