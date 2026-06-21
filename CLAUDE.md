# audit-trail — Claude Code layer

The canonical, harness-neutral briefing for this repo is **`AGENTS.md`**. Read it
first — it holds the contract, project context, commands, conventions, the integrity
invariants, the task workflow, commit rules, boundaries, and the load-bearing process
rules. This file adds only what is **specific to Claude Code** (skills, subagents,
hook profiles, plan mode, retro injection).

@AGENTS.md

---

Everything below is Claude Code-specific and supplements `AGENTS.md`.

## Subagents (`.claude/agents/`)

Use the **task-executor** agent to work through tasks one at a time. Each agent call
is ephemeral — it reads the task file, does the work, commits, and reports back
without bloating the main conversation.

```
use task-executor — task: docs/tasks/backlog/NNN-name.md, spec: docs/tasks/test-specs/NNN-name-test-spec.md
```

The workflow (test spec first, `scripts/start-task.sh` for isolation, 🟡 feat commit,
spec-verifier, 🟡→✅ verify commit, merge) is defined in `AGENTS.md`. The named roles
map to subagents under `.claude/agents/`:

- **architect** (opus) — invoke for the v1+ roadmap items (checkpoints, backends).
  They all sit behind the emit/verify seam and need design judgment + an ADR. Also
  runs spec/code drift audits and proposes fitness functions.
- **security-auditor** (opus) — this *is* a security primitive; run before any change
  to `chain.go`/`canonical.go`. Focus: can a tamper slip past `verify()`, can
  canonicalization diverge, are the socket/logfile perms right.
- **spec-verifier** (sonnet) — gate completed tasks against their test spec before the
  verify commit.
- **code-reviewer** (sonnet) — review diffs against the conventions before commit.
- **task-executor** (haiku) — scoped implementation of a single task file.

## Skills

- **security-review** — trigger before shipping integrity-affecting changes: "run a
  security review of the pending changes".
- **code-review** — `/code-review` on the current diff for correctness + cleanup.
- **simplify** — quality pass on changed code after heavier work.

## Hooks

Already wired in `.claude/settings.json`: `no-commit-on-main` blocks commits on
`main`; `protect-secrets` / `config-protection` guard edits; `spec-coverage-check`
enforces test refs on active tasks at commit; `protect-checkout` blocks
`git checkout -- <path>` over a dirty tree. Manage via `/update-config`.

## Agent rules and retros

Process-level rules, common rationalizations, and project-specific retros live in
[docs/agent-rules.md](docs/agent-rules.md) (their essentials are also inlined in
`AGENTS.md` so every harness sees them). The `inject-retros.py` SessionStart hook
reads that file (plus this `CLAUDE.md`) and surfaces relevant entries at the start of
every session, so adding an entry there is how a one-time mistake becomes a permanent
guard.
