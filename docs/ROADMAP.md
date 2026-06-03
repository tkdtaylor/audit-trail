# Roadmap (v1+)

The v1 contract (`emit`/`verify` shapes, the JCS rule) is **frozen** — see
[CONTRACT.md](CONTRACT.md). Everything here lands *behind the emit/verify seam*: it may add
capability, but it must not change the v1 contract without a contracts bump and a superseding
ADR.

This file captures only what a flat list can't: **dependency ordering** and a **one-line risk
flag** per item — the things that are decision-relevant and stable. It deliberately does **not**
contain per-item design detail; that rots. Each item gets its own ADR *at the moment it is
picked up* ([decisions/](architecture/decisions/)), then a decomposition into task files
([tasks/backlog/](tasks/)).

## Dependency order

```
checkpoints ──► witness / Rekor anchoring     (anchoring needs something to anchor)
            └─► log rotation / checkpointing  (rotation re-anchors at segment boundaries)

indexed query API        (independent — additive)
pluggable backends       (independent — but do last; highest abstraction-leak risk)
```

## Items

| Item | Depends on | Risk | Why the risk |
|---|---|---|---|
| **Signed checkpoints** (RFC 6962 STH) | — | 🔴 high | Touches the integrity core: key management, signature format, and *what exactly* gets signed. Get the signed-tree-head shape wrong and every downstream anchor inherits it. |
| **Witness / Rekor anchoring** | checkpoints | 🟠 med | External trust + network failure modes. Must degrade safely — an unreachable witness cannot block or weaken local `emit`/`verify`. |
| **Log rotation / checkpointing** | checkpoints | 🔴 high | Interacts with two load-bearing invariants: `Verify()` reads from disk, and the single-writer mutex. A rotation boundary is a seam where tamper-detection can silently break. |
| **Indexed query API** | — | 🟢 low | Additive, read-only. Must not become a second writer or bypass `Verify()`'s disk read. |
| **Pluggable backends** (Rekor / immudb / Postgres / SQLite) | — | 🟠 med | The contract fights to keep backend specifics *out* of emit/verify. This is the item most likely to leak abstraction into the frozen seam — do it last, when the seam is well-exercised. |

## Discipline

- **CLAUDE.md gets the headline, never the body.** New roadmap detail lands here, in an ADR, or
  in a task file — not as prose under CLAUDE.md's `## Roadmap`.
- **[docs/spec/](spec/) stays present-tense.** No future tense in the spec ([SPEC.md](spec/SPEC.md)
  rule); the roadmap lives here and in [ADR-001](architecture/decisions/001-foundational-stack.md).
- **ADR before code.** Write the design ADR when you start an item, not before — that's when you
  have the context to get it right.
