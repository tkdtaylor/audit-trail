# audit-trail — Authoritative Spec

**Project:** audit-trail
**Last updated:** 2026-06-03

## What this directory is

`docs/spec/` is the **authoritative current-state snapshot** of audit-trail. It answers:

> "If the code were deleted tomorrow, what would I need to write down to rebuild it?"

The spec is dual-natured:

- **Output of current sessions** — every completed task that changes externally-observable
  behavior, the data model, an interface, or configuration must update the relevant spec file
  in the same commit.
- **Input to future sessions** — onboarding, drift audits against the code, regeneration.

The code is one *realization* of this spec. If the spec and code disagree, one is wrong — fix
the wrong one in that same change.

## Spec vs. ADRs vs. overview

| Doc | Purpose | Lifecycle |
|-----|---------|-----------|
| [`docs/spec/`](.) | What the system **does and is** today | Snapshot — supersede in place |
| [`docs/architecture/decisions/`](../architecture/decisions/) | **Why** decisions were made | Append-only; ADRs supersede ADRs |
| [`docs/architecture/overview.md`](../architecture/overview.md) | Narrative tour | Snapshot, human-optimized |
| [`docs/architecture/diagrams.md`](../architecture/diagrams.md) | Visual structure and flows | Snapshot, part of the spec |

## The six sub-files

| File | Covers |
|------|--------|
| [behaviors.md](behaviors.md) | Observable behaviors — emit, verify, resume, IPC ops, tamper detection |
| [architecture.md](architecture.md) | C4 element catalog (paired with [`../architecture/diagrams.md`](../architecture/diagrams.md)) |
| [data-model.md](data-model.md) | The record schema, on-disk JSONL format, in-memory state |
| [interfaces.md](interfaces.md) | CLI surface, IPC wire protocol, internal Go API |
| [configuration.md](configuration.md) | Flags, paths, permissions |
| [fitness-functions.md](fitness-functions.md) | Executable architectural invariants |

## Maintenance rules

1. **Update in the same commit as the code change.** A behavior change isn't done until
   `behaviors.md` reflects it.
2. **Supersede in place. Never append.** ADRs carry history; the spec carries current truth.
3. **No future tense.** Roadmap lives in CLAUDE.md / ADR-001, not here.
4. **No implementation rationale.** "Chose X because Y" belongs in an ADR.
5. **Audit drift periodically** with the `architect` agent's drift-audit mode.

## Project summary

audit-trail is a tamper-evident, append-only forensic log — the spine the rest of the
secure-agent ecosystem emits to. Each event is hash-chained to its predecessor via
`hash = SHA256(prev_hash + JCS(record_without_hash))`; `verify()` walks the on-disk chain and
reports the first entry whose link or content hash doesn't reconcile. It records — it does not
detect, prevent, or alert. Go, standard library only.

## Top-level invariants

- **`Verify()` reads from disk, never from the in-memory `Chain`.** This asymmetry is what
  detects a tamper. (chain.go `Verify`)
- **The hash equation is frozen:** `SHA256(prev_hash + canonical(record_without_hash))`, hex
  lowercase. Genesis `prev_hash` is 64 zeros. (chain.go `hashRecord`, `Genesis`)
- **Canonicalization is RFC 8785 (JCS) and audited events contain no floats.** Integer/string/
  bool/null/array/object values only. (canonical.go)
- **The log is append-only.** Records are only ever appended (`O_APPEND`); never rewritten by
  the application. (chain.go `Emit`)
- **Single writer.** All `Emit` calls serialize through one `sync.Mutex`. (chain.go)
- **State is derived from disk.** `seq` and `prev_hash` are reconstructed by replaying the log
  on open, so the chain resumes across restarts and across processes. (chain.go `loadState`)

## Non-goals

- **Not telemetry / observability.** No metrics, no alerting, no detection. It records facts.
- **Not access control.** It does not authenticate or authorize emitters (file/socket perms
  are the only gate).
- **Float support in audited events** — deliberately out of scope to keep canonicalization exact.
- **Not (yet) cryptographically signed or anchored.** Signed checkpoints, witness/Rekor
  anchoring, rotation, query API, and pluggable backends are v1+ roadmap, behind the
  emit/verify seam — see ADR-001.
