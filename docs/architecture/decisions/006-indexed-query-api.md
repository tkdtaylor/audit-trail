# ADR-006 - Indexed query API

**Status:** Accepted · **Date:** 2026-07-12

## Context

ADR-001 names the indexed query API as a v1+ roadmap item (`docs/ROADMAP.md`: "Additive, read-only. Must not become a second writer or bypass `Verify()`'s disk read."). Task 020 adds a read-only `query` op over the existing Unix-socket IPC surface and a CLI `query` subcommand, filtering the hash-chained log on `actor`/`action`/`target`/`decision`/seq range/ts range with pagination.

Three consumers, in order of pull: armor incident review ("show me everything actor X did between ts A and ts B"), policy-engine decision-trace audits ("all `deny` slices for target Y"), and agent-builder forensics (post-incident reconstruction of one agent's actions across a rotated multi-segment log). All three are read paths over a log that may itself be under investigation, because it is suspected of having been tampered with, which drives both decisions below. The frozen v1 `emit`/`verify` contract (`docs/CONTRACT.md`) does not change; `query` is a new verb only.

## Decision

### 1. No persisted index - derived state, rebuilt from a full chain walk on demand

`query` maintains no on-disk or in-memory index. Every query streams every segment (manifest order, then the active segment) from disk, decodes each record, and filters in place. Nothing is written by `query`, and the emit path (`Chain.Emit`) gains no new hook.

**Forks considered:**

- **On-disk index (e.g. a secondary JSONL or SQLite side-file keyed by actor/action/etc.), incrementally maintained on every `Emit`.** Pro: O(matches) query cost instead of O(log size). Con: turns `query` into a second writer on the hot emit path, exactly what the roadmap item forbids ("must not become a second writer"), and introduces an index-vs-log consistency problem: an index that silently drifts from the log it indexes is itself a new class of tamper-adjacent bug, with its own corruption/rebuild/versioning surface.
- **In-memory index built at `serve` startup and updated per `Emit`.** Pro: avoids a second on-disk writer; fast queries against a live daemon. Con: still couples the emit hot path to index maintenance (a bug in the index-update code can silently desync from the log even though nothing hits disk), and the CLI `query` path (no long-lived daemon) gets no benefit from it, so two code paths would exist for one operation. Deferred to a later, additive optimization (task 020's Out of scope) once query semantics are exercised in production and the O(log size) walk is shown to matter.
- **Derived, on-demand walk (chosen).** Pro: nothing is written, so index loss or corruption is impossible by construction and can never affect `emit`/`verify` or tamper-evidence; the emit hot path is completely untouched; one code path serves both CLI and IPC. Con: every query is O(log size) rather than O(matches), acceptable for a forensic archive queried during incident review, not a high-QPS analytics store.

The on-demand walk wins because it cannot regress the emit path or introduce a second root of trust. An incrementally maintained in-memory index inside `serve` remains available as a later, purely additive optimization behind the same `runQuery` signature.

### 2. A log that fails verification returns results flagged `verified:false`, it does not refuse

Every `query` response carries the outcome of a fresh `verifyAllSegments` disk walk in `verified`/`tamper_detected_at`/`message`. When that walk reports `valid:false`, `query` still returns the matching records (the stored bytes, verbatim) rather than an error.

**Justification:** audit-trail is a forensic archive, not a live control system. The highest-value moment to query it is exactly incident review of a log that may already be tampered with: armor's injection/exfil investigation, or agent-builder's post-incident reconstruction, are triggered because something is suspected wrong. Refusing to serve queries on a failing log would make the API useless at the one moment it matters most, and would hand an attacker a one-byte denial-of-forensics: corrupt one byte anywhere in the log and every subsequent query goes dark, right when investigators need it most.

Tamper-evidence is preserved, not weakened, by this choice: every response carries the fresh verdict alongside the results, so the tamper travels with the evidence instead of being hidden behind a refusal. A consumer that ignores `verified` does so at its own risk, exactly as a consumer that ignores `Verify()`'s response today would. This mirrors the existing project posture (`Verify()` itself does not "refuse", it reports `valid:false` and lets the caller decide) and extends it consistently to `query`.

Records returned are the raw on-disk line bytes (`json.RawMessage`), never re-marshalled, re-hashed, or re-canonicalized. A tampered byte in a returned record is delivered to the consumer exactly as tampered, not silently repaired or hidden by a round-trip through Go's map type.

### 3. Continuation token format

`next_token` (request field: `token`) is the decimal string of the global `seq` at which the scan resumes, i.e. "the first candidate record has `seq >= token`". It is opaque to clients: they must treat it as an unstructured continuation cookie, not construct or parse it themselves. It is only meaningful when resubmitted with the same filter; the server does not validate filter equality across pages, so resubmitting a token with a different filter silently resumes the new filter's scan from that seq rather than erroring. This is a deliberate simplicity trade-off: validating cross-page filter equality would require the server to either persist per-token filter state, reintroducing index-like state, or accept an opaque signed token, which is unnecessary complexity for a trusted-operator CLI/socket surface with no external clients.

**Forks considered:**

- **Opaque server-signed token (e.g. HMAC over filter+seq).** Pro: detects/rejects a token resubmitted against a different filter. Con: requires a server-side signing key for a read-only op, adds a dependency-shaped surface (key management) to a feature explicitly scoped to avoid becoming a second writer, and the query surface has no untrusted-network client today (Unix-socket owner-only permissions are the access control per `docs/CONTRACT.md`).
- **Plain decimal seq string (chosen).** Pro: trivial to implement, trivial to reason about, matches the existing "seq is the one ordering primitive" pattern already used throughout the chain (`Chain.seq`, `VerifyResult.tamper_detected_at`, `RotateResult.first_seq/last_seq`). Con: a client can hand-craft or guess a token; this is not a security boundary (the socket already has full read access to every record), just a scan cursor.

## Consequences

- `query` is a pure reader: it opens segment files `O_RDONLY`, takes no `Chain.mu` lock, writes nothing, and never mutates `Chain.seq`/`Chain.prevHash`. It can be called concurrently with `Emit`/`Rotate` without any coordination beyond what the filesystem already provides for concurrent readers/writers of the same file.
- Query cost is O(log size) per call, not O(matches). For the roadmap's stated consumers (incident review, decision-trace audits, forensic reconstruction) this is the right trade: correctness and simplicity over throughput. A future in-memory index inside `serve` is explicitly left open as an additive optimization that does not change the `query` request/response contract.
- A tampered log remains queryable, with the tamper verdict attached to every response. Consumers that need "refuse on tamper" semantics get that today from `verify`/`checkpoint verify`; `query` intentionally does not duplicate that gate.
- The token is a plain, unsigned scan cursor. It provides no security guarantee and none is needed: the query surface is exposed only over the existing owner-only Unix socket and the local CLI, the same access-control boundary as every other IPC op.

## Links

- [ADR-001](001-foundational-stack.md) - foundational architecture and v1+ roadmap.
- [ADR-005](005-log-rotation.md) - segment/manifest model that `query` walks across.
- [docs/CONTRACT.md](../../CONTRACT.md) - frozen v1 `emit`/`verify` contract (unchanged).
- [docs/ROADMAP.md](../../ROADMAP.md) - indexed query API roadmap item.
- [docs/tasks/backlog/020-indexed-query-api.md](../../tasks/backlog/020-indexed-query-api.md)
