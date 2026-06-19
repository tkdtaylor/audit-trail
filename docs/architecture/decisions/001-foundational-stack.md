# ADR-001 — Foundational stack and architecture (bootstrap)

**Status:** Accepted (bootstrap) · **Date:** 2026-06-03

## Context

audit-trail predates this ADR log. This bootstrap ADR consolidates the decisions the codebase
already commits to as of 2026-06-03, so later ADRs (ADR-002, …) have a coherent baseline to
amend rather than free-floating in a vacuum. Each item below describes *what is*, not a fresh
proposal. Future ADRs supersede or refine these.

## Decisions

### D1 — Language: Go, standard library only

Go 1.26, `package main`, no third-party modules ([go.mod](../../../go.mod) has no `require`s).
Integrity primitives come from `crypto/sha256` + `encoding/hex`; the wire/canonical format
from `encoding/json`; persistence from `os`/`bufio`; IPC from `net`. A forensic spine must
minimize its trust surface — every dependency is code that could weaken the integrity claim.

### D2 — Canonicalization: RFC 8785 (JCS) via `encoding/json`, floats excluded

The hash is `SHA256(prev_hash + JCS(record_without_hash))`, so byte-exact canonical encoding
is load-bearing. Audited events are restricted to integer/string/bool/null/array/object
values. Within that domain, Go's `encoding/json` with `SetEscapeHTML(false)` is byte-identical
to a full JCS implementation (sorted keys, no insignificant whitespace, shortest-decimal
integers). **Floats are deliberately kept out** — they are the one place a naive serializer
diverges from RFC 8785. This avoids pulling in a heavyweight JCS library while keeping hashes
reproducible across processes. See [canonical.go](../../../canonical.go).

### D3 — Persistence: append-only JSONL, disk is the source of truth

The log is a newline-delimited JSON file, one record per line, opened `O_APPEND`. State
(`seq`, `prevHash`) is **derived from disk** via `loadState()` on open, making the chain
resumable across restarts and across separate CLI invocations. `Verify()` re-reads the file
from disk and never trusts the in-memory `Chain` — this asymmetry is what makes a tamper
detectable. See [chain.go](../../../chain.go).

### D4 — Two transports, same verbs

`emit` and `verify` are exposed identically over a **CLI** (standalone/CI, exit-code signalling)
and a **Unix-socket IPC** daemon (the hot path for live blocks). IPC errors use the shared
ecosystem shape `{error:{code,message,retryable}}`. See [main.go](../../../main.go),
[ipc.go](../../../ipc.go).

### D5 — Concurrency: single mutex, single writer

`Emit` is serialized by one `sync.Mutex` on `Chain`. The IPC server accepts connections into
goroutines, but all writes funnel through that lock — there is exactly one writer to the chain.

### D6 — Tooling & layout

Flat single-package layout (4 source files + `chain_test.go`). Build/test via
[Makefile](../../../Makefile) (`make build` → `bin/audit-trail`, `make test`, `make fmt`) or
plain `go build ./...` / `go test ./...`. License: Apache-2.0.

## Consequences

- Minimal supply-chain risk; trivially auditable.
- The float exclusion (D2) is a **convention the emit path must keep honoring** — it is not
  enforced by a type system. A fitness function or input guard is the natural place to make it
  unbreakable (see [../../spec/fitness-functions.md](../../spec/fitness-functions.md)).
- The v1 contract (`emit`/`verify` shapes, JCS rule) is frozen; changing it requires a contracts
  bump and a superseding ADR. See [docs/CONTRACT.md](../../CONTRACT.md).

## Roadmap (deferred to v1+, behind the emit/verify seam)

Signed checkpoints (RFC 6962 STH) · witness/Rekor anchoring · log rotation/checkpointing ·
indexed query API · pluggable backends (Rekor/immudb/Postgres/SQLite). Each will get its own
ADR when undertaken.

Dependency ordering and per-item risk flags are tracked in [../../ROADMAP.md](../../ROADMAP.md).
