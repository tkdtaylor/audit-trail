# Architecture — Element Catalog

**Project:** audit-trail · **Last updated:** 2026-06-03

Tabular C4 catalog. The structured pair to [`../architecture/diagrams.md`](../architecture/diagrams.md)
— both describe the same model. Every row corresponds to something on disk.

## Persons

| Person | Description |
|--------|-------------|
| Auditor / CI | Runs `verify()` to confirm chain integrity; gates on the exit code. |
| Operator | Runs the `serve` daemon; owns the socket and logfile. |

## Systems

| System | In/Out of scope | Description |
|--------|-----------------|-------------|
| audit-trail | **In** | This system — the hash-chained forensic log. |
| Ecosystem blocks (vault, scanner, sandbox, …) | External | Emit events as they act. They are clients, not part of this repo. |
| JSONL logfile | External (filesystem) | The append-only on-disk chain; the source of truth for `verify()`. |

## Containers

audit-trail is a **single deployable unit** — one Go binary exposing two transports. There is
no separate database, queue, or service.

| Container | Tech | Responsibility |
|-----------|------|----------------|
| `audit-trail` binary | Go 1.26, stdlib only | CLI + IPC daemon over the `Chain` core. |
| JSONL logfile | newline-delimited JSON | Persistent append-only chain. |

## Components

| Component | File | Responsibility | Depends on |
|-----------|------|----------------|------------|
| CLI | [main.go](../../main.go) | `serve`/`emit`/`verify` dispatch, flag parsing, JSON output, exit codes | Chain core |
| IPC server | [ipc.go](../../ipc.go) | Unix-socket listener, `{op}` dispatch, error shape | Chain core |
| Chain core | [chain.go](../../chain.go) | `Emit`, `Verify`, `loadState`, `hashRecord`; mutex; the integrity logic | Canonicalizer, `crypto/sha256`, `os` |
| Canonicalizer | [canonical.go](../../canonical.go) | RFC 8785 / JCS encoding | `encoding/json` |

## Cross-cutting decisions

| Concern | Decision | Where |
|---------|----------|-------|
| Trust surface | Standard library only; no third-party deps | [go.mod](../../go.mod), ADR-001 D1 |
| Integrity | `SHA256(prev_hash + JCS(record))`, hex; genesis = 64 zeros | chain.go, ADR-001 D2 |
| Tamper detection | `Verify()` reads disk, not memory | chain.go, ADR-001 D3 |
| Concurrency | Single `sync.Mutex` serializes all writes | chain.go, ADR-001 D5 |
| Error contract (IPC) | `{error:{code,message,retryable}}` | ipc.go |
| Socket security | `chmod 0600`; stale socket removed on start | ipc.go |

See [`../architecture/decisions/001-foundational-stack.md`](../architecture/decisions/001-foundational-stack.md)
for the rationale behind each.
