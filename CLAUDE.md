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

- `go build ./...` and `go test ./...` must stay green.
- `Verify()` MUST read from disk (never an in-memory copy) — that is what catches a tamper.
- Errors over IPC use the shared shape `{error:{code,message,retryable}}`.

## Roadmap (v1+)

Signed checkpoints (RFC 6962 STH) · witness/Rekor anchoring · log rotation/checkpointing ·
indexed query API · pluggable backends (Rekor/immudb/Postgres). Keep these behind the
emit/verify seam — don't leak backend specifics into the contract.
