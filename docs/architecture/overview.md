# Architecture Overview

**Project:** audit-trail
**Last updated:** 2026-06-03

## System purpose

audit-trail is a tamper-evident, append-only forensic log — the **spine** every other block
in the secure-agent ecosystem emits to. It records *what happened* in a form that survives
agent compromise: each event is hash-chained to its predecessor, so any byte-level alteration
of any past entry is detectable offline. It does **not** detect, prevent, or alert — it
records. Forensic archive, not telemetry.

The integrity claim is a single equation:

```
hash = SHA256( prev_hash + JCS(record_without_hash) )
```

`verify()` re-derives that equation for every entry, walking from the genesis `prev_hash`
(64 zeros) forward, and reports the `seq` of the first entry whose link or content hash
doesn't reconcile.

## Component map

Single Go package (`package main`), flat layout. Four source files, each one responsibility:

| File | Responsibility |
|------|----------------|
| [chain.go](../../chain.go) | The `Chain` type — the integrity core. `Emit` appends one record and returns `{seq, hash}`; `Verify` walks the on-disk chain; `loadState` resumes `seq`/`prevHash` from disk on open. Holds the only mutable state and the mutex. |
| [canonical.go](../../canonical.go) | `canonical()` — RFC 8785 (JCS) encoding via `encoding/json` with HTML-escaping disabled. The byte-exactness here is what makes hashes reproducible across processes. |
| [ipc.go](../../ipc.go) | `serve()` + `handleConn()` — newline-delimited JSON over a Unix socket. Translates `{op}` requests to `Chain` calls; emits the shared `{error:{code,message,retryable}}` shape on failure. |
| [main.go](../../main.go) | CLI dispatch (`serve`/`emit`/`verify`), flag parsing, JSON output. `verify` exits non-zero on tamper. |

## Data flow

```
emitter (block/agent/CLI)
   │  event = {ts, actor, action, target, decision?, refs, context?}
   ▼
Chain.Emit  ──►  build record (+ seq, prev_hash)
   │             hashRecord = SHA256(prev_hash + canonical(record))
   │             append "<json>\n" to JSONL logfile (O_APPEND)
   ▼             advance in-memory seq + prevHash
returns {seq, hash}

verify (CLI exit-code / IPC):
   logfile (disk)  ──►  Chain.Verify  ──►  re-walk every line,
                                           recompute each hash,
                                           check prev_hash linkage
                                       ──►  {valid, tamper_detected_at, message}
```

Two transports drive the same two verbs:
- **CLI** ([main.go](../../main.go)) — `emit`/`verify`, standalone & CI-friendly.
- **Unix-socket IPC** ([ipc.go](../../ipc.go)) — `{"op":"emit"|"verify"|"ping"}`, the hot path for live blocks.

## Key dependencies

**None beyond the Go standard library**, by design (PolyForm Noncommercial; minimal trust
surface). The integrity primitives are `crypto/sha256` + `encoding/hex`; canonicalization and
the wire format are `encoding/json`; persistence is `os`/`bufio`; IPC is `net` (Unix domain
socket). No third-party modules in [go.mod](../../go.mod).

## Entry points

- `audit-trail serve --socket <path> --logfile <path>` — long-lived IPC daemon.
- `audit-trail emit --logfile <path> --actor … --action … --target … [--decision …]` — one event.
- `audit-trail verify --logfile <path>` — walk the chain; exit 1 on tamper.

## Key decisions (observed in code)

- **Disk is the source of truth.** `Verify()` opens and re-reads the logfile; it never trusts
  the in-memory `Chain`. That is precisely what catches a tamper — an attacker who edits the
  file but not the process state is caught, and vice versa.
- **State is resumable.** `loadState()` replays the JSONL on open, so a restarted daemon (or a
  fresh CLI invocation against an existing log) continues the same chain. See
  `TestChainResumesFromDisk`.
- **Floats are excluded from audited events.** Integer/string/bool/null/array/object only.
  Within that domain Go's `encoding/json` (HTML-escaping off) is byte-identical to a full JCS
  implementation. Floats are the one place a naive serializer diverges from RFC 8785 — keeping
  them out keeps `canonical.go` honest without a heavyweight JCS library. See ADR-001.
- **Single-writer concurrency.** One `sync.Mutex` serializes `Emit`; IPC fans connections out
  to goroutines but they all funnel through that lock.
- **Frozen v1 contract.** `emit`/`verify` signatures and the JCS rule are fixed; see
  [docs/CONTRACT.md](../CONTRACT.md) and [decisions/001-foundational-stack.md](decisions/001-foundational-stack.md).

See [diagrams.md](diagrams.md) for the C4 + sequence views, and [../spec/](../spec/) for the
structured element catalog.
