# Data Model

**Project:** audit-trail · **Last updated:** 2026-06-03

## Persistent store — the JSONL logfile

One file, append-only, one JSON object per line (`"<json>\n"`). Default path `audit.log`,
mode `0600`. This file **is** the chain; there is no other persistence.

### Record schema (one line)

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `seq` | int | server-assigned | Monotonic, starts at 0, +1 per emit. |
| `ts` | int | emitter | Unix seconds; coerced to int64. CLI sets `time.Now().Unix()`. |
| `actor` | string | emitter | Requester identity (block/agent/user). |
| `action` | string | emitter | Verb: `resolve`, `inject`, `decide`, `scan`, `spawn`, `exit`, … |
| `target` | string | emitter | Resource: `vault://…`, host, sandbox-id, … |
| `decision` | string \| null | emitter | `allow`/`deny`/`require_approval`/`block`; `null` if unset. |
| `refs` | array | emitter | `[{type,id}]` attestation refs; defaults to `[]`. |
| `context` | object | emitter | Emitter-specific; **integer/string values only**; defaults to `{}`. |
| `prev_hash` | string | server-assigned | Hash of the previous record; `Genesis` (64 zeros) for seq 0. |
| `hash` | string | server-assigned | `SHA256(prev_hash + canonical(record_without_hash))`, hex lowercase. |

Key ordering on disk is whatever `encoding/json` emits for a Go map (sorted), but **ordering is
irrelevant to integrity** — the hash is computed over the *canonical* (sorted-key) form, so a
verifier reproduces it regardless of stored byte order. The `hash` field is excluded from its
own input.

### Data invariants (enforced in code)

- **Genesis:** the first record's `prev_hash` is `"0000…0000"` (64 zeros).
- **Linkage:** record *n*'s `prev_hash` equals record *n−1*'s `hash`.
- **Content binding:** `hash` recomputes exactly from the record's canonical content.
- **No floats** in any audited value (keeps canonicalization byte-exact). Convention, not yet
  guarded at input — see behaviors.md B-007 TODO.
- **Append-only:** the application never rewrites a line; integrity assumes the file is only
  appended to between emits.

## In-memory state — `Chain` (chain.go)

| Field | Type | Sharing / lock |
|-------|------|----------------|
| `mu` | `sync.Mutex` | Guards `Emit`; the single-writer lock. |
| `path` | string | Immutable after `NewChain`. |
| `seq` | int64 | Next sequence number; advanced under `mu`. |
| `prevHash` | string | Current chain head; advanced under `mu`. |

`seq` and `prevHash` are **derived state** — reconstructed from disk by `loadState()` on open.
The in-memory copy is never trusted by `Verify()`.

## Wire / interchange formats

- **IPC request:** newline-terminated JSON, `{"op":"emit","event":{…}}` / `{"op":"verify"}` /
  `{"op":"ping"}`.
- **IPC response:** one JSON line — `{seq,hash}`, the verify result, `{"ok":true}`, or
  `{error:{code,message,retryable}}`.
- **CLI output:** indented JSON to stdout.
