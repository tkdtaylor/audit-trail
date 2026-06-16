# Data Model

**Project:** audit-trail · **Last updated:** 2026-06-16

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
| `refs` | array | emitter | `[{type,id}]` attestation refs; recursive values may be integer/string/bool/null/array/object; defaults to `[]`. |
| `context` | object | emitter | Emitter-specific; recursive values may be integer/string/bool/null/array/object; defaults to `{}`. |
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
- **No floats** in any audited value (keeps canonicalization byte-exact). `Chain.Emit` rejects
  Go `float32` and `float64` values in audited event fields before hashing or appending.
- **Append-only:** the application never rewrites a line; integrity assumes the file is only
  appended to between emits.

## In-memory state — `Chain` (chain.go)

| Field | Type | Sharing / lock |
|-------|------|----------------|
| `mu` | `sync.Mutex` | Guards `Emit`, `BuildCheckpointPayload`, and `Rotate`; the single-writer lock. |
| `path` | string | Immutable after `NewChain`. |
| `seq` | int64 | Next sequence number; advanced under `mu`. |
| `prevHash` | string | Current chain head; advanced under `mu`. |

`seq` and `prevHash` are **derived state** — reconstructed from disk by `loadState()` on open.
The in-memory copy is never trusted by `Verify()`.

## Checkpoint payload

`CheckpointPayload` is the deterministic, unsigned statement over a verified on-disk chain
head. It is the object whose canonical bytes feed future signing and verification helpers.

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `format` | string | constant | Literal `audit-trail-checkpoint-v1`. |
| `version` | int | constant | Literal `1`. |
| `contract` | string | constant | Literal `audit-trail-v1`. |
| `log_id` | string | operator/config | Stable identifier for this log. |
| `tree_size` | int | verified logfile | Number of nonblank records in the on-disk chain. |
| `last_seq` | int | verified logfile | Last record sequence number; `-1` when `tree_size` is `0`. |
| `root_hash` | string | verified logfile | Current chain head; `Genesis` (64 zeros) for an empty log. |
| `hash_algorithm` | string | constant | Literal `sha256-linear-chain-v1`. |
| `issued_at` | int | caller | Unix seconds when the checkpoint payload is created. |

`BuildCheckpointPayload` derives `tree_size`, `last_seq`, and `root_hash` from the verified
disk state used by `Verify()`, not from the `Chain`'s in-memory `seq` or `prevHash`. Empty logs
produce `tree_size:0`, `last_seq:-1`, and `root_hash:Genesis`. Tampered, malformed, or
fractional-number logs fail closed and do not return a payload.

`CheckpointPayloadBytes` canonicalizes exactly the payload object with the same sorted-key,
no-insignificant-whitespace JCS subset used for audit records.

## Signed checkpoint envelope

`SignedCheckpoint` is the portable checkpoint object. Signing covers only
`CheckpointPayloadBytes(payload)`; the `signature` object is outside the signed bytes but is
strictly validated during verification.

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `payload` | object | checkpoint builder | The `CheckpointPayload` object above. |
| `signature` | object | signer | Ed25519 metadata and signature bytes. |

### Signature schema

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `algorithm` | string | constant | Literal `ed25519`; no other algorithm is accepted. |
| `key_id` | string | signer/verifier | `ed25519-sha256:` plus lowercase hex SHA-256 of the raw Ed25519 public key bytes. |
| `sig` | string | signer | Ed25519 signature over `CheckpointPayloadBytes(payload)`, encoded as RFC 4648 base64url without padding. |

Payload validation requires the literal checkpoint constants, non-empty `log_id`,
non-negative `tree_size`, `last_seq:-1` for an empty log, `last_seq == tree_size - 1` for a
non-empty log, a 64-character lowercase-hex `root_hash`, the literal hash algorithm, and a
non-negative `issued_at`. Signing refuses malformed payloads. Verification also refuses
malformed payloads, unknown algorithms, key-id mismatches, malformed signature encodings,
wrong-length signatures, wrong keys, and altered signed content.

## Log segments and the segment manifest

When the log is rotated (ADR-005), the single JSONL file becomes an **ordered sequence of
segments** held together by the same SHA-256 hash chain that links records. A never-rotated log
has no manifest and is byte-identical to the single-file case above (the degenerate case).

### Segment (on disk)

A segment is a JSONL file of audit records, identical in record format to the single log.

| Aspect | Value |
|--------|-------|
| Active segment | File at `Chain.path` (e.g. `audit.log`) — still taking writes. |
| Rotated-out segment | Sibling `<base>.NNN`, zero-padded monotonic (`audit.log.001`, `audit.log.002`, …; `n = manifest length + 1`). |
| Per-segment checkpoint | `<base>.NNN.checkpoint`, mode `0600` — an ADR-003 signed checkpoint over the **cumulative** chain head at that boundary (`tree_size`/`last_seq`/`root_hash` are global, not a per-segment subtree). |
| Record format | Unchanged (`{seq, ts, actor, action, target, decision, refs, context, prev_hash, hash}`). |

### `SegmentManifest` (segment.go)

JSON index at `<base>.manifest`, mode `0600`, written **atomically** (temp file in the same
directory → `os.Rename`, so a concurrent reader sees either the old manifest or the complete new
one, never a partial write). The manifest is an enumeration index, **not** the root of trust —
tamper-evidence stays cryptographic.

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `format` | string | constant | Literal `audit-trail-manifest-v1`. |
| `version` | int (int64) | constant | Literal `1`. |
| `segments` | array | rotation | Ordered list of segment entries, oldest first. |

Each `segments[]` entry (`Segment`):

| Field | Type | Source | Notes |
|-------|------|--------|-------|
| `segment` | string | rotation | Rotated-out segment filename (e.g. `audit.log.001`). |
| `first_seq` | int (int64) | rotation | Global `seq` of the segment's first record. |
| `last_seq` | int (int64) | rotation | Global `seq` of the segment's last record. |
| `start_prev_hash` | string | rotation | `prev_hash` the segment's first record carries (`Genesis` for segment 0, the previous segment's `end_hash` otherwise). |
| `end_hash` | string | rotation | The segment's last record's `hash` — the chain head at this boundary. |
| `issued_at` | int (int64) | caller | Unix seconds when the segment was rotated out. |

All numeric manifest fields are Go `int64` — no floats reach the manifest, consistent with the
no-floats invariant for audited data.

### Seam-continuity invariant (enforced at rotation)

> The `prev_hash` of the **first** record in segment N+1 equals the `hash` of the **last**
> record in segment N (Genesis for segment 0).

`Chain.Rotate()` carries `Chain.seq` and `Chain.prevHash` across the boundary unchanged when it
opens the fresh active segment, so the next `Emit()` writes the seam link automatically — there
is no separate bridge record. `loadState()` recovers the **global** offset from the manifest
(`last_seq + 1` and the last `end_hash`) before scanning the active segment, so a restart
mid-rotated-log resumes the correct global `seq` and `prevHash` from the active segment plus the
manifest. With no manifest, `loadState()` starts at `(0, Genesis)` exactly as before.

The rotation trigger is an **event-count threshold** on the active segment's record count:
`Rotate()` declines (no files touched, sentinel `errBelowRotationThreshold`) below the
threshold and proceeds at or above it. `Verify()`'s parameterized walker
(`verifyChainStateFrom(path, startPrev, startOffset)`) reproduces the single-file walk with
`(Genesis, 0)` and lets a rotated segment N>0 be re-verified/re-anchored from its non-Genesis
start hash and cumulative offset.

## Wire / interchange formats

- **IPC request:** newline-terminated JSON, `{"op":"emit","event":{…}}` / `{"op":"verify"}` /
  `{"op":"ping"}`.
- **IPC response:** one JSON line — `{seq,hash}`, the verify result, `{"ok":true}`, or
  `{error:{code,message,retryable}}`.
- **CLI output:** indented JSON to stdout.
