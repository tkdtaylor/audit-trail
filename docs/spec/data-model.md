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
| `mu` | `sync.Mutex` | Guards `Emit`; the single-writer lock. |
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

## Wire / interchange formats

- **IPC request:** newline-terminated JSON, `{"op":"emit","event":{…}}` / `{"op":"verify"}` /
  `{"op":"ping"}`.
- **IPC response:** one JSON line — `{seq,hash}`, the verify result, `{"ok":true}`, or
  `{error:{code,message,retryable}}`.
- **CLI output:** indented JSON to stdout.
