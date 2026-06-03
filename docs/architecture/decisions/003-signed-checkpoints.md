# ADR-003 - Signed checkpoints

**Status:** Accepted · **Date:** 2026-06-03

## Context

ADR-001 names signed checkpoints as the first high-risk v1+ roadmap item. The existing log is
a linear hash chain: every record commits to the previous record through
`SHA256(prev_hash + JCS(record_without_hash))`, and `Verify()` proves that the on-disk chain is
internally consistent.

A checkpoint adds a compact, signed statement about a specific chain head. It does not replace
`emit`, `verify`, or the JSONL log. It gives downstream systems a stable object to archive,
witness, or anchor without changing the frozen v1 contract.

## Decision

Add signed checkpoints as an additive feature behind the existing emit/verify seam. A
checkpoint is a signed statement over the current, verified, disk-backed chain head.

### Checkpoint payload

The checkpoint payload is the object whose canonical bytes are signed:

| Field | Type | Meaning |
|-------|------|---------|
| `format` | string | Literal `audit-trail-checkpoint-v1`. |
| `version` | int | Literal `1`. |
| `contract` | string | Literal `audit-trail-v1`. |
| `log_id` | string | Operator-supplied stable identifier for this log. |
| `tree_size` | int | Number of records in the on-disk chain. |
| `last_seq` | int | Last record sequence number; `-1` when `tree_size` is `0`. |
| `root_hash` | string | Lowercase hex current chain head; `Genesis` for an empty log. |
| `hash_algorithm` | string | Literal `sha256-linear-chain-v1`. |
| `issued_at` | int | Unix seconds when the checkpoint was created. |

`tree_size`, `last_seq`, and `issued_at` are JSON integers with no fractional form. String
fields are UTF-8 JSON strings. `root_hash` is exactly 64 lowercase hex characters.

The checkpoint envelope is:

| Field | Type | Meaning |
|-------|------|---------|
| `payload` | object | The payload object above. |
| `signature` | object | Signature metadata and bytes. |

The signature object is:

| Field | Type | Meaning |
|-------|------|---------|
| `algorithm` | string | Literal `ed25519`. |
| `key_id` | string | `ed25519-sha256:` plus lowercase hex SHA-256 of the raw public key bytes. |
| `sig` | string | Signature bytes encoded with RFC 4648 base64url without padding. |

### Canonical signed bytes

The signed byte input is:

```
JCS(checkpoint.payload)
```

The `signature` object, including `algorithm`, `key_id`, and `sig`, is excluded from the signed
bytes. Verification still requires `algorithm == "ed25519"` and requires `key_id` to match the
verification public key fingerprint before checking the signature.

Checkpoint canonicalization uses the same no-floats JCS subset as audited records:
integer/string/bool/null/array/object values only, sorted object keys, UTF-8, and no
insignificant whitespace. The implementation must expose one deterministic payload-byte helper
so signing, verification, fixtures, and fitness checks all use the same input.

### Signing and key material

Use Ed25519 from the Go standard library (`crypto/ed25519`). No third-party dependency is
required.

Key files use PEM-wrapped standard encodings that Go's `crypto/x509` package reads and writes:

| Key | PEM label | DER format |
|-----|-----------|------------|
| Signing key | `PRIVATE KEY` | PKCS #8 Ed25519 private key. |
| Verification key | `PUBLIC KEY` | SubjectPublicKeyInfo Ed25519 public key. |

Malformed key files, non-Ed25519 keys, empty keys, malformed base64 signatures, unknown
algorithms, key-id mismatches, malformed payload fields, and wrong-key signatures all fail
closed. They must return validation errors through the relevant surface rather than silently
accepting or falling back to another algorithm.

### Verification rules

Creating a checkpoint must:

1. Read the log from disk.
2. Run the same chain verification logic as `Verify()`.
3. Refuse to checkpoint a tampered or malformed log.
4. Derive `tree_size`, `last_seq`, and `root_hash` from the verified on-disk state, not from an
   in-memory `Chain` copy.
5. Sign only `JCS(checkpoint.payload)`.

Verifying a checkpoint must:

1. Parse the checkpoint envelope and fail closed on unknown or malformed required fields.
2. Recompute canonical payload bytes from the parsed `payload`.
3. Require `signature.algorithm == "ed25519"`.
4. Require `signature.key_id` to match the supplied public key.
5. Verify `signature.sig` over the canonical payload bytes.
6. When a logfile is supplied for comparison, run `Verify()` on that file and require its
   `tree_size`, `last_seq`, and `root_hash` to match the checkpoint payload.

Signature verification alone proves that the checkpoint was signed by the key holder. Logfile
comparison additionally proves that the local disk log is at the checkpointed head.

## RFC 6962 terminology

This design intentionally borrows the RFC 6962 signed-tree-head vocabulary:

- `tree_size` means the number of entries committed to by the checkpoint.
- `root_hash` means the signed commitment to those entries.
- the signed envelope is an STH-like checkpoint that downstream witnesses or anchors can store.

The current `root_hash` is not a Merkle tree root. It is the current head of audit-trail's
linear SHA-256 hash chain. The `hash_algorithm` field names this explicitly as
`sha256-linear-chain-v1` so later Merkle or backend work cannot confuse the two. A future
Merkle-tree checkpoint requires a superseding ADR or a new checkpoint format/version.

## Runtime surface

Existing v1 operations remain unchanged:

- CLI `audit-trail emit ...` still prints `{seq,hash}`.
- CLI `audit-trail verify ...` still prints `{valid,tamper_detected_at,message}` and keeps its
  existing exit-code behavior.
- IPC `{"op":"emit"}`, `{"op":"verify"}`, and `{"op":"ping"}` keep their current success and
  error shapes.

Checkpoint operations are additive.

### CLI

Add a `checkpoint` command group:

```
audit-trail checkpoint create --logfile <path> --log-id <id> --signing-key <private-pem> [--out <path>]
audit-trail checkpoint verify --checkpoint <path> --public-key <public-pem> [--logfile <path>]
```

`checkpoint create` prints the checkpoint envelope as JSON to stdout unless `--out` is
provided. It exits non-zero if the log does not verify, the key is unusable, or the checkpoint
cannot be written.

`checkpoint verify` prints a checkpoint verification result. If `--logfile` is present, it also
compares the signed checkpoint to that on-disk log head. It exits `0` only when the requested
verification succeeds.

### IPC

Add IPC operations without accepting arbitrary per-request key paths:

| Request | Success response | Error response |
|---------|------------------|----------------|
| `{"op":"checkpoint_create"}` | Checkpoint envelope object | `{error:{code,message,retryable}}` |
| `{"op":"checkpoint_verify","checkpoint":{...},"compare_log":true}` | `{"valid":bool,"signature_valid":bool,"log_match":bool|null,"message":"..."}` | `{error:{code,message,retryable}}` |

The daemon receives checkpoint key paths and `log_id` through startup configuration added in
the runtime-surface task. Missing checkpoint configuration returns a non-retryable IPC error
such as `checkpoint_not_configured`. All IPC errors keep the shared
`{error:{code,message,retryable}}` shape.

## Integrity risks

- **Signing an unverified or stale head:** checkpoint creation must read and verify disk state
  before deriving payload fields.
- **Canonical byte drift:** one payload-byte helper must feed signing, verification, fixtures,
  and fitness checks.
- **Signature confusion:** only Ed25519 is supported; unknown algorithms and key-id mismatches
  fail closed.
- **Linear-chain vs Merkle-root confusion:** `hash_algorithm` makes the current root semantics
  explicit.
- **Contract leakage:** checkpoint surfaces are additive and must not alter v1 `emit` or
  `verify` shapes.
- **Key exposure through IPC:** clients do not provide arbitrary key file paths per request.

## Required verification evidence for implementation tasks

- Task 005 must include direct tests proving payload fields are derived from the verified
  on-disk chain state, including the empty-log case, and proving payload canonical bytes are
  stable.
- Task 006 must include altered-payload, altered-signature, malformed-key, wrong-key, and
  key-id-mismatch tests. It must receive a security-focused review before completion.
- Task 007 must exercise the live CLI create/verify path and the live Unix-socket
  `checkpoint_create` / `checkpoint_verify` path, while also showing existing `emit` and
  `verify` responses are unchanged.
- Task 008 must add deterministic fixtures and named fitness checks for payload-byte stability
  and signature tamper rejection.

## Consequences

- Checkpoints become a portable signed commitment to a chain head without changing the frozen
  v1 contract.
- Future witness/Rekor anchoring has one stable object to anchor.
- Future log rotation can use checkpoint boundaries, but must still preserve the invariant that
  verification reads from disk.
- The implementation remains standard-library-only.

## Links

- [ADR-001](001-foundational-stack.md) - foundational architecture and v1+ roadmap.
- [ADR-002](002-enforce-no-float-audit-values.md) - no-float audited values and JCS subset.
- [docs/CONTRACT.md](../../CONTRACT.md) - frozen v1 emit/verify contract.
- [docs/spec/interfaces.md](../../spec/interfaces.md) - current CLI and IPC surface.
- [docs/tasks/backlog/005-checkpoint-payload-core.md](../../tasks/backlog/005-checkpoint-payload-core.md)
- [docs/tasks/backlog/006-sign-and-verify-checkpoints.md](../../tasks/backlog/006-sign-and-verify-checkpoints.md)
- [docs/tasks/backlog/007-checkpoint-runtime-surface.md](../../tasks/backlog/007-checkpoint-runtime-surface.md)
- [docs/tasks/backlog/008-checkpoint-fitness-and-fixtures.md](../../tasks/backlog/008-checkpoint-fitness-and-fixtures.md)
