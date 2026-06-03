# Behaviors

**Project:** audit-trail · **Last updated:** 2026-06-03

Observable behaviors of audit-trail. Each is numbered `B-NNN`. Source: [main.go](../../main.go),
[ipc.go](../../ipc.go), [chain.go](../../chain.go), validated by [chain_test.go](../../chain_test.go).

---

## B-001 — Emit an event

- **Trigger:** `audit-trail emit …` (CLI) or `{"op":"emit","event":{…}}` (IPC), or a direct
  `Chain.Emit(event)` call.
- **Response:** `{seq, hash}` — the assigned monotonic sequence number and the new chain head
  hash.
- **Side effects:** Builds a record `{seq, ts, actor, action, target, decision, refs, context,
  prev_hash}`, computes `hash = SHA256(prev_hash + canonical(record))`, and appends
  `"<json>\n"` to the logfile. Advances in-memory `seq` (+1) and `prevHash` (← new hash).
- **Defaults / normalization:** `refs` defaults to `[]`, `context` to `{}`, `ts` is coerced to
  int64, missing optional fields are stored as `null`. Via CLI, `ts` is `time.Now().Unix()` and
  `decision` is omitted from the event when the flag is empty.
- **Validation:** Audited event inputs copied into the record (`ts`, `actor`, `action`,
  `target`, `decision`, `refs`, `context`) must not contain Go `float32` or `float64` values.
  `refs` and `context` are checked recursively before hashing or appending. IPC decodes JSON
  numbers with preservation enabled, normalizes integer JSON numbers to `int64`, and rejects
  fractional JSON numbers before calling `Chain.Emit`.
- **Failure modes:** Float validation errors name the rejected location and return before any
  record is appended. IPC event validation failures return
  `{error:{code:"bad_request",…,retryable:false}}`. Filesystem errors (open/write/close)
  propagate as an error (CLI: exit 1 with `error:`; IPC: `{error:{code:"internal",…}}`).

## B-002 — Verify the chain

- **Trigger:** `audit-trail verify …` (CLI), `{"op":"verify"}` (IPC), or `Chain.Verify()`.
- **Response:** `{valid, tamper_detected_at, message}`.
  - Intact: `{valid:true, tamper_detected_at:null, message:"chain intact"}`.
  - Tampered: `valid:false`, `tamper_detected_at` = `seq` of the first broken entry, `message`
    describing the break.
- **Side effects:** None. Opens and re-reads the logfile from **disk** (not the in-memory
  chain), walking from `Genesis` forward.
- **CLI exit code:** 0 if valid, **1 if invalid** (so CI can gate on it).

## B-003 — Detect tampering

- **Trigger:** `verify()` over a logfile that has been altered after the fact.
- **Detected cases** (first one encountered wins, by line order):
  - **Broken link** — an entry's `prev_hash` ≠ the prior entry's `hash` → `"prev_hash link broken"`.
  - **Content mismatch** — recomputed `hash` ≠ stored `hash` (any byte of audited content
    changed) → `"content hash mismatch (tampered)"`.
  - **Corrupted line** — a line is not valid JSON → `"entry is not valid JSON (corrupted)"`,
    `tamper_detected_at` = line index.
- **Guarantee:** A single-character change to any past entry fails verification
  (`TestEmitVerifyAndTamperDetection`).

## B-004 — Resume an existing chain

- **Trigger:** `NewChain(path)` against a logfile that already has entries (new process, daemon
  restart, or fresh CLI invocation).
- **Response:** A `Chain` whose `seq` and `prevHash` continue from the last on-disk record.
- **Side effects:** `loadState()` replays the JSONL, counting entries and tracking the last
  `hash`. Blank lines are skipped. A subsequent `Emit` continues the same chain
  (`TestChainResumesFromDisk`).
- **Failure modes:** A malformed line during load returns an error (open fails closed).

## B-005 — Serve over a Unix socket

- **Trigger:** `audit-trail serve --socket <path> --logfile <path>`.
- **Response:** Long-lived daemon. Removes any stale socket, listens, `chmod 0600` on the
  socket, accepts connections, one goroutine per connection. Logs a startup line to stderr.
- **Per-request:** Reads one newline-terminated JSON request, dispatches on `op`, writes one
  JSON response line, closes the connection.

## B-006 — IPC ops: emit / verify / ping / errors

- **`{"op":"emit","event":{…}}`** → `{seq, hash}`; missing `event` → `{error:{code:"bad_request",
  message:"missing event",retryable:false}}`.
- **Emit numeric validation:** integer JSON numbers are accepted and normalized before append;
  fractional JSON numbers → `{error:{code:"bad_request",…}}` and no append.
- **`{"op":"verify"}`** → the verify result object.
- **`{"op":"ping"}`** → `{"ok":true}` (liveness).
- **Unparseable request** → `{error:{code:"bad_request",…}}`.
- **Unknown op** → `{error:{code:"unknown_op",message:"unsupported op",retryable:false}}`.
- **Core event validation failure** → `{error:{code:"bad_request",…}}`.
- **Server-side emit failure** → `{error:{code:"internal",…}}`.

## B-007 — Canonicalization is order-independent

- **Trigger:** Hashing any record.
- **Guarantee:** Two records with identical key/value content but different key insertion order
  produce identical canonical bytes and therefore identical hashes — keys are sorted
  (`TestCanonicalIsOrderIndependent`). This is what lets an independent verifier reproduce a
  hash without knowing the emitter's serialization order.
- **Input subset:** `Chain.Emit` rejects `float32` and `float64` values before record hashing
  so emitted records stay in the integer/string/bool/null/array/object subset described by
  ADR-001 and ADR-002.

## B-008 — Build a checkpoint payload

- **Trigger:** `Chain.BuildCheckpointPayload(logID, issuedAt)` from internal checkpoint code.
- **Response:** A `CheckpointPayload` with constants `format:"audit-trail-checkpoint-v1"`,
  `version:1`, `contract:"audit-trail-v1"`, `hash_algorithm:"sha256-linear-chain-v1"`, the
  caller's `log_id` and `issued_at`, and head fields derived from the verified on-disk chain.
- **Disk-backed head:** The builder uses the same disk walk as `Verify()`. It derives
  `tree_size`, `last_seq`, and `root_hash` from the verified on-disk chain, not from
  in-memory `Chain` state.
- **Empty log:** An intact empty logfile returns `tree_size:0`, `last_seq:-1`, and
  `root_hash` equal to `Genesis` (64 zeros).
- **Failure modes:** A tampered, malformed, unreadable, or fractional-number logfile fails
  closed with an invalid checkpoint-log error and no payload.
- **Canonical bytes:** `CheckpointPayloadBytes(payload)` returns
  `canonical(checkpoint.payload)`, excluding future signature envelope fields. The helper is
  the single signing-byte source for future signing, verification, fixtures, and fitness
  checks.

## B-009 — Sign and verify checkpoint signatures

- **Trigger:** `SignCheckpointPayload(payload, privateKey)` from checkpoint creation code, or
  `VerifySignedCheckpoint(checkpoint, publicKey)` from checkpoint verification code.
- **Signing response:** A signed checkpoint envelope with `payload` unchanged and
  `signature:{algorithm:"ed25519",key_id,sig}`. `key_id` is `ed25519-sha256:` plus the
  lowercase hex SHA-256 digest of the raw public key bytes. `sig` is an Ed25519 signature over
  `CheckpointPayloadBytes(payload)`, encoded as unpadded base64url.
- **Verification response:** `CheckpointVerificationResult` with
  `{valid:true, signature_valid:true, log_match:null, message:"checkpoint signature valid"}`
  when the signature verifies. Signature-only verification leaves `log_match` null because no
  logfile comparison has been requested yet.
- **Key loading:** Signing keys load from PEM-wrapped PKCS #8 Ed25519 private keys labeled
  `PRIVATE KEY`. Verification keys load from PEM-wrapped SubjectPublicKeyInfo Ed25519 public
  keys labeled `PUBLIC KEY`.
- **Failure modes:** Malformed payloads, malformed or missing key files, wrong key types,
  empty keys, unsupported algorithms, key-id mismatches, malformed base64url signatures,
  wrong-length signatures, altered payload fields, altered signatures, and wrong verification
  keys fail closed. Verification returns `{valid:false, signature_valid:false, log_match:null,
  message:"..."}` rather than panicking or falling back to another algorithm.
