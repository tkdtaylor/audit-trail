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
  `"<json>\n"` to the logfile, fsyncing before returning (durability over throughput,
  matching the rotation paths). Advances in-memory `seq` (+1) and `prevHash` (← new hash).
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
- **Side effects:** None. Opens and re-reads the log from **disk** (not the in-memory chain),
  walking from `Genesis` forward.
- **Single vs multi-segment:** When no manifest is present on disk (a never-rotated log),
  `Verify()` walks the single active segment at `chain.path` and is byte-for-byte identical to
  the original single-file behavior — the degenerate 1-segment case. When a manifest is present,
  `Verify()` loads it and walks **every rotated-out segment in manifest order plus the active
  segment**, threading the carried ending `prev_hash` and global seq offset from each segment
  into the next (Genesis/0 for the first). Every segment is read from disk; the in-memory
  `prevHash`/`seq` are never trusted. The response shape is unchanged: `tamper_detected_at`
  reports the **global** seq of the first broken record.
- **CLI exit code:** 0 if valid, **1 if invalid** (so CI can gate on it).

## B-003 — Detect tampering

- **Trigger:** `verify()` over a logfile that has been altered after the fact.
- **Detected cases** (first one encountered wins, by line order):
  - **Broken link** — an entry's `prev_hash` ≠ the prior entry's `hash` → `"prev_hash link broken"`.
  - **Content mismatch** — recomputed `hash` ≠ stored `hash` (any byte of audited content
    changed) → `"content hash mismatch (tampered)"`.
  - **Corrupted line** — a line is not valid JSON → `"entry is not valid JSON (corrupted)"`,
    `tamper_detected_at` = line index.
- **Cross-segment cases** (rotated logs — same root of trust, the SHA-256 chain):
  - **Seam break** — the first record of segment N+1 must carry `prev_hash` equal to segment N's
    last `hash`. A reordered, swapped, or seam-tampered segment fails this link and reports
    `"prev_hash link broken"` at the first record of the offending segment
    (`TestVerifySeamPrevHashTamper`, `TestVerifyReorderedSegments`).
  - **Tamper in any segment** — a byte-level change in a rotated-out segment (not just the
    active one) → `"content hash mismatch (tampered)"` at that record's global seq
    (`TestVerifyTamperInEarlierSegment`).
  - **Dropped segment** — a segment listed in the manifest but missing from disk →
    `valid:false` with a message **naming the missing segment file**
    (`TestVerifyDroppedSegment`).
  - **Manifest field tamper** — the manifest is an index, **not** the root of trust. Each
    segment's walked `start_prev_hash`/`first_seq`/`last_seq`/`end_hash` is cross-checked against
    the manifest's recorded values; a forged field surfaces as `valid:false`
    (`TestVerifyTamperedManifestEndHash`, `TestVerifyTamperedManifestSeqRange`).
  - **Orphan / truncation** — an on-disk `<base>.NNN` segment beyond the manifest's coverage
    (e.g. a crash mid-rotate left a rotated-out segment unlisted) is **not** silently treated as
    a clean shorter log; `Verify()` returns `valid:false` naming the uncovered segment
    (`TestVerifyOrphanSegmentBeyondManifest`).
- **Guarantee:** A single-character change to any past entry — in any segment — fails
  verification (`TestEmitVerifyAndTamperDetection`, `TestVerifyTamperInEarlierSegment`).
  `Verify()` reads from disk, so corruption applied after the `Chain` is loaded is detected
  without reloading (`TestVerifyReadsFromDiskNotMemory`).

## B-004 — Resume an existing chain

- **Trigger:** `NewChain(path)` against a logfile that already has entries (new process, daemon
  restart, or fresh CLI invocation).
- **Response:** A `Chain` whose `seq` and `prevHash` continue from the last on-disk record.
- **Side effects:** `loadState()` replays the JSONL, counting entries and tracking the last
  `hash`. Blank lines are skipped. A subsequent `Emit` continues the same chain
  (`TestChainResumesFromDisk`).
- **Failure modes:** A malformed line during load returns an error (open fails closed).

## B-005 — Serve over a Unix socket

- **Trigger:** `audit-trail serve --socket <path> --logfile <path>` with optional checkpoint
  config flags `--checkpoint-log-id`, `--checkpoint-signing-key`, and
  `--checkpoint-public-key`.
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
- **`{"op":"checkpoint_create"}`** → signed checkpoint envelope when checkpoint signing config
  is present.
- **`{"op":"checkpoint_verify","checkpoint":{…},"compare_log":true}`** →
  `{valid,signature_valid,log_match,message}` when checkpoint verification config is present.
- **Unparseable request** → `{error:{code:"bad_request",…}}`.
- **Unknown op** → `{error:{code:"unknown_op",message:"unsupported op",retryable:false}}`.
- **Core event validation failure** → `{error:{code:"bad_request",…}}`.
- **Server-side emit failure** → `{error:{code:"internal",…}}`.
- **Checkpoint config/input failures** →
  `{error:{code:"checkpoint_not_configured"|"bad_request"|"invalid_log"|"internal",message,retryable:false}}`.

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

## B-010 — Create and verify checkpoints through runtime surfaces

Runtime checkpoint CLI subcommands are `checkpoint create` and `checkpoint verify`.
Runtime checkpoint IPC operations are `checkpoint_create` and `checkpoint_verify`.

- **CLI create trigger:** `audit-trail checkpoint create --logfile <path> --log-id <id>
  --signing-key <private-pem> [--out <path>]`.
- **CLI create response:** Verifies the on-disk log, derives a checkpoint payload from that
  verified head, signs `CheckpointPayloadBytes(payload)`, and prints an indented signed
  checkpoint envelope to stdout. When `--out` is set, writes the same JSON plus a trailing
  newline to that path with mode `0600`.
- **CLI verify trigger:** `audit-trail checkpoint verify --checkpoint <path> --public-key
  <public-pem> [--logfile <path>]`.
- **CLI verify response:** Prints `{valid, signature_valid, log_match, message}`. Signature-only
  verification returns `log_match:null`. With `--logfile`, audit-trail first verifies the
  signature, then verifies the logfile from disk and compares `tree_size`, `last_seq`, and
  `root_hash` to the signed payload. The logfile is walked with the **same single cross-segment
  walker** that produced the checkpoint, so a checkpoint created over a rotated (multi-segment)
  log compares against that log's cumulative global head — a freshly created checkpoint always
  reports `log_match:true` against its own log, whether or not rotation has occurred
  ("checkpointable ⟺ verifiable"). Exit code is `0` only when the requested verification is
  valid; invalid signatures, malformed checkpoints, tampered logs, and log mismatches exit
  non-zero.
- **IPC create trigger:** `{"op":"checkpoint_create"}`. The daemon uses
  `--checkpoint-log-id` and `--checkpoint-signing-key` from startup configuration; request
  bodies cannot supply key paths.
- **IPC verify trigger:** `{"op":"checkpoint_verify","checkpoint":{…},"compare_log":true}`.
  The daemon uses `--checkpoint-public-key` from startup configuration. `compare_log:true`
  compares against the daemon's logfile; absent or false verifies only the signature.
- **IPC failure modes:** Missing daemon checkpoint config returns
  `{error:{code:"checkpoint_not_configured",message:"checkpoint not configured",retryable:false}}`.
  Missing or malformed checkpoint objects and malformed key material return
  `{error:{code:"bad_request",...,retryable:false}}`. Source log verification failure during
  checkpoint creation returns `{error:{code:"invalid_log",...,retryable:false}}`.
- **v1 preservation:** Existing CLI `emit`/`verify` output and IPC `emit`/`verify`/`ping`,
  unknown-op, and malformed-request shapes are unchanged.

## B-011 — Submit signed checkpoints to Rekor (anchoring)

- **Trigger:** `audit-trail checkpoint anchor …` (CLI) or `{"op":"checkpoint_anchor"}` (IPC).
- **Response:** `RekorReceipt` object containing `{log_id, log_index, integrated_time, signed_entry_timestamp, entry_id}`.
- **Side effects:** Decodes the checkpoint, loads the operator public key, and forms a standard Sigstore `hashedrekord` request. Sends a POST request to Rekor's `POST /api/v1/log/entries` endpoint. Decodes and returns the inclusion proof.
- **SSRF protection:** The daemon will only query the URL configured at startup via `--rekor-url`.
- **Key-injection protection:** The daemon will only read keys configured at startup.

## B-012 — Verify Rekor anchoring (receipt validation)

- **Trigger:** `audit-trail checkpoint verify-anchor …` (CLI) or receipt-based `checkpoint_verify` (IPC).
- **Response:** `{valid, signature_valid, rekor_valid, rekor_online_match, message}`.
- **Offline verification:** Reconstructs the `hashedrekord` from the checkpoint and operator public key PEM. Canonicalizes it using RFC 8785 (JCS) to build the SET payload. Verifies the Rekor server's signature (`signed_entry_timestamp`) against the payload using the Rekor public key.
- **Online verification:** Performed offline verification first, then fetches the entry from Rekor using UUID (`entry_id`) or log index (`log_index`), and checks that all metadata and entry body fields match the local checkpoint and receipt.
- **Failure modes:** Any mismatch, invalid signature, or network timeout fails closed, returning `valid:false`.

## B-013 — Expose anchoring through CLI and IPC runtime surfaces

- **CLI anchor trigger:** `audit-trail checkpoint anchor --checkpoint <path> --rekor-url <url> --public-key <path> [--out <path>]`.
- **CLI verify-anchor trigger:** `audit-trail checkpoint verify-anchor --checkpoint <path> --receipt <path> --rekor-public-key <path> [--rekor-url <url>] [--public-key <path>]`.
- **IPC anchor trigger:** `{"op":"checkpoint_anchor"}`. Requires `--rekor-url`, `--rekor-public-key`, `--checkpoint-signing-key` and `--checkpoint-log-id` in daemon configuration.
- **IPC verify trigger:** `{"op":"checkpoint_verify","checkpoint":{…},"receipt":{…},"online":bool}`. Requires `--checkpoint-public-key` and `--rekor-public-key` in daemon configuration.
- **Rejection of client-submitted config:** IPC requests containing config-override fields (`rekor_url`, `public_key`, `signing_key`, etc.) are explicitly rejected with `bad_request` to prevent SSRF and key-injection.

## B-014 — Rotate the active segment through runtime surfaces

- **CLI trigger:** `audit-trail rotate --logfile <path> --rotate-after <N> --log-id <id> --signing-key <private-pem>`.
- **IPC trigger:** `{"op":"rotate"}` sent to a daemon started with `--rotate-after <N>`,
  `--checkpoint-log-id <id>`, and `--checkpoint-signing-key <private-pem>`.
- **At-or-above threshold response:** Closes the active segment, archives it as `<base>.NNN`,
  writes a signed boundary checkpoint to `<base>.NNN.checkpoint`, updates `<base>.manifest`
  atomically, opens a fresh active segment at `<base>`, and returns:
  `{"rotated":true,"segment":"<base>.NNN","first_seq":N,"last_seq":N,"checkpoint":"<base>.NNN.checkpoint"}`.
  The next `Emit` carries `prev_hash` equal to the rotated-out segment's last hash — no
  separate bridge record; the chain link is the bridge.
- **Below-threshold response:** Returns `{"rotated":false}` (CLI exit 0; IPC success shape, not
  an error). No files are touched.
- **IPC not-configured response:** If the daemon is started without `--rotate-after` (or
  `--checkpoint-log-id` / `--checkpoint-signing-key` are missing), the IPC op returns
  `{"error":{"code":"rotation_not_configured","message":"rotation not configured","retryable":false}}`.
  The daemon does not crash or partially rotate.
- **Emit path:** Rotation is always an explicit, separate operation — it never happens
  implicitly inside `Emit`. The emit hot path is untouched.
- **Concurrency:** `Rotate()` holds the chain mutex (`c.mu`) across the entire operation; `Emit()`
  and checkpoint ops also take `c.mu`. All writes are serialized. A concurrent emit waits for
  the rotation to finish (or vice versa) and then proceeds normally — neither stalls indefinitely
  because no network calls are made inside `Rotate()`.
- **Key-injection protection:** The daemon reads rotation configuration from startup flags only.
  The client-key-path rejection list covers `rotate` requests: any request containing
  `signing_key`, `key_path`, etc. is rejected with `bad_request`.
- **v1 preservation:** All existing `emit`/`verify`/`ping`/`checkpoint_*` CLI and IPC shapes
  are unchanged. `verify` now walks all segments (manifest + active) and returns the same
  `{valid, tamper_detected_at, message}` shape.

