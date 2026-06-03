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
- **Failure modes:** Filesystem errors (open/write/close) propagate as an error (CLI: exit 1
  with `error:`; IPC: `{error:{code:"internal",…}}`).

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
- **`{"op":"verify"}`** → the verify result object.
- **`{"op":"ping"}`** → `{"ok":true}` (liveness).
- **Unparseable request** → `{error:{code:"bad_request",…}}`.
- **Unknown op** → `{error:{code:"unknown_op",message:"unsupported op",retryable:false}}`.
- **Emit failure** → `{error:{code:"internal",…}}`.

## B-007 — Canonicalization is order-independent

- **Trigger:** Hashing any record.
- **Guarantee:** Two records with identical key/value content but different key insertion order
  produce identical canonical bytes and therefore identical hashes — keys are sorted
  (`TestCanonicalIsOrderIndependent`). This is what lets an independent verifier reproduce a
  hash without knowing the emitter's serialization order.

---

> **Known gap:** There is no input-time guard rejecting float values in `context`. A float in
> `context` would canonicalize via Go's default float formatting, which can diverge from JCS.
> [ADR-002](../architecture/decisions/002-enforce-no-float-audit-values.md) accepts enforcing
> this invariant; [task 002](../tasks/backlog/002-reject-floats-in-core.md) tracks the
> implementation.
