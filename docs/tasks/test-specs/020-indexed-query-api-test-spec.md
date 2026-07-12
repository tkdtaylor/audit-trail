# Test spec: 020 - indexed query API

## Scope

Add a read-only `query` capability over the hash-chained log: a `query` op on the existing Unix-socket IPC surface (`handleConn` in `ipc.go`) and a `query` CLI subcommand (`main.go`). Filters on `actor`, `action`, `target`, `decision`, seq range, and ts range, combinable (AND), with a result limit and a continuation token. Results are the stored JSONL records verbatim (raw bytes, never recomputed). The query walk is derived state rebuilt from a full chain walk on demand; nothing is persisted, so index loss/corruption cannot exist and cannot affect `emit`/`verify` or tamper-evidence. Every query response carries the outcome of a fresh `verifyAllSegments` disk walk; a log that fails verification still returns results, flagged `verified:false` (ADR-006 decision). The frozen v1 `emit`/`verify` contract and all existing IPC ops are unchanged - this is additive, a new verb only.

## Fixture

All test cases below that query a populated log use this exact fixture, built in a `t.TempDir()` logfile via `Chain.Emit` (unit tests) or the live surfaces (runtime tests), in this order:

| seq | ts | actor | action | target | decision |
|---|---|---|---|---|---|
| 0 | 1700000000 | `vault` | `resolve` | `vault://db-creds` | `allow` |
| 1 | 1700000010 | `policy-engine` | `evaluate` | `exec:rm` | `deny` |
| 2 | 1700000020 | `vault` | `resolve` | `vault://api-key` | `allow` |
| 3 | 1700000030 | `armor` | `scan` | `https://example.com` | `flag` |
| 4 | 1700000040 | `vault` | `rotate` | `vault://db-creds` | `allow` |

`refs` and `context` are omitted on emit (stored as `[]`/`{}`). "Expected records" below means: the result element is byte-equal to the corresponding stored JSONL line on disk (compare against the line read back from the logfile, not against a re-marshalled map).

## Requirements traced

- REQ-020-01: IPC op `query` on the existing socket; request shape `{op:"query", filter:{...}, limit, token}`; response shape `{results, count, next_token, verified, tamper_detected_at, message}`.
- REQ-020-02: Filters `actor`, `action`, `target`, `decision` (exact string match) and `seq_min`/`seq_max`/`ts_min`/`ts_max` (inclusive int64 ranges), all optional, combined with AND; results in ascending seq order.
- REQ-020-03: `limit` (default 100, max 1000) plus opaque continuation `token`; `next_token` is non-null exactly when more matches remain; resubmitting with the token and the same filter returns the next page.
- REQ-020-04: Results are the stored records verbatim - raw on-disk line bytes (`json.RawMessage`), never re-hashed, re-canonicalized, or rebuilt from a decoded map.
- REQ-020-05: Every query runs a fresh `verifyAllSegments` walk from disk and reports `verified`/`tamper_detected_at`/`message`; a failing log still returns results with `verified:false` (never refuses - ADR-006).
- REQ-020-06: The query path is read-only: opens the log `O_RDONLY`, takes no emit mutex, writes nothing to disk, never mutates `Chain.seq`/`Chain.prevHash`; there is no persisted index.
- REQ-020-07: Query walks rotated logs across all segments (manifest order plus active segment), with manifest filenames validated the same way `verifyAllSegments` validates them.
- REQ-020-08: Malformed input returns the shared `{error:{code:"bad_request",message,retryable:false}}` shape: unknown filter key, non-integer JSON number in a range field, non-string value in a string field, `limit` outside 1..1000, non-numeric `token`.
- REQ-020-09: All existing v1 IPC ops (`emit`, `verify`, `ping`, `checkpoint_*`, `rotate`) and CLI commands produce unchanged responses; `query` is additive.
- REQ-020-10: CLI subcommand `audit-trail query` with flags `--logfile --actor --action --target --decision --seq-min --seq-max --ts-min --ts-max --limit --token`; prints the response JSON; exits 0 on a served query (including `verified:false`), 1 on operational error, 2 on usage error.
- REQ-020-11: `docs/spec/interfaces.md` and `docs/spec/behaviors.md` document the new surface in the same commit; ADR-006 records the query design and the flagged-unverified decision.

## Test cases

### TC-020-01 - single-field filters return exact seq sets

- Setup: fixture log; call the core query function (`runQuery`) directly, no limit/token.
- Table-driven, exact expectations:
  - `{actor:"vault"}` -> records seq [0, 2, 4], `count:3`.
  - `{action:"resolve"}` -> seq [0, 2].
  - `{target:"vault://db-creds"}` -> seq [0, 4].
  - `{decision:"deny"}` -> seq [1].
  - `{actor:"nobody"}` -> `results:[]`, `count:0`, `next_token:null`.
- Every non-empty case: results ascending by seq, each element byte-equal to its stored line, `verified:true`, `tamper_detected_at:null`, `message:"chain intact"`.

### TC-020-02 - combined filters and ranges (AND semantics, inclusive bounds)

- Setup: fixture log.
- Exact expectations:
  - `{actor:"vault", action:"resolve"}` -> seq [0, 2].
  - `{seq_min:1, seq_max:3}` -> seq [1, 2, 3] (both bounds inclusive).
  - `{ts_min:1700000010, ts_max:1700000030}` -> seq [1, 2, 3].
  - `{actor:"vault", seq_min:2}` -> seq [2, 4].
  - `{actor:"vault", decision:"deny"}` -> `results:[]`, `count:0` (AND, not OR).

### TC-020-03 - pagination: limit, continuation token, terminal page

- Setup: fixture log.
- Query `{actor:"vault"}` with `limit:2` -> seq [0, 2], `count:2`, `next_token:"3"` (decimal string of the resume seq).
- Resubmit `{actor:"vault"}` with `limit:2, token:"3"` -> seq [4], `count:1`, `next_token:null`.
- Query `{actor:"vault"}` with `limit:3` -> seq [0, 2, 4], `next_token:null` (page exactly consumed, no phantom next page).
- Omitted `limit` defaults to 100: all 3 matches, `next_token:null`.

### TC-020-04 - results are stored bytes, never recomputed

- Setup: fixture log; additionally tamper record seq 1 on disk (replace `"evaluate"` with `"evaluatX"` in the stored line, same length).
- Over live IPC (`serve` on a temp socket): send `{"op":"query","filter":{"actor":"policy-engine"}}`.
- Expected:
  - The raw response line contains the tampered on-disk line byte-for-byte (`bytes.Contains(responseLine, storedLine)`) - the record is returned as stored, tamper included, not re-derived.
  - `verified:false`, `tamper_detected_at:1`, `message:"content hash mismatch (tampered)"` in the same response.
- Mutation guard: a variant that re-marshals the decoded record instead of returning raw bytes must fail this test (assert byte equality against the disk line, not JSON-semantic equality).

### TC-020-05 - failed verification is surfaced, results still returned, read fresh from disk

- Setup: fixture log via a live `serve` daemon; after emitting, tamper record seq 3's stored `hash` field externally (edit the file behind the running daemon's back).
- Send `{"op":"query","filter":{"actor":"vault"}}` over the socket.
- Expected:
  - `results` = stored lines for seq [0, 2, 4] (matching records before the tamper point are still returned).
  - `verified:false` with the non-null `tamper_detected_at` and message produced by `verifyAllSegments` - proving the verified flag comes from a fresh disk walk, not the daemon's in-memory chain state.
  - The response is a success shape (no `{error:...}` envelope); querying a tampered log is not refused.

### TC-020-06 - query spans segments after rotation

- Setup: fixture log; rotate with `Chain.Rotate(3, "test-log", <fixed ts>, <test key>)` so `audit.log.001` holds seq 0..4 and the active segment is fresh (or threshold 5 rotating all five, then emit one more `vault` event at seq 5, ts 1700000050 - either way at least one match on each side of the boundary; pin the exact split in the test).
- Query `{actor:"vault"}` with no limit.
- Expected: matches from the rotated-out segment and the active segment, ascending seq order with no duplicates and no gaps versus the single-file result for the same events; `verified:true`.
- Manifest safety: a manifest whose segment field contains a path separator (e.g. `../evil`) makes the query return an error result, not read outside the log directory.

### TC-020-07 - malformed requests return the shared error shape; existing ops unchanged

- Over live IPC, each of the following returns `{error:{code:"bad_request",message:...,retryable:false}}` exactly (no results field):
  - `{"op":"query","filter":{"bogus":"x"}}` (unknown filter key)
  - `{"op":"query","filter":{"ts_min":1.5}}` (non-integer JSON number)
  - `{"op":"query","filter":{"actor":7}}` (non-string in a string field)
  - `{"op":"query","limit":0}` and `{"op":"query","limit":5000}` (limit out of 1..1000)
  - `{"op":"query","token":"abc"}` (non-numeric token)
- After the query op exists, existing ops are byte-shape-identical: `emit` -> `{seq,hash}`, `verify` -> `{valid,tamper_detected_at,message}`, `ping` -> `{"ok":true}`, `rotate` unconfigured -> `{error:{code:"rotation_not_configured",...}}`.

### TC-020-08 - CLI query subcommand live path

- Setup: fixture log on disk; run the built binary.
- `audit-trail query --logfile <log> --actor vault --limit 2`:
  - Exits 0.
  - Stdout JSON has `count:2`, results for seq 0 and 2 with `actor:"vault"`, `next_token:"3"`, `verified:true`.
- `audit-trail query --logfile <log> --actor vault --token 3` -> seq 4 only, `next_token:null`, exit 0.
- After tampering the log: `audit-trail query --logfile <log> --actor vault` exits 0 and prints `verified:false` with a non-null `tamper_detected_at` (exit code stays 0 - the flag is the signal; document this).
- `audit-trail query --logfile <log> --limit 0` exits 2 with a usage message on stderr.
- Missing logfile path -> exit 1 with `error:` on stderr.

### TC-020-09 - documentation and ADR

- `docs/spec/interfaces.md` documents the `query` IPC op (request and response shapes, error codes) and the `query` CLI subcommand with its flags and exit codes.
- `docs/spec/behaviors.md` documents: filters AND-combine, inclusive ranges, verbatim stored results, pagination token semantics, and the flagged-unverified behavior on a failing log.
- Both stay present-tense (no future tense).
- `docs/architecture/decisions/006-indexed-query-api.md` exists, status Accepted, and records: derived on-demand walk (no persisted index), why results are flagged unverified rather than refused, and the token format.
