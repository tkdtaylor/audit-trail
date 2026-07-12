# Task 020 - indexed query API

## Goal

Add the roadmap's **indexed query API** item ([docs/ROADMAP.md](../../ROADMAP.md): "Additive, read-only. Must not become a second writer or bypass `Verify()`'s disk read."): a read-only `query` op over the existing Unix-socket IPC surface plus a CLI `query` subcommand, filtering the hash-chained log on actor/action/target/decision/seq range/ts range with pagination. The frozen v1 `emit`/`verify` contract (docs/CONTRACT.md) does not change - this is a new verb only.

Design decision: write [ADR-006](../../architecture/decisions/006-indexed-query-api.md) as the first milestone of this task (roadmap discipline: ADR at pick-up time). Its content is fixed by the decisions below - record them, don't reopen them.

## Context

Consumers, in order of pull:

- **armor incident review** - "show me everything actor X did between ts A and ts B" during an injection/exfil investigation, without hand-grepping JSONL across rotated segments.
- **policy decision traces** - policy-engine emits allow/deny decisions here; auditors need `decision:"deny"` slices per target.
- **agent-builder forensics** - the orchestrator's audit spine; post-incident reconstruction of one agent's actions across a rotated multi-segment log.

All three are read paths over a possibly tampered log - which drives the two design decisions:

1. **No persisted index.** The "index" is derived state rebuilt from a full chain walk on demand, per query. Nothing is written to disk and no emit-path hook exists, so index loss/corruption is impossible by construction and can never affect `emit`/`verify` or tamper-evidence. This also honors the roadmap's "must not become a second writer". An incremental in-memory index in `serve` is a later optimization, not this task.
2. **A log that fails verification returns results flagged `verified:false` - it does not refuse.** Justification (record in ADR-006): this is a forensic archive; the highest-value query moment is incident review of a log that may already be tampered. Refusing would make the API useless exactly then, and would hand an attacker a one-byte denial-of-forensics. Tamper-evidence is preserved because every response carries the fresh `verifyAllSegments` verdict (`verified`, `tamper_detected_at`, `message`) and results are the stored bytes verbatim - the tamper travels with the evidence instead of hiding it.

## Interfaces

New IPC op (same newline-terminated JSON-over-Unix-socket transport as `emit`/`verify`/`rotate` in `ipc.go`):

Request - all `filter` fields optional and AND-combined; `limit` optional (default 100, max 1000); `token` optional:

```json
{"op": "query",
 "filter": {"actor": "vault", "action": "resolve", "target": "vault://db-creds",
            "decision": "allow", "seq_min": 0, "seq_max": 99,
            "ts_min": 1700000000, "ts_max": 1700000099},
 "limit": 100,
 "token": "3"}
```

Response - `results` are the stored JSONL records verbatim (raw bytes), ascending seq; `next_token` non-null only when more matches remain; `verified`/`tamper_detected_at`/`message` come from a fresh `verifyAllSegments` disk walk on every query:

```json
{"results": [{"seq": 0, "ts": 1700000000, "actor": "vault", "action": "resolve",
              "target": "vault://db-creds", "decision": "allow", "refs": [],
              "context": {}, "prev_hash": "0000…", "hash": "ab12…"}],
 "count": 1,
 "next_token": null,
 "verified": true,
 "tamper_detected_at": null,
 "message": "chain intact"}
```

Errors use the shared shape from `errShape` in `ipc.go`: `{"error":{"code":"bad_request","message":"…","retryable":false}}`. Bad-request cases: unknown filter key, non-integer JSON number in `seq_*`/`ts_*` (reuse the `normalizeJSONNumbers` convention), non-string in a string field, `limit` outside 1..1000, non-numeric `token`.

Token format (record in ADR-006): decimal string of the global seq at which the scan resumes (first candidate record has `seq >=` token). Opaque to clients; only meaningful with the same filter; the server does not validate filter equality across pages.

CLI:

```
audit-trail query --logfile audit.log [--actor A] [--action A] [--target T] [--decision D]
                  [--seq-min N] [--seq-max N] [--ts-min N] [--ts-max N] [--limit N] [--token T]
```

Prints the response JSON via the existing `printJSON` (indentation only - `json.RawMessage` keeps key order and scalar bytes). Exit 0 on any served query **including `verified:false`** (the flag is the signal; a nonzero exit would break forensic pipelines - unlike `cmdVerify`, whose job is the verdict). Exit 1 on operational error (unreadable log), exit 2 on usage error.

## Requirements

- REQ-020-01: `query` op wired as a new `case "query":` in `handleConn` (`ipc.go`), request/response shapes exactly as above. The daemon queries its startup `--logfile` chain; per-request paths are not accepted (same posture as `rotate`, task 017).
- REQ-020-02: Filters `actor`/`action`/`target`/`decision` are exact string matches against the stored record fields; `seq_min`/`seq_max`/`ts_min`/`ts_max` are inclusive int64 bounds; all optional; AND-combined; results ascending by seq.
- REQ-020-03: `limit` default 100, max 1000; `next_token` per the token format above; continuation with the same filter returns the next page; a page that exactly exhausts the matches has `next_token:null`.
- REQ-020-04: Results are the stored on-disk line bytes (`json.RawMessage` per matching line, trailing newline trimmed) - never re-marshalled from a decoded map, never re-hashed, never re-canonicalized via `canonical()` (`canonical.go`).
- REQ-020-05: Every query calls `verifyAllSegments(logPath)` (`chain.go`) fresh and copies its verdict into `verified`/`tamper_detected_at`/`message`; a failing log still returns matching records, flagged unverified (ADR-006 decision).
- REQ-020-06: The query path is strictly read-only: opens files `O_RDONLY`, takes no `Chain.mu` lock, writes nothing, never mutates `Chain.seq`/`Chain.prevHash`, persists no index.
- REQ-020-07: Rotated logs are queried across all segments: walk `loadManifest(manifestPath(logPath))` segments in manifest order, then the active segment, reusing the manifest-filename validation `verifyAllSegments` applies (untrusted manifest, no path traversal - `segment.go`).
- REQ-020-08: Malformed requests return the shared `bad_request` error shape (exact cases in the test spec, TC-020-07).
- REQ-020-09: All existing IPC ops (`emit`, `verify`, `ping`, `checkpoint_create`, `checkpoint_anchor`, `checkpoint_verify`, `rotate`) and CLI commands are byte-shape unchanged; `query` is additive only.
- REQ-020-10: CLI `query` subcommand as specified above, wired into `main()`'s dispatch and the `usage()` string in `main.go`.
- REQ-020-11: `docs/spec/interfaces.md` and `docs/spec/behaviors.md` updated in the feat commit (present tense); ADR-006 written first, recording the no-persisted-index design, the flagged-unverified decision, and the token format.

## Files and functions

New file `query.go` (package `main`, alongside the other roots - this repo is a flat single package):

- `type QueryFilter struct { Actor, Action, Target, Decision *string; SeqMin, SeqMax, TsMin, TsMax *int64 }`
- `type QueryResponse struct { Results []json.RawMessage "json:\"results\""; Count int64 "json:\"count\""; NextToken *string "json:\"next_token\""; Verified bool "json:\"verified\""; TamperDetectedAt *int64 "json:\"tamper_detected_at\""; Message string "json:\"message\"" }`
- `func parseQueryRequest(req map[string]any) (QueryFilter, int64, int64, error)` - returns filter, limit, resume seq; rejects unknown filter keys and bad types.
- `func runQuery(logPath string, f QueryFilter, limit, resumeSeq int64) (QueryResponse, error)` - enumerates segments (manifest order + active), streams lines, applies filters against the decoded record while keeping the raw line for the result, honors limit/resume, then attaches the `verifyAllSegments(logPath)` verdict.
- `func matchesFilter(rec map[string]any, f QueryFilter) bool`

Edits:

- `ipc.go`: add `case "query":` in `handleConn` calling a small `queryForIPC(req map[string]any, chain *Chain) (QueryResponse, error)` that parses the request and runs `runQuery(chain.path, …)`. No new keys needed in the client-submitted-path rejection list (query carries no paths/URLs/keys).
- `main.go`: add `case "query": cmdQuery(os.Args[2:])`, extend `usage()` to `<serve|emit|verify|checkpoint|rotate|query>`, add `func cmdQuery(args []string)` (flag parsing mirrors `cmdVerify`/`cmdRotate`).

New tests:

- `query_test.go` - TC-020-01/02/03/06 against `runQuery` (fixture from the test spec, `t.TempDir()`, table-driven with `t.Run`).
- `query_runtime_test.go` - TC-020-04/05/07/08 over the live socket and built binary; follow the pattern in `rotation_runtime_test.go`.

## Implementation outline

1. `scripts/start-task.sh 020 indexed-query-api`; if it prints `WORKTREE <path>`, `cd <path>` before anything else.
2. Write ADR-006 (decisions fixed above). Commit: `docs: add ADR 006 — indexed query API`.
3. Add the task 020 row to `docs/tasks/test-specs/coverage-tracker.md` (spec file already exists: `020-indexed-query-api-test-spec.md`). Commit: `test: add spec for task 020 — indexed query API`.
4. Implement `query.go` core (`QueryFilter`, `QueryResponse`, `parseQueryRequest`, `runQuery`, `matchesFilter`) with `query_test.go` red-then-green against the fixture.
5. Wire `ipc.go` (`case "query"`, `queryForIPC`) and `main.go` (`cmdQuery`, dispatch, usage); add `query_runtime_test.go` for the live socket + CLI paths, including the tamper cases.
6. Update `docs/spec/interfaces.md` (op + subcommand + shapes + error codes + exit codes) and `docs/spec/behaviors.md` (filter/pagination/verbatim/unverified-flag semantics). Same commit as the code.
7. Move this file to `docs/tasks/completed/`, set the tracker row to 🟡. Commit: `feat: complete task 020 — indexed query API`.
8. Run spec-verifier; on APPROVE with L5/L6 evidence recorded, promote 🟡 -> ✅ in a separate `verify: confirm task 020 — <evidence>` commit; merge to main.

## Acceptance criteria

- TC-020-01 through TC-020-09 pass.
- `go build ./...`, `go test ./...`, `go test -race ./...` all green; `make check` and `make fitness` exit 0.
- `git diff` on `chain.go`'s `Emit`/`Verify`/`verifyAllSegments` and on `canonical.go` shows no behavioral change (additive wiring only).
- Live-path evidence quoted for the runtime-visible surfaces (see Verification plan).

## Verification plan

Highest achievable level: **L6 (live binary observed)** - this task is runtime-visible on both transports.

- Unit/harness: `go test -run 'TestQuery' ./...` then `go test ./...` and `go test -race ./...`; `make check`; `make fitness`.
- Live CLI: build `bin/audit-trail`; emit the 5 fixture events; run `audit-trail query --logfile <log> --actor vault --limit 2` and quote the JSON (`count:2`, `next_token:"3"`, `verified:true`); rerun with `--token 3`; tamper one byte in the logfile and rerun, quoting `verified:false` + `tamper_detected_at` with exit code 0.
- Live IPC: `audit-trail serve --socket <tmp>/q.sock --logfile <log>`; send `{"op":"query","filter":{"actor":"vault"}}` and a `bad_request` case over the socket; quote both responses; confirm `ping`/`emit`/`verify` responses unchanged after the query op lands.
- Rotated log: after a `rotate`, run the same CLI query and quote the cross-segment result.

## Out of scope

- Pluggable backends (Rekor/immudb/Postgres/SQLite) - separate roadmap item, deliberately last.
- Emitter authentication/authorization - socket permissions (owner-only, `listenUnix`) remain the access control.
- A persisted or incrementally maintained index (on-disk or in the `serve` process) - future optimization once the query semantics are exercised.
- Filtering on `refs`/`context` contents, prefix/regex/free-text matching, ordering other than ascending seq, streaming responses.
- Any change to the v1 `emit`/`verify` shapes, the record schema, or `canonical()`.

## Dependencies

- None (roadmap marks this item independent; tasks 001-018 it touches - IPC surface, rotation walk - are already shipped and merged).

## Notes

This task is runtime-visible on both transports: reaching ✅ requires live CLI and live socket evidence (L6), not unit tests alone. The integrity-sensitive part is what the task must *not* do - keep `Emit`, `Verify`, `verifyAllSegments`, and `canonical()` untouched, and never let query results pass through a re-marshal (the verbatim guarantee is what makes the output forensic evidence). Do a security-focused self-review of the segment-name handling (untrusted manifest) before the feat commit.
