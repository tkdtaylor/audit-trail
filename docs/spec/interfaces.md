# Interfaces

**Project:** audit-trail · **Last updated:** 2026-07-12

## CLI surface ([main.go](../../main.go))

```
audit-trail <serve|emit|verify|checkpoint|rotate|query> [flags]
```

| Subcommand | Flags | Behavior |
|------------|-------|----------|
| `serve` | `--socket <path>` (required), `--logfile <path>` (default `audit.log`), `--checkpoint-log-id <id>`, `--checkpoint-signing-key <private-pem>`, `--checkpoint-public-key <public-pem>`, `--rekor-url <url>`, `--rekor-public-key <public-pem>`, `--rotate-after <N>` (default `0` = disabled) | Run the IPC daemon. Errors to stderr; exits 2 if `--socket` missing. Checkpoint and rotation IPC ops use the configured log ID and key paths; clients do not send key paths per request. |
| `emit` | `--logfile <path>` (default `audit.log`), `--actor`, `--action`, `--target`, `--decision` (optional) | Append one event; prints `{seq,hash}`. `ts` = now. |
| `verify` | `--logfile <path>` (default `audit.log`) | Walk the chain across all segments; prints the result. **Exit 0 = valid, 1 = invalid.** |
| `rotate` | `--logfile <path>` (default `audit.log`), `--rotate-after <N>` (required, > 0), `--log-id <id>` (required), `--signing-key <private-pem>` (required) | Close the active segment when it holds at least `N` records, archiving it as `<base>.NNN`, writing a signed boundary checkpoint to `<base>.NNN.checkpoint`, updating the manifest, and opening a fresh active segment. Prints the rotation result as JSON to stdout. Below threshold prints `{"rotated":false}` and exits 0 (decline is not an error). |
| `query` | `--logfile <path>` (default `audit.log`), `--actor`, `--action`, `--target`, `--decision` (optional exact-match filters), `--seq-min`, `--seq-max`, `--ts-min`, `--ts-max` (optional inclusive range filters), `--limit <N>` (default `100`, must be `1..1000`), `--token <T>` (optional continuation token) | Read-only filtered scan of the chain across all segments; prints the query response as JSON to stdout. **Exit 0 on any served query, including `verified:false`** (the flag is the signal, not the exit code); **exit 1** on an operational error (e.g. unreadable logfile); **exit 2** on a usage error (e.g. `--limit` out of range). |
| `checkpoint create` | `--logfile <path>` (default `audit.log`), `--log-id <id>` (required), `--signing-key <private-pem>` (required), `--out <path>` (optional) | Verify the on-disk log, build a checkpoint payload from that verified head, sign it, and print the signed checkpoint envelope or write it to `--out`. |
| `checkpoint verify` | `--checkpoint <path>` (required), `--public-key <public-pem>` (required), `--logfile <path>` (optional) | Verify a signed checkpoint. If `--logfile` is present, also verify the log and compare its head to the checkpoint. **Exit 0 = valid, 1 = invalid.** |
| `checkpoint anchor` | `--checkpoint <path>` (required), `--rekor-url <url>` (required), `--public-key <public-pem>` (required), `--out <path>` (optional) | Submit a signed checkpoint to Rekor and write the returned receipt to `--out` or stdout. |
| `checkpoint verify-anchor` | `--checkpoint <path>` (required), `--receipt <path>` (required), `--rekor-public-key <public-pem>` (required), `--rekor-url <url>` (optional), `--public-key <public-pem>` (optional) | Verify a signed checkpoint and its Rekor receipt. Triggers online verification if `--rekor-url` is supplied. **Exit 0 = valid, 1 = invalid.** |

Unknown subcommand or no args → usage to stderr, exit 2.

### `query` request and response shapes

Both the CLI subcommand and the IPC op produce the same `QueryResponse` shape. `filter` fields are optional and AND-combined; `limit` defaults to `100`, max `1000`; `token` (IPC) / `--token` (CLI) is the opaque decimal-seq continuation cursor from a prior response's `next_token` (ADR-006 §3):

```json
{"results": [{"seq":0,"ts":1700000000,"actor":"vault","action":"resolve","target":"vault://db-creds","decision":"allow","refs":[],"context":{},"prev_hash":"0000…","hash":"ab12…"}],
 "count": 1,
 "next_token": null,
 "verified": true,
 "tamper_detected_at": null,
 "message": "chain intact"}
```

`results` are the stored JSONL lines verbatim (`json.RawMessage`, never re-marshalled, re-hashed, or re-canonicalized), ascending by `seq`. `verified`/`tamper_detected_at`/`message` always come from a fresh `verifyAllSegments` disk walk on every call: a query never refuses on a failing log, it flags the response `verified:false` instead (ADR-006 §2).

### `rotate` JSON response shapes

Successful rotation:

```json
{"rotated":true,"segment":"audit.log.001","first_seq":0,"last_seq":4,"checkpoint":"audit.log.001.checkpoint"}
```

Below-threshold (exit 0, not an error):

```json
{"rotated":false}
```

## IPC wire protocol ([ipc.go](../../ipc.go))

Newline-delimited JSON over a Unix domain socket (`--socket`). One request → one response,
then the connection closes. Socket is `chmod 0600`.

IPC request decoding preserves JSON numbers. For `emit` events, integer JSON numbers are
normalized to Go `int64` values before the core `Chain.Emit` call; fractional JSON numbers are
rejected as client input.

| Request | Success response | Error response |
|---------|------------------|----------------|
| `{"op":"emit","event":{…}}` | `{"seq":N,"hash":"…"}` | `{"error":{"code":"bad_request","message":"missing event","retryable":false}}` if `event` absent; `bad_request` for fractional JSON numbers or core event validation failures |
| `{"op":"verify"}` | `{"valid":…,"tamper_detected_at":…,"message":"…"}` | — |
| `{"op":"ping"}` | `{"ok":true}` | — |
| `{"op":"rotate"}` | `{"rotated":true,"segment":"…","first_seq":N,"last_seq":N,"checkpoint":"…"}` on success; `{"rotated":false}` when below threshold | `{"error":{"code":"rotation_not_configured","message":"rotation not configured","retryable":false}}` if `serve` lacks `--rotate-after`, `--checkpoint-log-id`, or `--checkpoint-signing-key`; `bad_request` for malformed key material; `internal` for filesystem errors |
| `{"op":"query","filter":{…},"limit":N,"token":"…"}` | `{"results":[…],"count":N,"next_token":"…"|null,"verified":bool,"tamper_detected_at":N|null,"message":"…"}`, always returned, even when `verified:false` (ADR-006 §2) | `bad_request` for an unrecognized filter key, a non-integer JSON number in a range field, a non-string value in a string field, `limit` outside `1..1000`, or a non-numeric `token`; `internal` for an invalid manifest segment name (path-traversal defense, REQ-020-07) or a filesystem error |
| `{"op":"checkpoint_create"}` | signed checkpoint envelope object | `checkpoint_not_configured` if `serve` lacks `--checkpoint-log-id` or `--checkpoint-signing-key`; `bad_request` for malformed key material; `invalid_log` for an unverified source log |
| `{"op":"checkpoint_verify","checkpoint":{…},"compare_log":true}` | `{"valid":bool,"signature_valid":bool,"log_match":bool|null,"message":"…"}` | `checkpoint_not_configured` if `serve` lacks `--checkpoint-public-key`; `bad_request` for missing or malformed checkpoint/key material |
| `{"op":"checkpoint_anchor"}` | RekorReceipt object | `checkpoint_not_configured` if `serve` lacks `--rekor-url`, `--rekor-public-key` or operator keys; `internal` for HTTP submit errors |
| `{"op":"checkpoint_verify","checkpoint":{…},"receipt":{…},"online":bool}` | `{"valid":bool,"signature_valid":bool,"rekor_valid":bool,"rekor_online_match":bool|null,"message":"…"}` | `checkpoint_not_configured` if `serve` lacks keys or `rekor-url` (when online:true); `bad_request` for key-injection attempts or malformed content |
| unparseable | — | `{"error":{"code":"bad_request",…}}` |
| unknown `op` | — | `{"error":{"code":"unknown_op","message":"unsupported op","retryable":false}}` |
| server-side emit failure | — | `{"error":{"code":"internal",…}}` |

**Error shape** is the shared ecosystem contract: `{error:{code,message,retryable}}`. All
current errors are `retryable:false`.

IPC ops `checkpoint_create` and `checkpoint_verify` are additive. `checkpoint_verify` uses
`compare_log:true` to compare against the daemon's configured logfile. If `compare_log` is
absent or false, it verifies only the checkpoint signature and returns `log_match:null`.
If `receipt` is present, `checkpoint_verify` performs receipt-based anchor verification (both offline, and online if `online:true`). Clients cannot submit key paths or URLs to the daemon; any request containing configuration-override fields is rejected with `bad_request` to prevent SSRF and key-injection.

The `rotate` op uses the daemon's startup-time `--rotate-after` threshold, `--checkpoint-log-id`,
and `--checkpoint-signing-key`. Clients cannot submit a threshold, key path, or log path per
request. The client-key-path rejection list applies to `rotate` requests the same as all other ops.

The `query` op is read-only and additive (task 020, ADR-006): it queries the daemon's startup `--logfile` chain across all segments (manifest order plus the active segment); per-request paths are not accepted, the same posture as `rotate`. It takes no `Chain.mu` lock, opens segment files `O_RDONLY`, and writes nothing, so it can run concurrently with `emit`/`rotate` without coordination. There is no persisted index; every call re-walks the log from disk (ADR-006 §1).

## Internal Go API ([chain.go](../../chain.go))

These are the load-bearing functions other code (and future backends) depends on:

| Symbol | Signature | Contract |
|--------|-----------|----------|
| `NewChain` | `func NewChain(path string) (*Chain, error)` | Open/create the log and resume `seq`/`prevHash` from disk. |
| `(*Chain).Emit` | `func (c *Chain) Emit(event map[string]any) (map[string]any, error)` | Append one event under the mutex; return `{seq,hash}`. |
| `(*Chain).Verify` | `func (c *Chain) Verify() VerifyResult` | Re-read all segments from disk and walk the chain. |
| `(*Chain).Rotate` | `func (c *Chain) Rotate(threshold int64, logID string, issuedAt int64, privateKey ed25519.PrivateKey) (RotateResult, error)` | Close the active segment (if at or above threshold) under the chain mutex; returns `errBelowRotationThreshold` when below threshold. |
| `runQuery` | `func runQuery(logPath string, f QueryFilter, limit, resumeSeq int64) (QueryResponse, error)` (query.go) | Read-only, filtered scan across all segments plus the active segment; no lock, no writes, no persisted index (ADR-006). |
| `(*Chain).BuildCheckpointPayload` | `func (c *Chain) BuildCheckpointPayload(logID string, issuedAt int64) (CheckpointPayload, error)` | Build a checkpoint payload from the verified on-disk head. |
| `(*Chain).CreateSignedCheckpoint` | `func (c *Chain) CreateSignedCheckpoint(logID string, issuedAt int64, privateKey ed25519.PrivateKey) (SignedCheckpoint, error)` | Build and sign a checkpoint over the verified on-disk head. |
| `VerifySignedCheckpoint` | `func VerifySignedCheckpoint(checkpoint SignedCheckpoint, publicKey ed25519.PublicKey) CheckpointVerificationResult` | Verify the signed checkpoint payload bytes and signature metadata. |
| `VerifySignedCheckpointForLog` | `func VerifySignedCheckpointForLog(checkpoint SignedCheckpoint, publicKey ed25519.PublicKey, logPath string) CheckpointVerificationResult` | Verify the signature and compare the payload head fields to a verified logfile. |
| `Genesis` | `const string` | The seq-0 `prev_hash`: 64 zeros. |
| `canonical` | `func canonical(v map[string]any) ([]byte, error)` | RFC 8785 / JCS bytes (canonical.go). |

`VerifyResult` = `{Valid bool, TamperDetectedAt *int64, Message string}` with JSON tags
`valid` / `tamper_detected_at` / `message`.

`RotateResult` = `{Rotated bool, Segment string, FirstSeq int64, LastSeq int64, Checkpoint string}`
with JSON tags `rotated` / `segment` / `first_seq` / `last_seq` / `checkpoint`.

`QueryResponse` = `{Results []json.RawMessage, Count int64, NextToken *string, Verified bool, TamperDetectedAt *int64, Message string}`
with JSON tags `results` / `count` / `next_token` / `verified` / `tamper_detected_at` / `message`.
`QueryFilter` = `{Actor, Action, Target, Decision *string, SeqMin, SeqMax, TsMin, TsMax *int64}` (query.go).

## External services called

**None.** Verification is fully offline and deterministic; the only external surface is the
filesystem (logfile) and the Unix socket.

> The v1 contract (CLI subcommands, IPC ops, the two verb signatures, the JCS rule) is **frozen**
> — see [docs/CONTRACT.md](../CONTRACT.md). Changing it requires a contracts bump + superseding
> ADR. The `rotate` command and `{"op":"rotate"}` IPC op are additive v1+ surfaces, as are the
> `query` command and `{"op":"query"}` IPC op (task 020, ADR-006).
