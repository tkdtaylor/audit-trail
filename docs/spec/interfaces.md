# Interfaces

**Project:** audit-trail · **Last updated:** 2026-06-03

## CLI surface ([main.go](../../main.go))

```
audit-trail <serve|emit|verify|checkpoint> [flags]
```

| Subcommand | Flags | Behavior |
|------------|-------|----------|
| `serve` | `--socket <path>` (required), `--logfile <path>` (default `audit.log`), `--checkpoint-log-id <id>`, `--checkpoint-signing-key <private-pem>`, `--checkpoint-public-key <public-pem>` | Run the IPC daemon. Errors to stderr; exits 2 if `--socket` missing. Checkpoint IPC ops use the configured log ID and key paths; clients do not send key paths per request. |
| `emit` | `--logfile <path>` (default `audit.log`), `--actor`, `--action`, `--target`, `--decision` (optional) | Append one event; prints `{seq,hash}`. `ts` = now. |
| `verify` | `--logfile <path>` (default `audit.log`) | Walk the chain; prints the result. **Exit 0 = valid, 1 = invalid.** |
| `checkpoint create` | `--logfile <path>` (default `audit.log`), `--log-id <id>` (required), `--signing-key <private-pem>` (required), `--out <path>` (optional) | Verify the on-disk log, build a checkpoint payload from that verified head, sign it, and print the signed checkpoint envelope or write it to `--out`. |
| `checkpoint verify` | `--checkpoint <path>` (required), `--public-key <public-pem>` (required), `--logfile <path>` (optional) | Verify a signed checkpoint. If `--logfile` is present, also verify the log and compare its head to the checkpoint. **Exit 0 = valid, 1 = invalid.** |

Unknown subcommand or no args → usage to stderr, exit 2.

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
| `{"op":"checkpoint_create"}` | signed checkpoint envelope object | `checkpoint_not_configured` if `serve` lacks `--checkpoint-log-id` or `--checkpoint-signing-key`; `bad_request` for malformed key material; `invalid_log` for an unverified source log |
| `{"op":"checkpoint_verify","checkpoint":{…},"compare_log":true}` | `{"valid":bool,"signature_valid":bool,"log_match":bool|null,"message":"…"}` | `checkpoint_not_configured` if `serve` lacks `--checkpoint-public-key`; `bad_request` for missing or malformed checkpoint/key material |
| unparseable | — | `{"error":{"code":"bad_request",…}}` |
| unknown `op` | — | `{"error":{"code":"unknown_op","message":"unsupported op","retryable":false}}` |
| server-side emit failure | — | `{"error":{"code":"internal",…}}` |

**Error shape** is the shared ecosystem contract: `{error:{code,message,retryable}}`. All
current errors are `retryable:false`.

IPC ops `checkpoint_create` and `checkpoint_verify` are additive. `checkpoint_verify` uses
`compare_log:true` to compare against the daemon's configured logfile. If `compare_log` is
absent or false, it verifies only the checkpoint signature and returns `log_match:null`.

## Internal Go API ([chain.go](../../chain.go))

These are the load-bearing functions other code (and future backends) depends on:

| Symbol | Signature | Contract |
|--------|-----------|----------|
| `NewChain` | `func NewChain(path string) (*Chain, error)` | Open/create the log and resume `seq`/`prevHash` from disk. |
| `(*Chain).Emit` | `func (c *Chain) Emit(event map[string]any) (map[string]any, error)` | Append one event under the mutex; return `{seq,hash}`. |
| `(*Chain).Verify` | `func (c *Chain) Verify() VerifyResult` | Re-read the file from disk and walk the chain. |
| `(*Chain).BuildCheckpointPayload` | `func (c *Chain) BuildCheckpointPayload(logID string, issuedAt int64) (CheckpointPayload, error)` | Build a checkpoint payload from the verified on-disk head. |
| `(*Chain).CreateSignedCheckpoint` | `func (c *Chain) CreateSignedCheckpoint(logID string, issuedAt int64, privateKey ed25519.PrivateKey) (SignedCheckpoint, error)` | Build and sign a checkpoint over the verified on-disk head. |
| `VerifySignedCheckpoint` | `func VerifySignedCheckpoint(checkpoint SignedCheckpoint, publicKey ed25519.PublicKey) CheckpointVerificationResult` | Verify the signed checkpoint payload bytes and signature metadata. |
| `VerifySignedCheckpointForLog` | `func VerifySignedCheckpointForLog(checkpoint SignedCheckpoint, publicKey ed25519.PublicKey, logPath string) CheckpointVerificationResult` | Verify the signature and compare the payload head fields to a verified logfile. |
| `Genesis` | `const string` | The seq-0 `prev_hash`: 64 zeros. |
| `canonical` | `func canonical(v map[string]any) ([]byte, error)` | RFC 8785 / JCS bytes (canonical.go). |

`VerifyResult` = `{Valid bool, TamperDetectedAt *int64, Message string}` with JSON tags
`valid` / `tamper_detected_at` / `message`.

## External services called

**None.** Verification is fully offline and deterministic; the only external surface is the
filesystem (logfile) and the Unix socket.

> The v1 contract (CLI subcommands, IPC ops, the two verb signatures, the JCS rule) is **frozen**
> — see [docs/CONTRACT.md](../CONTRACT.md). Changing it requires a contracts bump + superseding
> ADR.
