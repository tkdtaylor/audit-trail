# Interfaces

**Project:** audit-trail · **Last updated:** 2026-06-03

## CLI surface ([main.go](../../main.go))

```
audit-trail <serve|emit|verify> [flags]
```

| Subcommand | Flags | Behavior |
|------------|-------|----------|
| `serve` | `--socket <path>` (required), `--logfile <path>` (default `audit.log`) | Run the IPC daemon. Errors to stderr; exits 2 if `--socket` missing. |
| `emit` | `--logfile <path>` (default `audit.log`), `--actor`, `--action`, `--target`, `--decision` (optional) | Append one event; prints `{seq,hash}`. `ts` = now. |
| `verify` | `--logfile <path>` (default `audit.log`) | Walk the chain; prints the result. **Exit 0 = valid, 1 = invalid.** |

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
| unparseable | — | `{"error":{"code":"bad_request",…}}` |
| unknown `op` | — | `{"error":{"code":"unknown_op","message":"unsupported op","retryable":false}}` |
| server-side emit failure | — | `{"error":{"code":"internal",…}}` |

**Error shape** is the shared ecosystem contract: `{error:{code,message,retryable}}`. All
current errors are `retryable:false`.

## Internal Go API ([chain.go](../../chain.go))

These are the load-bearing functions other code (and future backends) depends on:

| Symbol | Signature | Contract |
|--------|-----------|----------|
| `NewChain` | `func NewChain(path string) (*Chain, error)` | Open/create the log and resume `seq`/`prevHash` from disk. |
| `(*Chain).Emit` | `func (c *Chain) Emit(event map[string]any) (map[string]any, error)` | Append one event under the mutex; return `{seq,hash}`. |
| `(*Chain).Verify` | `func (c *Chain) Verify() VerifyResult` | Re-read the file from disk and walk the chain. |
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
