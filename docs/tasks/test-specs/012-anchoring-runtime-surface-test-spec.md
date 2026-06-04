# Test spec: 012 - anchoring runtime surface

## Scope

Expose Rekor anchoring and verification capabilities through the CLI subcommands and Unix socket IPC interface, ensuring emitters remain offline/non-blocking and the daemon remains secure against SSRF and key-path injection.

## Requirements traced

- REQ-012-01: Implement CLI subcommands `checkpoint anchor` (submitting checkpoints) and `checkpoint verify-anchor` (validating inclusion).
- REQ-012-02: Support daemon startup flags `--rekor-url` and `--rekor-public-key` for configuring the global Rekor instance.
- REQ-012-03: Implement the IPC operation `{"op":"checkpoint_anchor"}` which submits the current head's checkpoint to the configured Rekor instance.
- REQ-012-04: Implement the IPC operation `{"op":"checkpoint_verify","checkpoint":{...},"receipt":{...},"online":bool}` for validating anchors.
- REQ-012-05: Enforce that the daemon rejects client-submitted URLs or public key file paths to mitigate SSRF and key-injection vulnerabilities.

## Test cases

### TC-012-01 - Live CLI execution tests
- Command: Run `checkpoint anchor` and `checkpoint verify-anchor` subcommands.
- Expected:
  - `checkpoint anchor` returns a valid receipt JSON to stdout or writes it to `--out`.
  - `checkpoint verify-anchor` validates the receipt and checkpoint both offline and online.
  - Exits with code 0 on success, and 1 or 2 on failure.

### TC-012-02 - Live socket IPC tests
- Command: Execute `checkpoint_anchor` and `checkpoint_verify` operations over Unix socket.
- Expected:
  - `checkpoint_anchor` returns a valid receipt JSON object.
  - `checkpoint_verify` returns `{"valid":true,"signature_valid":true,"rekor_valid":true,"rekor_online_match":true,"message":"..."}` on successful verification.

### TC-012-03 - Missing daemon config
- Command: Call IPC anchoring/verification operations when daemon was started without Rekor configuration.
- Expected:
  - Returns `{"error":{"code":"checkpoint_not_configured","message":"...","retryable":false}}`.

### TC-012-04 - Compatibility checks
- Command: Verify that existing `emit`, `verify`, and `ping` commands remain functional and unchanged.
- Expected:
  - Ping returns `{"ok":true}`.
  - Emit appends event and returns `{seq, hash}`.
  - Verify walks the chain and validates it.

### TC-012-05 - SSRF and Key-injection mitigations
- Command: Send client-submitted URLs or public key file paths in IPC requests.
- Expected:
  - Requests are explicitly rejected with `bad_request` error codes and containing "rejected" message.
