# Task 012 - anchoring runtime surface

## Goal

Expose Rekor anchoring and verification capabilities through the CLI subcommands and Unix socket IPC interface, ensuring emitters remain offline/non-blocking and the daemon remains secure against SSRF and key-path injection.

Design decision: [ADR-004](../../architecture/decisions/004-witness-anchoring.md).

## Requirements

- REQ-012-01: Implement CLI subcommands `checkpoint anchor` (submitting checkpoints) and `checkpoint verify-anchor` (validating inclusion).
- REQ-012-02: Support daemon startup flags `--rekor-url` and `--rekor-public-key` for configuring the global Rekor instance.
- REQ-012-03: Implement the IPC operation `{"op":"checkpoint_anchor"}` which submits the current head's checkpoint to the configured Rekor instance.
- REQ-012-04: Implement the IPC operation `{"op":"checkpoint_verify","checkpoint":{...},"receipt":{...},"online":bool}` for validating anchors.
- REQ-012-05: Enforce that the daemon rejects client-submitted URLs or public key file paths to mitigate SSRF and key-injection vulnerabilities.

## Acceptance criteria

- TC-012-01: Live CLI execution tests verify that `checkpoint anchor` returns a valid receipt and `checkpoint verify-anchor` validates it.
- TC-012-02: Live socket tests verify that `checkpoint_anchor` and `checkpoint_verify` function correctly over IPC.
- TC-012-03: Missing daemon config results in a `checkpoint_not_configured` IPC error code.
- TC-012-04: Existing `emit`, `verify`, and `ping` commands remain functional and unchanged.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 011, because runtime actions require client and verification logic.
