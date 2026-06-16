# Task 017 - rotation runtime surface

## Goal

Expose log rotation through the ADR-005-specified CLI command and IPC operation, keeping the
emit path non-blocking and preserving all existing v1 `emit`/`verify`/`ping`/`checkpoint_*`
shapes unchanged.

Design decision: [ADR-005](../../architecture/decisions/005-log-rotation.md).

## Requirements

- REQ-017-01: Add the ADR-005-specified CLI command for triggering log rotation; print the
  rotation result as JSON to stdout.
- REQ-017-02: Add the ADR-005-specified IPC rotation operation; the daemon reads rotation
  configuration from startup flags only, not from per-request fields.
- REQ-017-03: The emit write path is never blocked by rotation; rotation must not stall a
  queued emit indefinitely.
- REQ-017-04: Missing rotation configuration over IPC returns
  `{error:{code,message,retryable:false}}` using the shared error shape.
- REQ-017-05: All existing v1 IPC ops (`emit`, `verify`, `ping`) and CLI operations produce
  unchanged responses.
- REQ-017-06: Update `docs/spec/interfaces.md` and `docs/spec/behaviors.md` for the new
  runtime-visible rotation surface.

## Acceptance criteria

- TC-017-01 passes.
- TC-017-02 passes.
- TC-017-03 passes.
- TC-017-04 passes.
- TC-017-05 passes.
- TC-017-06 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 016, because the runtime surface calls `Rotate()` and the cross-segment `Verify()`
  which must both be implemented and reviewed before being exposed through a live socket.

## Notes

This task is runtime-visible. Verify through the live binary CLI path and the live Unix-socket
path, not only unit tests — the TC-017-01 through TC-017-05 checks require live-path evidence
to reach ✅ in the coverage tracker. Update the daemon's `--help` text with the new flags.
