# Task 007 - checkpoint runtime surface

## Goal

Expose signed checkpoint creation and verification through the ADR-approved runtime surfaces
while preserving the frozen v1 `emit` and `verify` shapes.

Design decision: [ADR-003](../../architecture/decisions/003-signed-checkpoints.md).

## Requirements

- REQ-007-01: Add the ADR-approved CLI commands or flags for creating a signed checkpoint.
- REQ-007-02: Add the ADR-approved CLI commands or flags for verifying a signed checkpoint.
- REQ-007-03: Add the ADR-approved IPC operations, preserving the shared
  `{error:{code,message,retryable}}` shape.
- REQ-007-04: Keep existing `emit`, `verify`, `ping`, unknown-op, and malformed-request
  behavior unchanged.
- REQ-007-05: Update `docs/spec/interfaces.md` and `docs/spec/behaviors.md` for the new
  runtime-visible checkpoint surface.

## Acceptance criteria

- TC-007-01 passes.
- TC-007-02 passes.
- TC-007-03 passes.
- TC-007-04 passes.
- TC-007-05 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 006, because runtime surfaces should call the already-reviewed signing and verification
  primitives.

## Notes

This task is runtime-visible. Verify through the live binary path and the live Unix-socket path,
not only unit tests.
