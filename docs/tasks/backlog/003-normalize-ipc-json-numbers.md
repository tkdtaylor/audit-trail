# Task 003 — normalize IPC JSON numbers

## Goal

Keep IPC usable after float rejection by preserving integer JSON numbers and rejecting
fractional values at the socket boundary with the correct client-error shape.

## Requirements

- REQ-003-01: Decode IPC JSON using a number-preserving path and normalize integer JSON numbers
  to integer Go values before `Chain.Emit`.
- REQ-003-02: Reject fractional JSON numbers in emitted event payloads.
- REQ-003-03: Return `{error:{code:"bad_request",message,retryable:false}}` for event
  validation failures.
- REQ-003-04: Preserve all existing IPC operations and error shapes outside numeric validation.
- REQ-003-05: Update `docs/spec/interfaces.md` and `docs/spec/behaviors.md` for the IPC numeric
  validation behavior.

## Acceptance criteria

- TC-003-01 passes.
- TC-003-02 passes.
- TC-003-03 passes.
- TC-003-04 passes.
- TC-003-05 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 002, because IPC should delegate the actual no-floats invariant to the core validator.

## Notes

This task is runtime-visible because it changes IPC responses for invalid numeric event
payloads. Verify it through the live socket path, not only unit tests.
