# Task 006 - sign and verify checkpoints

## Goal

Add standard-library checkpoint signing and signature verification over the deterministic
payload bytes from task 005.

Design decision: [ADR-003](../../architecture/decisions/003-signed-checkpoints.md).

## Requirements

- REQ-006-01: Implement the ADR's signature algorithm using only the Go standard library.
- REQ-006-02: Load and validate signing and verification keys in the ADR's configured format.
- REQ-006-03: Sign only the canonical checkpoint payload bytes from task 005.
- REQ-006-04: Verify checkpoint signatures and fail closed for malformed checkpoints,
  malformed keys, wrong keys, altered payload fields, or altered signatures.
- REQ-006-05: Update `docs/spec/configuration.md`, `docs/spec/data-model.md`, and
  `docs/spec/behaviors.md` for key configuration and signed checkpoint verification.

## Acceptance criteria

- TC-006-01 passes.
- TC-006-02 passes.
- TC-006-03 passes.
- TC-006-04 passes.
- TC-006-05 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 005, because signing must consume one deterministic checkpoint byte representation.

## Notes

This task is integrity-sensitive. Run a security-focused review before calling it done. Do not
add external dependencies.
