# Task 002 — reject floats in core emit path

## Goal

Make the highest-value unenforced invariant executable: floats must not reach audited record
canonicalization through `Chain.Emit`.

Design decision: [ADR-002](../../architecture/decisions/002-enforce-no-float-audit-values.md).

## Requirements

- REQ-002-01: Reject float32 and float64 values before hashing or appending a record.
- REQ-002-02: Recursively validate event values that become audited record data, including
  nested `refs` and `context` values.
- REQ-002-03: Preserve successful emit/verify behavior for allowed value types:
  integer/string/bool/null/array/object.
- REQ-002-04: Return a clear validation error that names float rejection.
- REQ-002-05: Wire FF-004 into `make fitness` through a named `fitness-no-floats` target and
  update `docs/spec/fitness-functions.md`, `docs/spec/behaviors.md`, and
  `docs/spec/data-model.md`.

## Acceptance criteria

- TC-002-01 passes.
- TC-002-02 passes.
- TC-002-03 passes.
- TC-002-04 passes.
- TC-002-05 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 001, because this task adds a new named fitness rule to the umbrella runner.

## Notes

Keep the validation in or near the core path so every transport inherits the invariant. Do not
solve IPC JSON decoding in this task; task 003 handles preserving integer JSON numbers before
they reach `Chain.Emit`.
