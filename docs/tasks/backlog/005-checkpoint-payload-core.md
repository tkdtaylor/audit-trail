# Task 005 - checkpoint payload core

## Goal

Add the deterministic core representation for a checkpoint over the current chain head without
adding signatures or runtime command surfaces yet.

Design decision: task 004's signed-checkpoints ADR.

## Requirements

- REQ-005-01: Add a checkpoint data model matching the ADR's payload fields.
- REQ-005-02: Build checkpoint payloads from the on-disk chain state so a checkpoint reflects
  the same disk-backed truth that `Verify()` uses.
- REQ-005-03: Produce byte-stable canonical checkpoint payload bytes for signing and
  verification.
- REQ-005-04: Reject or fail closed when the underlying log does not verify cleanly.
- REQ-005-05: Update `docs/spec/data-model.md` and `docs/spec/behaviors.md` for the
  checkpoint payload behavior.

## Acceptance criteria

- TC-005-01 passes.
- TC-005-02 passes.
- TC-005-03 passes.
- TC-005-04 passes.
- TC-005-05 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 004, because the payload shape and canonical signing bytes must come from the ADR.

## Notes

This task should not introduce key loading, signatures, CLI flags, IPC ops, or checkpoint files.
Keep the change small enough that the canonical checkpoint bytes can be reviewed directly.
