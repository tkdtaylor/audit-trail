# Task 015 - segment and manifest core

## Goal

Implement the segment data model, manifest format, rotation trigger logic, and the
`Chain.Rotate()` operation, with all writes going through the existing `Chain` mutex.
Chain continuity at the seam is enforced so that `prev_hash` of the first record in
segment N+1 equals the last `hash` of segment N. The single-file degenerate case must
remain unchanged.

Design decision: [ADR-005](../../architecture/decisions/005-log-rotation.md).

## Requirements

- REQ-015-01: Define a `Segment` data model and a `SegmentManifest` data model matching the
  ADR-005 schema; write both to disk with mode `0600`.
- REQ-015-02: Write the manifest atomically (write to a temp file, then rename) to prevent
  partial reads by a concurrent Verify() call.
- REQ-015-03: `Chain.Rotate()` acquires `c.mu` before renaming the active log segment, writing
  the manifest, and opening the new segment file; the mutex is held until all file operations
  complete or fail cleanly.
- REQ-015-04: Enforce the ADR-005 rotation trigger: decline rotation when below threshold,
  proceed when at or above threshold.
- REQ-015-05: After rotation, `Chain.Emit()` appends to the new active segment with
  `prev_hash` equal to the last hash of the rotated-out segment.
- REQ-015-06: The rotated-out segment receives a signed checkpoint using the existing
  `CreateSignedCheckpoint` machinery, written at the ADR-005-specified path.
- REQ-015-07: A single-segment log must be the degenerate case — existing behavior and tests
  are unchanged.
- REQ-015-08: Update `docs/spec/data-model.md` with the segment and manifest schemas.

## Acceptance criteria

- TC-015-01 passes.
- TC-015-02 passes.
- TC-015-03 passes.
- TC-015-04 passes.
- TC-015-05 passes.
- TC-015-06 passes.
- TC-015-07 passes.
- TC-015-08 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 014, because the segment model, manifest schema, trigger choice, and continuity rule
  all come from ADR-005.

## Notes

Do not add CLI flags, IPC ops, or Verify() multi-segment walk in this task. Keep the scope to
the data model, rotation trigger, and the rotation operation itself. This task is unit-test
only; the runtime surface and cross-segment verify come in tasks 017 and 016 respectively.

Security note: `Rotate()` and the manifest write touch integrity-critical paths. Request a
security-focused review from the security-auditor agent before marking this task complete.
