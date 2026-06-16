# Task 016 - cross-segment Verify()

## Goal

Extend `Verify()` to walk multiple segment files from disk in manifest order, detect tampers at
or across any segment boundary, and preserve the existing `VerifyResult` shape so the v1
contract is unchanged. A single-segment log must remain the degenerate case with identical
behavior to today.

Design decision: [ADR-005](../../architecture/decisions/005-log-rotation.md).

## Requirements

- REQ-016-01: `Verify()` loads the segment manifest from disk and walks all segment files in
  manifest order without using in-memory chain state.
- REQ-016-02: `Verify()` checks cross-segment hash continuity: the `prev_hash` of the first
  record in segment N+1 must equal the `hash` of the last record in segment N.
- REQ-016-03: A byte-level change to any record in any segment is detected and reported with
  `tamper_detected_at` pointing to the affected entry's seq.
- REQ-016-04: A segment listed in the manifest but missing from disk causes `Verify()` to
  return `valid:false` with a message naming the missing segment.
- REQ-016-05: A reordered segment (manifest order swapped) causes `Verify()` to return
  `valid:false` at the boundary where the hash link breaks.
- REQ-016-06: A single-segment log produces results identical to today's single-file Verify().
- REQ-016-07: The `VerifyResult` struct shape and v1 contract remain unchanged.
- REQ-016-08: Update `docs/spec/behaviors.md` to document the extended Verify() behavior.

## Acceptance criteria

- TC-016-01 passes.
- TC-016-02 passes.
- TC-016-03 passes.
- TC-016-04 passes.
- TC-016-05 passes.
- TC-016-06 passes.
- TC-016-07 passes.
- TC-016-08 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 015, because this task requires the segment manifest written by `Rotate()` to exist
  on disk before the multi-segment walk can be implemented and tested.

## Notes

This is the highest-risk task in the chunk. The cross-segment seam (TC-016-02, TC-016-03) is
exactly where tamper detection can silently break if `prev_hash` linkage is not checked between
files. TC-016-07 ensures Verify() reads from disk, not memory — this is the invariant that
makes the forensic guarantee hold. Request a security-focused review from the security-auditor
agent before marking this task complete.

Do not add CLI flags or IPC ops in this task. The runtime surface is task 017.
