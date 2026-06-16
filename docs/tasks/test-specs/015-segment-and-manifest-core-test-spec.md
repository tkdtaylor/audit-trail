# Test spec: 015 - segment and manifest core

## Scope

Implement the segment data model, manifest format, rotation trigger logic, and the rotation
operation itself — without touching the Verify() walk or the runtime surface. All writes
(rotation included) must go through the existing `Chain` mutex. This is a unit-test-only task;
no CLI flags or IPC ops are added here.

## Requirements traced

- REQ-015-01: A `Segment` data model and a `SegmentManifest` data model are defined matching
  the ADR-005 schema; both are persisted to disk with mode `0600`.
- REQ-015-02: The segment manifest is written atomically (write-then-rename) to prevent a
  partial manifest from being read by a concurrent Verify() call.
- REQ-015-03: `Chain.Rotate()` (or the ADR-named equivalent) acquires `c.mu` before renaming
  the active log segment, writing the manifest, and opening the new segment file; it releases
  the lock only after all file operations succeed or fail cleanly.
- REQ-015-04: The rotation trigger (size-based, count-based, or checkpoint-triggered per
  ADR-005) is enforced: rotation is declined when the log does not meet the trigger threshold
  and proceeds when it does.
- REQ-015-05: After rotation, `Chain.Emit()` continues appending to the new active segment
  with `prev_hash` equal to the last hash of the rotated-out segment, preserving chain
  continuity at the seam.
- REQ-015-06: The rotated-out segment receives a signed checkpoint using `CreateSignedCheckpoint`
  from the existing checkpoint machinery; the checkpoint is written alongside the segment file
  or at the path specified by ADR-005.
- REQ-015-07: A single-segment log (no rotation has ever occurred) must be the degenerate case:
  `Chain` state, `Emit`, and `loadState` behavior are unchanged from before this task, as
  observed by the existing test suite.
- REQ-015-08: Update `docs/spec/data-model.md` with the segment and manifest schemas.

## Test cases

### TC-015-01 - segment and manifest models round-trip to disk

- Command: unit test that writes a `SegmentManifest` to a temp directory and reads it back.
- Expected:
  - All manifest fields (segment filenames, seq ranges, root hashes, issued timestamps) survive
    the write/read round-trip without mutation.
  - File mode on disk is `0600`.

### TC-015-02 - manifest write is atomic

- Command: unit test that simulates a mid-write crash by checking that no partial manifest file
  is ever visible to a concurrent reader (use a temp-file-then-rename write strategy and verify
  the swap is atomic from the reader's perspective).
- Expected:
  - Before the rename completes, the old manifest (or no manifest) is visible.
  - After the rename, only the complete new manifest is visible.
  - No partial file is left on disk on simulated failure before rename.

### TC-015-03 - Rotate() acquires the mutex and updates chain state

- Command: unit test that calls `Rotate()` on a chain with N events and then emits one more
  event.
- Expected:
  - The new segment file is created under the path named by ADR-005.
  - `seq` of the new emit equals N (continues from where rotation stopped).
  - The new record's `prev_hash` equals the `hash` of the last record in the rotated-out
    segment.
  - The rotated-out segment file is no longer the active file.

### TC-015-04 - rotation trigger threshold is enforced

- Command: unit test that attempts rotation below the threshold and at/above the threshold.
- Expected:
  - Below threshold: `Rotate()` returns a sentinel error or no-op without touching any file.
  - At or above threshold: rotation proceeds and the manifest is updated.
  - The threshold is the value specified by ADR-005 (operator-configurable or documented
    default); the test uses a small value to keep fixture size manageable.

### TC-015-05 - chain continuity is preserved at the seam

- Command: unit test that emits M events, rotates, then emits K more events, then loads the
  resulting chain state from the new active segment.
- Expected:
  - The first record in the new segment has `prev_hash` equal to the last `hash` in the
    rotated-out segment.
  - `loadState()` applied to only the new active segment produces `seq = M + K` (continues
    the global count) and `prevHash` equal to the last emitted hash.

### TC-015-06 - rotated-out segment receives a signed checkpoint

- Command: unit test that calls `Rotate()` with a test signing key and inspects the resulting
  checkpoint file.
- Expected:
  - A checkpoint file exists adjacent to the rotated-out segment at the ADR-005 path.
  - The checkpoint's `tree_size`, `last_seq`, and `root_hash` match the rotated-out segment's
    verified state.
  - `VerifySignedCheckpoint` succeeds on the checkpoint using the matching test public key.

### TC-015-07 - single-segment degenerate case is unchanged

- Command: run the existing test suite without any rotation having occurred.
- Expected:
  - All pre-existing tests pass without modification.
  - A chain that has never been rotated behaves identically to a pre-rotation chain.
  - `make check` exits 0.

### TC-015-08 - data-model spec is updated

- Command: inspect `docs/spec/data-model.md`.
- Expected:
  - Segment and manifest schemas are documented with field names, types, and sources.
  - The seam-continuity invariant (`prev_hash` of first record in N+1 equals last `hash` in N)
    is stated explicitly.
