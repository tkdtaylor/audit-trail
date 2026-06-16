# Test spec: 016 - cross-segment Verify()

## Scope

Extend `Verify()` to walk multiple segment files from disk in manifest order, detect a tamper
at or across any segment boundary, and produce the same result shape as today's single-file
Verify(). The single-file case must remain the degenerate 1-segment path. This task contains
the load-bearing security work for rotation: the seam is the one place tamper detection can
silently break.

## Requirements traced

- REQ-016-01: `Verify()` loads the segment manifest from disk and walks all segment files in
  manifest order; it does not use in-memory chain state.
- REQ-016-02: `Verify()` verifies cross-segment hash continuity: the `prev_hash` of the first
  record in segment N+1 must equal the `hash` of the last record in segment N; a mismatch
  reports tamper at the first record of segment N+1.
- REQ-016-03: A byte-level change to any record in any segment (not just the active one) is
  detected and reported with `tamper_detected_at` pointing to the affected entry's seq.
- REQ-016-04: A dropped segment (removed from disk but still referenced in the manifest) causes
  Verify() to return `valid:false` with a message naming the missing segment.
- REQ-016-05: A reordered segment (manifest lists segments in wrong order) causes Verify() to
  return `valid:false` at the boundary where the hash link breaks.
- REQ-016-06: A single-segment log (no manifest, or manifest with one entry) produces results
  identical to today's single-file Verify(), including the `{valid:true, tamper_detected_at:null,
  message:"chain intact"}` success shape.
- REQ-016-07: The `VerifyResult` struct shape and the v1 `emit`/`verify` contract are unchanged;
  no new fields are added to the response without a contracts bump.
- REQ-016-08: Update `docs/spec/behaviors.md` to document the extended Verify() behavior.

## Test cases

### TC-016-01 - multi-segment intact chain verifies

- Command: unit test that emits M events, rotates, emits K more events, then calls Verify().
- Expected:
  - `Verify()` returns `{valid:true, tamper_detected_at:null, message:"chain intact"}`.
  - The test uses at least two complete segments plus an active segment (three total).

### TC-016-02 - tamper in an earlier segment is detected

- Command: unit test that emits into two segments, directly edits a record byte in the first
  (rotated-out) segment file, then calls Verify().
- Expected:
  - `Verify()` returns `valid:false` and `tamper_detected_at` points to the seq of the edited
    record in segment 0.
  - Message contains "content hash mismatch (tampered)" or equivalent.

### TC-016-03 - tamper at the cross-segment seam is detected

- Command: unit test that modifies the `prev_hash` of the first record in segment N+1 so it no
  longer matches the last hash of segment N.
- Expected:
  - `Verify()` returns `valid:false` and `tamper_detected_at` points to the seq of the first
    record in segment N+1.
  - Message contains "prev_hash link broken" or equivalent.

### TC-016-04 - dropped segment is detected

- Command: unit test that removes a segment file that is still listed in the manifest.
- Expected:
  - `Verify()` returns `valid:false` with a message naming the missing segment file.
  - `tamper_detected_at` is set to the seq of the first record that would have been in the
    dropped segment, or to nil with a clear error message — whichever the ADR specifies.

### TC-016-05 - reordered segments are detected

- Command: unit test that swaps the order of two segment entries in the manifest.
- Expected:
  - `Verify()` returns `valid:false` at the boundary where the hash link breaks.

### TC-016-06 - single-segment degenerate case is identical to v1

- Command: run the existing Verify() tests against a chain that has never been rotated (no
  manifest, or manifest with one segment).
- Expected:
  - All pre-existing Verify() tests pass unchanged.
  - Result shape is `{valid, tamper_detected_at, message}` — no new fields.
  - `make check` exits 0.

### TC-016-07 - Verify() reads from disk, not memory

- Command: unit test that (a) emits events into two segments, (b) directly corrupts a segment
  file on disk after the Chain is loaded, then (c) calls Verify() on the Chain without
  reloading it.
- Expected:
  - Verify() detects the corruption from the on-disk read, not from in-memory state.
  - The in-memory Chain still reports the pre-corruption prevHash; Verify() disagrees.

### TC-016-08 - behaviors spec is updated

- Command: inspect `docs/spec/behaviors.md`.
- Expected:
  - B-002 (or a new B-NNN) describes the multi-segment Verify() walk.
  - The cross-segment seam check and dropped-segment detection are documented.
  - Docs stay present-tense.
