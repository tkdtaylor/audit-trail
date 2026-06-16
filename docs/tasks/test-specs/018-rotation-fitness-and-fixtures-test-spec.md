# Test spec: 018 - rotation fitness and fixtures

## Scope

Add deterministic multi-segment log fixtures and named fitness functions that guard cross-segment
tamper detection, seam-continuity stability, and manifest integrity. Wire the new targets into
`make fitness`. These fixtures are the regression anchor for the highest-risk invariants in the
rotation chunk.

## Requirements traced

- REQ-018-01: Add deterministic multi-segment fixtures under `testdata/segments/` (or the
  ADR-005-specified path): at least two complete rotated-out segment files, their associated
  signed checkpoints, and the manifest file that describes them, plus an active segment with
  additional records.
- REQ-018-02: Add a named fitness target `make fitness-rotation-stability` that proves
  `Verify()` over the committed multi-segment fixtures returns `{valid:true,...}` and that the
  first record in each non-initial segment's `prev_hash` matches the last `hash` in the
  preceding segment.
- REQ-018-03: Add a named fitness target `make fitness-rotation-tamper-detection` that proves
  each of the following modifications causes `Verify()` to return `valid:false`: (a) one byte
  changed in any record in a rotated-out segment; (b) the `prev_hash` of the first record in
  segment N+1 modified to break the seam; (c) a segment file removed from disk while remaining
  in the manifest; (d) two segment entries swapped in the manifest.
- REQ-018-04: Wire both new fitness targets into `make fitness` so they run alongside all
  existing FF-001 through FF-009 checks.
- REQ-018-05: Add FF-010 (rotation seam tamper detection) and FF-011 (cross-segment chain
  stability) to `docs/spec/fitness-functions.md`.
- REQ-018-06: Update `docs/tasks/test-specs/coverage-tracker.md` with the task 018 row.

## Test cases

### TC-018-01 - committed fixtures verify intact

- Command: `make fitness-rotation-stability`
- Expected:
  - Exits 0.
  - `Verify()` applied to the committed multi-segment fixtures returns
    `{valid:true, tamper_detected_at:null, message:"chain intact"}`.
  - The seam-continuity check (prev_hash of segment N+1 first record == hash of segment N last
    record) passes for every segment boundary in the fixtures.

### TC-018-02 - tamper cases fail the fitness target

- Command: `make fitness-rotation-tamper-detection`
- Expected:
  - Exits 0 (the test runner succeeds because all tamper cases correctly return valid:false).
  - Sub-case (a): one-byte edit in a rotated-out segment causes `valid:false` with
    `tamper_detected_at` pointing to that segment's affected seq.
  - Sub-case (b): modified `prev_hash` at the seam between segment N and segment N+1 causes
    `valid:false` with `tamper_detected_at` pointing to the first record of segment N+1.
  - Sub-case (c): removed segment causes `valid:false` with a message naming the missing file.
  - Sub-case (d): swapped manifest entries causes `valid:false` at the broken boundary.

### TC-018-03 - rotation fitness targets are wired into make fitness

- Command: `make fitness`
- Expected:
  - Runs `make fitness-rotation-stability` and `make fitness-rotation-tamper-detection` in
    addition to all existing FF-001 through FF-009 checks.
  - Exits 0 and prints the final success line after all checks pass.
  - No existing fitness target is removed or broken.

### TC-018-04 - fitness-functions spec and coverage tracker are updated

- Command: inspect `docs/spec/fitness-functions.md` and
  `docs/tasks/test-specs/coverage-tracker.md`.
- Expected:
  - FF-010 (rotation seam tamper detection) is documented with check command
    `make fitness-rotation-tamper-detection`.
  - FF-011 (cross-segment chain stability) is documented with check command
    `make fitness-rotation-stability`.
  - Task 018 coverage row is present with status ❌ Not started (to be updated by the
    spec-verifier after implementation).
