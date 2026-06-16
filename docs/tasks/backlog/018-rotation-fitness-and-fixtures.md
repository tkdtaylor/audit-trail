# Task 018 - rotation fitness and fixtures

## Goal

Add deterministic multi-segment log fixtures and named fitness functions (FF-010, FF-011) that
guard cross-segment tamper detection and seam-continuity stability across code changes. Wire
both into `make fitness` alongside the existing FF-001 through FF-009 checks.

Design decision: [ADR-005](../../architecture/decisions/005-log-rotation.md).

## Requirements

- REQ-018-01: Add deterministic multi-segment fixtures under `testdata/segments/` (or the
  ADR-005-specified path): at least two rotated-out segment files with signed checkpoints,
  a manifest file, and an active segment.
- REQ-018-02: Add `make fitness-rotation-stability` proving `Verify()` over the committed
  fixtures returns `{valid:true,...}` and that every cross-segment seam's `prev_hash` link
  holds.
- REQ-018-03: Add `make fitness-rotation-tamper-detection` proving that each of the following
  causes `Verify()` to return `valid:false`: a one-byte edit in any rotated-out segment, a
  broken seam `prev_hash`, a dropped segment file, and swapped manifest entries.
- REQ-018-04: Wire both fitness targets into `make fitness` without removing or breaking any
  existing target.
- REQ-018-05: Add FF-010 and FF-011 to `docs/spec/fitness-functions.md`.
- REQ-018-06: Update `docs/tasks/test-specs/coverage-tracker.md` with the task 018 row.

## Acceptance criteria

- TC-018-01 passes.
- TC-018-02 passes.
- TC-018-03 passes.
- TC-018-04 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 017, because the fitness functions exercise the final rotation and verification
  runtime logic that must already be implemented and live-path-verified before fixture
  regression coverage is meaningful.

## Notes

The committed fixtures are the long-term regression anchor. Generate them once from a
known-good run of the implementation (deterministic key + deterministic log content) and
commit them to `testdata/segments/`. Future code changes that alter seam-continuity behavior
or Verify() disk reads will be caught by these targets. Do not regenerate the fixtures as part
of normal test runs — they must be stable committed bytes.
