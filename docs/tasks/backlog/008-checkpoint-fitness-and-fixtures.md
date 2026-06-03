# Task 008 - checkpoint fitness and fixtures

## Goal

Add durable regression fixtures and fitness checks for signed checkpoints so future anchoring,
rotation, and backend work cannot accidentally change checkpoint bytes or signature semantics.

Design decision: [ADR-003](../../architecture/decisions/003-signed-checkpoints.md).

## Requirements

- REQ-008-01: Add stable signed-checkpoint fixtures for a small known log and key pair.
- REQ-008-02: Add a named fitness target that proves checkpoint payload bytes are stable.
- REQ-008-03: Add a named fitness target that proves altered checkpoint content or signatures
  fail verification.
- REQ-008-04: Wire the checkpoint fitness checks into `make fitness`.
- REQ-008-05: Update `docs/spec/fitness-functions.md` and the coverage tracker with the
  implemented checkpoint checks.

## Acceptance criteria

- TC-008-01 passes.
- TC-008-02 passes.
- TC-008-03 passes.
- TC-008-04 passes.
- TC-008-05 passes.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 007, because the fitness checks should exercise the final runtime-visible checkpoint
  paths where practical.

## Notes

The fixtures must be deterministic and safe to commit. Do not use production key material.
