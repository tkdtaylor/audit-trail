# Task 013 - anchoring fitness and fixtures

## Goal

Add durable regression fixtures and named fitness functions to ensure that Rekor receipt validation and tamper detection remain stable and correct.

Design decision: [ADR-004](../../architecture/decisions/004-witness-anchoring.md).

## Requirements

- REQ-013-01: Add stable test data fixtures under `testdata/checkpoints/` containing a Rekor public key, a signed checkpoint, and a valid Rekor receipt.
- REQ-013-02: Add a named fitness target that proves receipt verification succeeds offline using the fixtures.
- REQ-013-03: Add a named fitness target that proves altered receipts, checkpoints, or public keys fail verification.
- REQ-013-04: Wire the anchoring fitness targets into `make fitness`.
- REQ-013-05: Update `docs/spec/fitness-functions.md` to document the new fitness rules.

## Acceptance criteria

- TC-013-01: Offline verification of the committed fixture receipt and checkpoint succeeds.
- TC-013-02: Tampered receipt or checkpoint payload bytes successfully fail validation.
- TC-013-03: `make fitness` runs all checks and succeeds.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 012, because the fitness functions should exercise the final runtime verification logic.
