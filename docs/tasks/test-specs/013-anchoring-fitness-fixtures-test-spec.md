# Test spec: 013 - anchoring fitness and fixtures

## Scope

Add durable regression fixtures and named fitness functions to ensure that Rekor receipt validation and tamper detection remain stable and correct.

## Requirements traced

- REQ-013-01: Add stable test data fixtures under `testdata/checkpoints/` containing a Rekor public key, a signed checkpoint, and a valid Rekor receipt.
- REQ-013-02: Add a named fitness target that proves receipt verification succeeds offline using the fixtures.
- REQ-013-03: Add a named fitness target that proves altered receipts, checkpoints, or public keys fail verification.
- REQ-013-04: Wire the anchoring fitness targets into `make fitness`.
- REQ-013-05: Update `docs/spec/fitness-functions.md` to document the new fitness rules.

## Test cases

### TC-013-01 - offline verification of fixtures succeeds

- Command: run the fixture verification test or command named by the implementation.
- Expected:
  - known fixture receipt and checkpoint verify successfully using the fixture Rekor public key and operator public key offline.

### TC-013-02 - tampered assets fail offline verification

- Command: run the tamper detection test.
- Expected:
  - altered receipt bytes (e.g. signature, integratedTime, logIndex, logID) fail offline verification.
  - altered checkpoint bytes fail offline verification.
  - altered operator public key or Rekor public key fails offline verification.

### TC-013-03 - anchoring fitness targets are wired into make fitness

- Command: `make fitness`
- Expected:
  - runs both anchoring fitness targets: `make fitness-anchor-stability` and `make fitness-anchor-tamper-detection`.
  - exits 0 and prints the final success line after all checks pass.

### TC-013-04 - docs and coverage tracker are updated

- Command: inspect `docs/spec/fitness-functions.md` and `docs/tasks/test-specs/coverage-tracker.md`.
- Expected:
  - Rekor anchoring fitness functions are documented with command names.
  - task 013 coverage row records the implemented checks.
