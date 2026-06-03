# Test spec: 008 - checkpoint fitness and fixtures

## Scope

Add deterministic signed-checkpoint fixtures and fitness targets that guard checkpoint byte
stability and tamper-detection semantics.

## Requirements traced

- REQ-008-01: stable fixtures exist for a known log and test key pair.
- REQ-008-02: named fitness target proves checkpoint payload byte stability.
- REQ-008-03: named fitness target proves altered checkpoint content or signatures fail.
- REQ-008-04: checkpoint fitness checks are wired into `make fitness`.
- REQ-008-05: fitness spec and coverage tracker describe the new checks.

## Test cases

### TC-008-01 - deterministic fixtures verify

- Command: run the fixture verification test or command named by the implementation.
- Expected:
  - known fixture checkpoint verifies with the fixture public key
  - fixture log verifies as intact

### TC-008-02 - payload stability fitness target passes

- Command: `make fitness-checkpoint-stability`
- Expected:
  - exits 0 on the current tree
  - fails if canonical checkpoint payload bytes change from the fixture expectation

### TC-008-03 - checkpoint tamper fitness target passes

- Command: `make fitness-checkpoint-tamper-detection`
- Expected:
  - exits 0 on the current tree
  - proves altered signed content fails verification
  - proves altered signature bytes fail verification

### TC-008-04 - umbrella fitness includes checkpoint checks

- Command: `make fitness`
- Expected:
  - runs both checkpoint fitness targets
  - prints the final success line after all checks pass

### TC-008-05 - docs and coverage tracker are updated

- Command: inspect `docs/spec/fitness-functions.md` and
  `docs/tasks/test-specs/coverage-tracker.md`.
- Expected:
  - checkpoint fitness functions are documented with command names
  - task 008 coverage row records the implemented checks after completion
