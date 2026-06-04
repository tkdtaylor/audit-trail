# Task 009 - design witness anchoring

## Goal

Design the Architecture Decision Record (ADR-004) and task framework for anchoring signed checkpoints to an external transparency log (Rekor), detailing the payload schemas, inclusion proofs, verification rules, CLI/IPC interfaces, and security threat mitigations.

Design decision: [ADR-004](../../architecture/decisions/004-witness-anchoring.md).

## Requirements

- REQ-009-01: Write ADR-004 specifying the Rekor entry schema (`hashedrekord`), inclusion proof structure (`RekorReceipt`), and online/offline verification logic.
- REQ-009-02: Ensure ADR-004 specifies safety mitigations against Server-Side Request Forgery (SSRF) and key-path injection over the IPC surface.
- REQ-009-03: Create the test-spec document defining verification test cases for the design.
- REQ-009-04: Update `docs/tasks/test-specs/coverage-tracker.md` to reflect Task 009's status.

## Acceptance criteria

- TC-009-01 passes: ADR-004 exists and is complete.
- TC-009-02 passes: Safety mitigations are clearly documented in the ADR.
- TC-009-03 passes: The test-spec file `docs/tasks/test-specs/009-design-witness-anchoring-test-spec.md` is complete.
- TC-009-04 passes: `coverage-tracker.md` maps Task 009 to its test-spec.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 008, because anchoring requires stable and fully-tested signed checkpoints.

## Notes

This is a design-only task. No Go source files are modified during this task.
