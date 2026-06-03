# Task 004 - design signed checkpoints

## Goal

Write the signed-checkpoints ADR before implementation so the integrity-core shape is explicit:
what checkpoint bytes mean, what gets signed, how keys are configured, and which runtime
surfaces expose the feature without changing the frozen v1 `emit` / `verify` contract.

Design decision: [ADR-003](../../architecture/decisions/003-signed-checkpoints.md).

## Requirements

- REQ-004-01: Add an ADR for signed checkpoints under
  `docs/architecture/decisions/`.
- REQ-004-02: Define the checkpoint payload fields, canonical byte input, signature algorithm,
  key material format, and verification rules.
- REQ-004-03: State how checkpoints relate to the current linear hash chain and RFC 6962
  signed-tree-head terminology.
- REQ-004-04: State the CLI and IPC surface for checkpoint creation and checkpoint
  verification, keeping existing `emit` and `verify` response shapes unchanged.
- REQ-004-05: Identify integrity risks and required verification evidence for later
  implementation tasks.

## Acceptance criteria

- TC-004-01 passes.
- TC-004-02 passes.
- TC-004-03 passes.
- TC-004-04 passes.
- TC-004-05 passes.

## Dependencies

None.

## Notes

Do not implement checkpoint code in this task. This task exists because signed checkpoints are
the first high-risk roadmap item and need a design decision before touching `chain.go` or
canonicalization-adjacent code.
