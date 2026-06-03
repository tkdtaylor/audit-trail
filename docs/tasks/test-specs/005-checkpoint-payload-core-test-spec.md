# Test spec: 005 - checkpoint payload core

## Scope

Implement deterministic checkpoint payload creation from the on-disk chain head, without
signatures or runtime command surfaces.

## Requirements traced

- REQ-005-01: checkpoint data model matches the ADR.
- REQ-005-02: payloads are built from on-disk chain state.
- REQ-005-03: canonical checkpoint payload bytes are byte-stable.
- REQ-005-04: checkpoint creation fails closed when the log does not verify.
- REQ-005-05: data-model and behavior specs describe the payload behavior.

## Test cases

### TC-005-01 - payload reflects an intact chain head

- Setup: emit two records into a temp logfile.
- Command: call the checkpoint payload builder.
- Expected:
  - payload tree size or record count matches the log length
  - payload head hash matches the last record hash
  - payload timestamp or creation metadata matches the ADR rules

### TC-005-02 - payload is built from disk, not stale memory

- Setup: create a chain, emit records, then tamper with the logfile on disk.
- Command: call the checkpoint payload builder.
- Expected:
  - builder detects the broken log through disk-backed verification
  - no checkpoint payload is returned

### TC-005-03 - canonical payload bytes are stable

- Setup: construct equivalent checkpoint payloads with different map insertion order where
  applicable.
- Command: canonicalize each payload for signing.
- Expected:
  - canonical byte outputs are identical
  - output matches an expected fixture string or hex digest

### TC-005-04 - malformed or empty log behavior matches ADR

- Setup: test empty log and malformed log cases named by the ADR.
- Command: call the checkpoint payload builder.
- Expected:
  - empty log behavior matches the ADR
  - malformed log fails closed

### TC-005-05 - specs are present-tense and updated

- Command: inspect `docs/spec/data-model.md` and `docs/spec/behaviors.md`.
- Expected:
  - checkpoint payload fields and creation behavior are documented
  - docs do not use future-tense roadmap prose
