# Test spec: 007 - checkpoint runtime surface

## Scope

Expose signed checkpoint creation and verification through the ADR-approved CLI and IPC
surfaces while preserving existing v1 operation shapes.

## Requirements traced

- REQ-007-01: CLI creates a signed checkpoint.
- REQ-007-02: CLI verifies a signed checkpoint.
- REQ-007-03: IPC supports ADR-approved checkpoint operations with shared error shape.
- REQ-007-04: existing IPC operations remain unchanged.
- REQ-007-05: interface and behavior specs document the runtime-visible checkpoint surface.

## Test cases

### TC-007-01 - CLI creates a signed checkpoint

- Command: run the checkpoint-create CLI path against a temp logfile and test signing key.
- Expected:
  - exits 0
  - prints or writes a signed checkpoint in the ADR-approved format
  - checkpoint verifies with the matching public key

### TC-007-02 - CLI verifies valid and invalid checkpoints

- Command: run the checkpoint-verify CLI path for a valid checkpoint and a tampered
  checkpoint.
- Expected:
  - valid checkpoint exits 0 and reports valid
  - tampered checkpoint exits non-zero and reports invalid

### TC-007-03 - IPC creates and verifies checkpoints

- Command: run `audit-trail serve` against a temp socket/logfile and send the ADR-approved
  checkpoint requests over the Unix socket.
- Expected:
  - checkpoint create response succeeds
  - checkpoint verify response succeeds for valid input
  - invalid input uses `{error:{code,message,retryable}}`

### TC-007-04 - existing IPC ops remain unchanged

- Requests:
  - `{"op":"emit","event":{...}}`
  - `{"op":"verify"}`
  - `{"op":"ping"}`
  - malformed JSON
  - unknown op
- Expected:
  - responses match the existing spec except for any new checkpoint ops
  - `emit` and `verify` response shapes are unchanged

### TC-007-05 - runtime documentation is updated

- Command: inspect `docs/spec/interfaces.md` and `docs/spec/behaviors.md`.
- Expected:
  - new CLI and IPC surfaces are documented
  - shared error shape is documented
  - docs stay present-tense
