# Test spec: 004 - design signed checkpoints

## Scope

Create the signed-checkpoints ADR required before implementing the first high-risk roadmap
item. This is a design task, so the checks are documentation and traceability checks rather
than Go unit tests.

## Requirements traced

- REQ-004-01: ADR exists in `docs/architecture/decisions/`.
- REQ-004-02: ADR defines payload fields, canonical bytes, signature algorithm, key material,
  and verification rules.
- REQ-004-03: ADR explains how checkpoints relate to the current linear hash chain and RFC
  6962 signed-tree-head terminology.
- REQ-004-04: ADR defines additive CLI and IPC surfaces without changing existing `emit` and
  `verify` response shapes.
- REQ-004-05: ADR identifies integrity risks and required evidence for implementation tasks.

## Test cases

### TC-004-01 - ADR exists and is linked

- Command: inspect `docs/architecture/decisions/`.
- Expected:
  - a new signed-checkpoints ADR exists
  - later task files can link to it
  - ADR status is appropriate for implementation work

### TC-004-02 - checkpoint bytes are specified

- Command: read the ADR payload section.
- Expected:
  - payload fields are named
  - canonical byte input is specified
  - the signed bytes exclude the signature itself
  - integer and string encodings are unambiguous

### TC-004-03 - key and signature rules are specified

- Command: read the ADR signing section.
- Expected:
  - signature algorithm is named
  - key formats are named
  - malformed, missing, and wrong-key behavior fails closed
  - no third-party dependency is required

### TC-004-04 - runtime surface preserves v1 verbs

- Command: compare the ADR against `docs/CONTRACT.md` and `docs/spec/interfaces.md`.
- Expected:
  - existing `emit` and `verify` result shapes are unchanged
  - any new CLI or IPC operations are additive
  - shared IPC error shape remains `{error:{code,message,retryable}}`

### TC-004-05 - risk and evidence are explicit

- Command: read the ADR consequences and verification sections.
- Expected:
  - integrity risks are listed
  - required live-path evidence for runtime-visible tasks is listed
  - security-review expectations for core signing work are listed
