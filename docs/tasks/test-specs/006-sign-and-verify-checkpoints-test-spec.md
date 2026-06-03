# Test spec: 006 - sign and verify checkpoints

## Scope

Add standard-library signing and verification over checkpoint payload bytes from task 005.

## Requirements traced

- REQ-006-01: signature algorithm uses only the Go standard library.
- REQ-006-02: signing and verification keys load and validate in the ADR format.
- REQ-006-03: signatures cover only the canonical checkpoint payload bytes.
- REQ-006-04: malformed checkpoints, keys, payloads, and signatures fail closed.
- REQ-006-05: configuration, data-model, and behavior specs describe signed checkpoints.

## Test cases

### TC-006-01 - valid checkpoint signature verifies

- Setup: generate or load a deterministic test key pair and build a checkpoint payload.
- Command: sign the payload, then verify with the matching public key.
- Expected:
  - verification succeeds
  - signed checkpoint contains the ADR-approved signature fields

### TC-006-02 - altered payload fails verification

- Setup: sign a checkpoint payload.
- Command: change a signed payload field and verify.
- Expected:
  - verification fails
  - failure message identifies invalid signature or altered content

### TC-006-03 - altered signature or wrong key fails verification

- Setup: sign a checkpoint payload.
- Command: verify with a modified signature and with a different public key.
- Expected:
  - both verifications fail closed
  - no panic occurs for malformed signature bytes

### TC-006-04 - malformed key material fails closed

- Setup: provide malformed, missing, short, or wrong-type key material.
- Command: load signing and verification keys.
- Expected:
  - key loading returns clear errors
  - no default or empty key is accepted

### TC-006-05 - specs document key configuration and behavior

- Command: inspect `docs/spec/configuration.md`, `docs/spec/data-model.md`, and
  `docs/spec/behaviors.md`.
- Expected:
  - signing and verification key configuration is documented
  - signed checkpoint structure is documented
  - verification failure behavior is documented
