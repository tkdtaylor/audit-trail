# Test spec: 009 - design witness anchoring

## Scope

Create the witness/Rekor anchoring ADR required before implementing the next roadmap item. This is a design task, so the checks are documentation and traceability checks rather than Go unit tests.

## Requirements traced

- REQ-009-01: ADR exists in `docs/architecture/decisions/`.
- REQ-009-02: ADR defines Rekor `hashedrekord` API schema, inclusion proof structure (`RekorReceipt`), and offline/online verification rules.
- REQ-009-03: ADR defines safety mitigations against Server-Side Request Forgery (SSRF) and key-path injection over the IPC surface.
- REQ-009-04: Update `docs/tasks/test-specs/coverage-tracker.md` to map Task 009 to its test-spec.

## Test cases

### TC-009-01 - ADR exists and is linked

- Command: inspect `docs/architecture/decisions/`.
- Expected:
  - `004-witness-anchoring.md` exists.
  - The ADR status is Proposed or Accepted.

### TC-009-02 - Rekor schema and inclusion proof are specified

- Command: read the ADR entry schema and receipt sections.
- Expected:
  - The Rekor `hashedrekord` JSON payload structure is specified.
  - The local `RekorReceipt` fields (including `log_id`, `log_index`, `integrated_time`, `signed_entry_timestamp`, `entry_id`) are specified.

### TC-009-03 - Verification rules are specified

- Command: read the ADR verification section.
- Expected:
  - Both offline (SET verification using Rekor public key) and online (REST API fetch) verification modes are defined.
  - Malformed key, signature, and network failures fail closed.

### TC-009-04 - Security and IPC mitigations are specified

- Command: read the ADR security and runtime sections.
- Expected:
  - SSRF is mitigated by requiring the daemon to use configured startup URLs.
  - Key path injection is mitigated by loading keys only from daemon startup paths.
  - Emitter non-blocking is preserved (network out of the write path).

### TC-009-05 - Coverage tracker is updated

- Command: inspect `docs/tasks/test-specs/coverage-tracker.md`.
- Expected:
  - Task 009 is listed with its status and spec file.
