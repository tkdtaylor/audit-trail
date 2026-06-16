# Test spec: 014 - design log rotation

## Scope

Create the log-rotation ADR (ADR-005) required before implementing the next roadmap item. This
is a design task; the checks are documentation and traceability checks rather than Go unit
tests.

## Requirements traced

- REQ-014-01: ADR-005 exists in `docs/architecture/decisions/` and its status is appropriate
  for implementation work.
- REQ-014-02: ADR-005 resolves the segment boundary trigger fork — size-based, event-count-based,
  or explicit checkpoint-triggered rotation — and states which is chosen and why.
- REQ-014-03: ADR-005 specifies how chain continuity is preserved across the rotation seam:
  the `prev_hash` of the first record in segment N+1 must chain from the last hash of segment N,
  and the design must explain how this link is enforced and verified.
- REQ-014-04: ADR-005 specifies how `Verify()` walks multiple segment files from disk, keeps
  the single-file case as the degenerate 1-segment case, and retains the v1 `emit`/`verify`
  contract without a contracts bump.
- REQ-014-05: ADR-005 specifies the segment manifest/enumeration scheme and how that
  enumeration is itself tamper-evident (dropped or reordered segments must be detectable).
- REQ-014-06: ADR-005 states that rotation is a write that goes through the existing `Chain`
  mutex (single-writer invariant), and identifies what runtime surface triggers rotation.
- REQ-014-07: ADR-005 states that each rotated-out segment receives a signed checkpoint
  (re-anchoring at boundaries), specifying how the existing checkpoint machinery from ADR-003
  is reused.
- REQ-014-08: ADR-005 identifies the integrity risks that the later implementation tasks must
  address, including: seam tamper-detection, manifest integrity, concurrent rotation and emit,
  and re-anchoring freshness.

## Test cases

### TC-014-01 - ADR-005 exists and is linked

- Command: inspect `docs/architecture/decisions/`.
- Expected:
  - `005-log-rotation.md` exists.
  - ADR status is Proposed or Accepted.
  - Later task files can link to it.

### TC-014-02 - segment boundary trigger is resolved

- Command: read the ADR boundary-trigger section.
- Expected:
  - The ADR names the trigger mechanism (size-based bytes threshold, event count, or explicit
    checkpoint-triggered rotation) and states the chosen option with rationale.
  - The ADR notes that all three forks were considered; the chosen option is unambiguous.
  - The trigger threshold or mechanism is operator-configurable or has a documented default.

### TC-014-03 - chain continuity across the seam is specified

- Command: read the ADR chain-continuity section.
- Expected:
  - The `prev_hash` of the first record in segment N+1 equals the `hash` of the last record
    in segment N (or a signed checkpoint hash bridging the two is specified).
  - The ADR explains what enforces this link at rotation time and what verifies it at
    cross-segment Verify() time.
  - The empty-segment case (rotation triggered on an empty segment) is addressed.

### TC-014-04 - cross-segment Verify() and v1 preservation are specified

- Command: read the ADR Verify() section and compare with `docs/CONTRACT.md`.
- Expected:
  - Verify() reads all segment files from disk in order and detects a tamper at or across any
    segment boundary.
  - A single-segment log is the degenerate case and produces results identical to today's
    single-file Verify().
  - The v1 `emit`/`verify` response shapes are unchanged; no contracts bump is required.
  - In-memory copies are never trusted (Verify() reads from disk).

### TC-014-05 - segment manifest and enumeration are specified

- Command: read the ADR manifest section.
- Expected:
  - The ADR names how segments are named and ordered (naming convention or manifest file).
  - The ADR explains how a dropped or reordered segment is detected during Verify().
  - The manifest scheme's own tamper-evidence property is addressed (either the manifest is
    checked by the chain or an attacker dropping the manifest is caught in some other way).

### TC-014-06 - single-writer invariant and rotation trigger are specified

- Command: read the ADR concurrency and runtime sections.
- Expected:
  - Rotation acquires the `Chain` mutex before writing or renaming any file.
  - No emit or checkpoint operation can race with rotation.
  - The runtime surface that triggers rotation (CLI, IPC, automatic, or some combination) is
    named.

### TC-014-07 - re-anchoring at segment boundaries is specified

- Command: read the ADR re-anchoring section.
- Expected:
  - Each rotated-out segment receives a signed checkpoint using the existing ADR-003 machinery.
  - The ADR states whether re-anchoring to Rekor (ADR-004) is synchronous, asynchronous, or
    out-of-scope for this item.
  - The re-anchoring step does not block the write path.

### TC-014-08 - integrity risks and required evidence are explicit

- Command: read the ADR integrity risks and implementation evidence sections.
- Expected:
  - The seam tamper risk (Verify() can silently miss a break at a segment boundary) is listed
    with the chosen mitigation.
  - The manifest integrity risk (attacker drops or reorders a segment file) is listed with
    its mitigation.
  - The concurrent-rotation risk (emit and rotation race) is listed with its mitigation.
  - Required verification evidence for later implementation tasks (015–018) is named: which
    tests must exercise cross-segment tamper detection, seam continuity, and single-writer
    isolation.
