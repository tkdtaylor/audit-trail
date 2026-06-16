# Task 014 - design log rotation

## Goal

Write ADR-005 (log rotation / checkpointing) before any implementation begins, so the
load-bearing design decisions are explicit and reviewable: how segment boundaries are triggered,
how chain continuity is preserved across the seam, how cross-segment Verify() works without
trusting in-memory state, how the segment manifest is itself tamper-evident, how rotation
respects the single-writer mutex, and how the shipped checkpoint machinery re-anchors at
boundaries.

Design decision: [ADR-005](../../architecture/decisions/005-log-rotation.md).

## Requirements

- REQ-014-01: Add ADR-005 under `docs/architecture/decisions/005-log-rotation.md`.
- REQ-014-02: Resolve the segment boundary trigger fork (size-based, event-count, or explicit
  checkpoint-triggered) and state the chosen option with rationale and configurable threshold or
  documented default.
- REQ-014-03: Specify how chain continuity is preserved across the rotation seam: the
  `prev_hash` of the first record in segment N+1 must chain from the last hash of segment N (or
  via a bridging signed checkpoint), and state what enforces and verifies this link.
- REQ-014-04: Specify how `Verify()` walks multiple segment files from disk and detects a
  tamper at or across any segment boundary. A single-segment log must be the degenerate case
  that produces results identical to today's single-file Verify(). The v1 `emit`/`verify`
  response shapes must remain unchanged with no contracts bump.
- REQ-014-05: Specify the segment manifest/enumeration scheme and how that enumeration is
  itself tamper-evident so that dropped or reordered segment files are detectable during
  Verify().
- REQ-014-06: State that rotation is a write that must acquire the existing `Chain` mutex
  (single-writer invariant) before touching any file, and name what runtime surface triggers
  rotation.
- REQ-014-07: State that each rotated-out segment receives a signed checkpoint using the ADR-003
  signing machinery, and clarify whether Rekor re-anchoring is synchronous, asynchronous, or
  out-of-scope.
- REQ-014-08: Identify the integrity risks (seam tamper-detection, manifest integrity,
  concurrent-rotation race, re-anchoring freshness) and state the required verification evidence
  that implementation tasks 015–018 must provide.

## Acceptance criteria

- TC-014-01 passes.
- TC-014-02 passes.
- TC-014-03 passes.
- TC-014-04 passes.
- TC-014-05 passes.
- TC-014-06 passes.
- TC-014-07 passes.
- TC-014-08 passes.

## Dependencies

- Task 013, because rotation re-anchors at segment boundaries using the shipped checkpoint and
  anchoring machinery — ADR-005 must reference ADR-003 and ADR-004 as stable foundations.

## Notes

Do not implement any Go source changes in this task. The task is complete when ADR-005 is
written, the test-spec is present, and the coverage tracker is updated. The four open design
forks listed in the requirements are the load-bearing decisions ADR-005 must settle; task
executors must not resolve them in the task files themselves.
