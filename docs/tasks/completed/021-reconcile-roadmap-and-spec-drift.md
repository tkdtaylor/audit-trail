# Task 021: Reconcile ROADMAP and SPEC drift for log rotation and indexed query API

**Project:** audit-trail
**Created:** 2026-10-31
**Status:** completed

## Goal

Update `docs/ROADMAP.md` and `docs/spec/SPEC.md` so they accurately record log rotation (Tasks 014 through 018) and the indexed query API (Task 020) as completed and verified (`✅`) rather than "not started".

## Context

Tasks 014 through 018 implemented tamper-evident multi-segment log rotation (`audit-trail rotate` and IPC `{"op":"rotate"}`) and cross-segment chain verification (`verifyAllSegments`), and Task 020 implemented the cross-segment query surface (`audit-trail query` and IPC `{"op":"query"}`). Both are L6-verified in `docs/tasks/test-specs/coverage-tracker.md`, but `docs/ROADMAP.md` and `docs/spec/SPEC.md` still list those rows as "not started".

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-021-01 | `docs/ROADMAP.md` marks log rotation and the indexed query API as completed (`✅`) with their task numbers and capabilities. | must have |
| REQ-021-02 | `docs/spec/SPEC.md` updates the capability status table so log rotation and the query API are marked complete (`✅`). | must have |
| REQ-021-03 | Automated doc-consistency test (`doc_drift_021_test.go`) verifies neither `docs/ROADMAP.md` nor `docs/spec/SPEC.md` lists log rotation or the query API as "not started", and `make check` passes. | must have |

## Readiness gate

- [x] Test spec `docs/tasks/test-specs/021-reconcile-roadmap-and-spec-drift-test-spec.md` exists
- [x] Tasks 014 through 020 are completed and verified

## Implementation outline

1. Run `scripts/start-task.sh 021 reconcile-roadmap-and-spec-drift`.
2. Update `docs/ROADMAP.md` and `docs/spec/SPEC.md` to mark log rotation and the indexed query API as `✅` complete.
3. Add `doc_drift_021_test.go` asserting `docs/ROADMAP.md` and `docs/spec/SPEC.md` record log rotation and the query API as shipped.
4. Run `make check` and confirm all tests and fitness checks pass.

## Acceptance criteria

- [x] [REQ-021-01] TC-021-01: `docs/ROADMAP.md` marks log rotation and indexed query API as `✅`.
- [x] [REQ-021-02] TC-021-02: `docs/spec/SPEC.md` marks log rotation and indexed query API as `✅`.
- [x] [REQ-021-03] TC-021-03: `go test -race -v -run TestTC021 ./... && make check` passes.

## Verification plan

- **Highest level achievable:** L2/L3 automated doc-drift test + `make check`.
- **Command:** `go test -race -v -run TestTC021 ./... && make check`
