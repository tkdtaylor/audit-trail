# Test Spec 021: Reconcile ROADMAP and SPEC drift for log rotation and indexed query API

**Linked task:** [`docs/tasks/completed/021-reconcile-roadmap-and-spec-drift.md`](../completed/021-reconcile-roadmap-and-spec-drift.md)
**Written:** 2026-10-31
**Status:** ready for implementation

## Requirements coverage

| Req ID | Description | Test cases |
|--------|-------------|------------|
| REQ-021-01 | `docs/ROADMAP.md` records log rotation and indexed query API as completed (`✅`). | TC-021-01 |
| REQ-021-02 | `docs/spec/SPEC.md` records log rotation and indexed query API as completed (`✅`). | TC-021-02 |
| REQ-021-03 | Full test and fitness suite passes. | TC-021-03 |

## Test cases

### TC-021-01: `docs/ROADMAP.md` marks rotation and query API complete

- **Requirement:** REQ-021-01
- **Level:** L2 (`doc_drift_021_test.go`)
- **Step:** Read `docs/ROADMAP.md` and assert the log rotation and indexed query API rows carry `✅` and do not say `not started`.

### TC-021-02: `docs/spec/SPEC.md` marks rotation and query API complete

- **Requirement:** REQ-021-02
- **Level:** L2 (`doc_drift_021_test.go`)
- **Step:** Read `docs/spec/SPEC.md` and assert the log rotation and indexed query API rows carry `✅` and do not say `not started`.

### TC-021-03: Full test and fitness suite passes

- **Requirement:** REQ-021-03
- **Level:** L3
- **Step:** Run `make check` and confirm all unit tests and fitness checks pass.
