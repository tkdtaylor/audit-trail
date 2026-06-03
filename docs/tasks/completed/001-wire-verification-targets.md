# Task 001 — wire verification targets

## Goal

Turn the proposed verification rails into executable project targets so future task work can
rely on `make check` and `make fitness` without ad hoc commands.

## Requirements

- REQ-001-01: Add `make check` as the ordinary non-mutating project verification target. It
  must run `go test ./...` and `go build ./...`.
- REQ-001-02: Add `make fitness` as an umbrella target for currently enforceable fitness
  functions.
- REQ-001-03: Add named targets for:
  - `fitness-no-deps`
  - `fitness-tamper-detection`
  - `fitness-canonical-stability`
  - `fitness-gofmt`
- REQ-001-04: Update `docs/spec/fitness-functions.md` so implemented rules are marked wired
  and the command names match the Makefile.

## Acceptance criteria

- TC-001-01 passes.
- TC-001-02 passes.
- TC-001-03 passes.
- TC-001-04 passes.
- TC-001-05 passes.
- `make check` and `make fitness` both exit 0 on the final tree.

## Dependencies

None.

## Notes

Do not implement FF-004 here. This task only wires checks for invariants that are already
directly enforceable from the current code and tests.
