# Test spec: 001 — wire verification targets

## Scope

Add first-class Makefile targets for the checks the task workflow and fitness spec already
name: `make check`, `make fitness`, and named fitness rules for the existing invariants.

## Requirements traced

- REQ-001-01: `make check` runs the ordinary project verification without mutating source
  files.
- REQ-001-02: `make fitness` runs all currently enforceable fitness rules from
  `docs/spec/fitness-functions.md`.
- REQ-001-03: named fitness targets exist for no third-party deps, tamper detection,
  canonicalization stability, and gofmt cleanliness.
- REQ-001-04: the fitness spec reflects the implemented target names and status.

## Test cases

### TC-001-01 — check target runs build and tests

- Command: `make check`
- Expected:
  - exits 0 on the current clean tree
  - runs `go test ./...`
  - runs `go build ./...`
  - does not rewrite Go source files

### TC-001-02 — umbrella fitness target runs all wired rules

- Command: `make fitness`
- Expected:
  - exits 0 on the current clean tree
  - runs the no-deps check
  - runs the tamper-detection test
  - runs the canonicalization-stability test
  - runs the gofmt cleanliness check
  - prints a clear final success line suitable for task reports

### TC-001-03 — no-deps fitness rule fails on a require directive

- Setup: temporarily add a `require` directive to `go.mod` in a disposable copy or restore it
  before commit.
- Command: `make fitness-no-deps`
- Expected:
  - exits non-zero when `go.mod` contains a third-party dependency
  - exits 0 after restoring the no-dependency state

### TC-001-04 — named security tests are callable through fitness

- Commands:
  - `make fitness-tamper-detection`
  - `make fitness-canonical-stability`
- Expected:
  - each exits 0
  - each invokes the specific existing Go test named by the fitness spec

### TC-001-05 — gofmt fitness rule catches unformatted Go

- Setup: introduce reversible formatting drift in a disposable copy or restore it before
  commit.
- Command: `make fitness-gofmt`
- Expected:
  - exits non-zero while formatting drift exists
  - reports the unformatted file path
  - exits 0 after `gofmt` restores the file
