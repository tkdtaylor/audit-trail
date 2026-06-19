# Task 019 - Apache-2.0 relicense follow-up — SPDX headers + publish

## Context

Relicensed PolyForm Noncommercial → Apache-2.0 in commit `73cc926`.

Done in that commit:
- `LICENSE` (Apache-2.0), `NOTICE`
- README adoption sections
- `CONTRIBUTING.md` (DCO)
- `.github/FUNDING.yml` + `.github/dco.yml`
- PolyForm references fixed in `README.md`, `CLAUDE.md`, and `docs/`

## Remaining

### REQ-019-01: SPDX headers — DONE (2026-06-19)
Add `// SPDX-License-Identifier: Apache-2.0` as the first line of every first-party Go
source file (`*.go`). Skip generated and vendored files. Land this as its own commit.

Completed: header added to all 22 first-party `.go` files (incl. `_test.go`). No vendored
or `Code generated ... DO NOT EDIT.` files present. `testdata/segments/generate/main.go`
carries `//go:build ignore`; SPDX placed above the constraint with the blank line before
`package` preserved. `go build ./...` passes; `gofmt -l .` clean.

### REQ-019-02: Publish
This repo has no git remote yet. When ready, create the GitHub remote and push. Confirm
public/private visibility intent at that point.

## Acceptance criteria

- TC-019-01: Every first-party `.go` file has the SPDX Apache-2.0 header as its first line. ✅ DONE
- TC-019-02: GitHub remote created and the repo pushed. ⏳ PENDING (awaits user creating a remote)

## Notes

REQ-019-01 and REQ-019-02 are independent and can land separately. SPDX headers should go
in before publishing.
