# Test Coverage Tracker

**Project:** audit-trail

## Rules

- Test specs are written **before** implementation begins — no exceptions
- A task is **not** "complete" because the feat commit landed and tests passed. See the verification ladder below.
- Each row maps a task ID to its spec file, current test status, and the verification level achieved

## Coverage

| Task ID | Feature | Spec file | Tests written | Status | Verified by |
|---------|---------|-----------|---------------|--------|-------------|
| 001 | Wire verification targets | [001-wire-verification-targets-test-spec.md](001-wire-verification-targets-test-spec.md) | Spec complete; TC-001-01..05 passed | 🟡 | L3: `make fitness` -> `fitness: all wired checks passed`; `make check` -> `go build ./...`; failure paths observed |
| 002 | Reject floats in core emit path | [002-reject-floats-in-core-test-spec.md](002-reject-floats-in-core-test-spec.md) | Spec complete; TC-002-01..05 passed | 🟡 | L3: `make fitness` -> `fitness: all wired checks passed`; `make check` -> `go build ./...`; core float rejection remains covered by `TestEmitRejectsFloats`; current IPC numeric behavior is verified by task 003 |
| 003 | Normalize IPC JSON numbers | [003-normalize-ipc-json-numbers-test-spec.md](003-normalize-ipc-json-numbers-test-spec.md) | Spec complete; TC-003-01..05 passed | ✅ | L6: live `go run . serve` socket path; integer emit -> `{"seq":0,"hash":"..."}`; fractional emit -> `{"error":{"code":"bad_request",...,"retryable":false}}`; verify -> `{"valid":true,...}`; logfile line count `1`; `make check` -> `go build ./...`; `make fitness` -> `fitness: all wired checks passed` |
| 004 | Design signed checkpoints | [004-design-signed-checkpoints-test-spec.md](004-design-signed-checkpoints-test-spec.md) | Spec complete; TC-004-01..05 passed | 🟡 | Docs review: [ADR-003](../../architecture/decisions/003-signed-checkpoints.md) exists, is accepted, specifies payload/signing/runtime/risk evidence; design-only, no runtime surface. Checks: `go fmt ./...`; `go test ./...` -> `ok github.com/tkdtaylor/audit-trail (cached)`; `go build ./...`; `make fitness` -> `fitness: all wired checks passed` |
| 005 | Checkpoint payload core | [005-checkpoint-payload-core-test-spec.md](005-checkpoint-payload-core-test-spec.md) | Spec complete; TC-005-01..05 passed | 🟡 | L3: unit-test-only internal helper; no runtime surface. `make check` -> `go build ./...`; `make fitness` -> `fitness: all wired checks passed`; security-focused review found no issues in the disk-backed checkpoint payload path |
| 006 | Sign and verify checkpoints | [006-sign-and-verify-checkpoints-test-spec.md](006-sign-and-verify-checkpoints-test-spec.md) | Spec complete; TC-006-01..05 passed | 🟡 | L2: unit-test-only signing helpers; no runtime surface until task 007. `go test ./... -run 'Checkpoint'` -> `ok github.com/tkdtaylor/audit-trail`; `make check` and `make fitness` pass on task branch |
| 007 | Checkpoint runtime surface | [007-checkpoint-runtime-surface-test-spec.md](007-checkpoint-runtime-surface-test-spec.md) | Spec complete; TC-007-01..05 passed | ✅ | L6: live CLI `checkpoint verify --checkpoint ... --public-key ... --logfile ...` -> `{valid:true, signature_valid:true, log_match:true}`; tampered checkpoint exited 1 with `invalid checkpoint signature`; live Unix socket `checkpoint_create` returned a signed envelope; `checkpoint_verify` -> `{valid:true,signature_valid:true,log_match:true,...}`; existing live IPC `ping` -> `{"ok":true}`, `verify` -> v1 verify shape, `emit` -> `{hash,seq}`; `make check` -> `go build ./...`; `make fitness` -> `fitness: all wired checks passed` |
| 008 | Checkpoint fitness and fixtures | [008-checkpoint-fitness-and-fixtures-test-spec.md](008-checkpoint-fitness-and-fixtures-test-spec.md) | Spec complete; TC-008-01..05 passed | ✅ | L5: fixture verification tests exercise committed `testdata/checkpoints` log/key/checkpoint/payload fixtures; `make fitness-checkpoint-stability` -> `ok github.com/tkdtaylor/audit-trail`; `make fitness-checkpoint-tamper-detection` -> `ok github.com/tkdtaylor/audit-trail`; umbrella `make fitness` includes both and ends `fitness: all wired checks passed`; `make check` -> `go build ./...` |
| 009 | Design witness anchoring | [009-design-witness-anchoring-test-spec.md](009-design-witness-anchoring-test-spec.md) | Spec complete; TC-009-01..05 passed | ✅ | Docs review: [ADR-004](../../architecture/decisions/004-witness-anchoring.md) exists, specifies Rekor schema/inclusion proof/verification/risk evidence; design-only, no runtime surface. Checks: `go fmt ./...`; `go test ./...` -> `ok github.com/tkdtaylor/audit-trail 0.039s`; `go build ./...`; `make fitness` -> `fitness: all wired checks passed` |
| 010 | Rekor client core | [010-rekor-client-core-test-spec.md](010-rekor-client-core-test-spec.md) | Spec complete; TC-010-01..04 passed | 🟡 | L2: unit-test-only; no runtime surface. `make check` -> `ok github.com/tkdtaylor/audit-trail`; `make fitness` -> `fitness: all wired checks passed` |
| 011 | Offline and online anchor verification | [011-anchor-verification-test-spec.md](011-anchor-verification-test-spec.md) | Spec complete; TC-011-01..03 passed | ✅ | L2: unit-test-only; no runtime surface. `make check` -> `ok github.com/tkdtaylor/audit-trail`; `make fitness` -> `fitness: all wired checks passed` |
| 012 | Anchoring runtime surface | [012-anchoring-runtime-surface-test-spec.md](012-anchoring-runtime-surface-test-spec.md) | Spec complete; TC-012-01..05 passed | ✅ | L5: validation harness exercises CLI and IPC socket paths. `go test -v -run TestRekorRuntimeIntegration` -> `ok github.com/tkdtaylor/audit-trail 0.608s` |
| 013 | Anchoring fitness and fixtures | [013-anchoring-fitness-fixtures-test-spec.md](013-anchoring-fitness-fixtures-test-spec.md) | Spec complete; TC-013-01..04 passed | ✅ | L5: fixture verification tests exercise committed `testdata/checkpoints/rekor-*` fixtures; `make fitness-anchor-stability` -> `ok github.com/tkdtaylor/audit-trail 0.004s`; `make fitness-anchor-tamper-detection` -> `ok github.com/tkdtaylor/audit-trail 0.003s`; umbrella `make fitness` includes both and ends `fitness: all wired checks passed`; `make check` -> `go build ./...` |
| 014 | Design log rotation | [014-design-log-rotation-test-spec.md](014-design-log-rotation-test-spec.md) | Spec complete; TC-014-01..08 passed | ✅ | Docs review (design-only, no runtime surface): [ADR-005](../../architecture/decisions/005-log-rotation.md) written, status Accepted; spec-verifier APPROVE — all 8 TCs / 25 sub-assertions satisfied. Resolves all 4 forks (event-count boundary trigger, manifest/seam tamper-evidence, parameterized walk + v1 preservation, synchronous re-anchoring), with single-writer mutex, integrity risks, and required 015–018 evidence. No Go source modified |
| 015 | Segment and manifest core | [015-segment-and-manifest-core-test-spec.md](015-segment-and-manifest-core-test-spec.md) | TC-015-01..08 implemented + passing (segment_test.go). Follow-ups: TC-015-02 failure-path proven (`TestManifestWriteFailureLeavesNoTempFile` — rename forced to fail, no leftover `.tmp`); SEC-001 fixed (Rotate derives segment number from disk + refuses overwrite, `TestRotateDoesNotOverwriteExistingSegment`) | 🟡 Code merged | L3: `make check` (`ok github.com/tkdtaylor/audit-trail`) + `go build ./...` clean; `make fitness` "fitness: all wired checks passed"; `go test -race ./...` clean. data-model.md updated (disk-derived segment numbering + SEC-001 non-destructive rotate). Awaiting spec-verifier + L5/L6. |
| 016 | Cross-segment Verify() | [016-cross-segment-verify-test-spec.md](016-cross-segment-verify-test-spec.md) | Spec complete; TC-016-01..08 defined | ❌ Not started | — |
| 017 | Rotation runtime surface | [017-rotation-runtime-surface-test-spec.md](017-rotation-runtime-surface-test-spec.md) | Spec complete; TC-017-01..06 defined | ❌ Not started | — |
| 018 | Rotation fitness and fixtures | [018-rotation-fitness-and-fixtures-test-spec.md](018-rotation-fitness-and-fixtures-test-spec.md) | Spec complete; TC-018-01..04 defined | ❌ Not started | — |



## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | **Verified** — validation harness exercised the live runtime path, or operator observed the targeted behaviour |
| 🟡 | **Code merged** — feat-commit landed, unit tests + fitness + CI green, but runtime/live behaviour not yet observed |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |

## Verification ladder

A task earns 🟡 at levels 1–4 and ✅ only at level 5 or 6. The `Verified by` column records which level the row reached.

| Level | Evidence | Status this earns |
|-------|----------|-------------------|
| 1 | Code merged | 🟡 |
| 2 | Unit tests pass (paste verbatim final line of `make check`) | 🟡 |
| 3 | `make fitness` passes (verbatim closing line) | 🟡 |
| 4 | CI passes (`gh run watch <id> --exit-status` → success) | 🟡 |
| 5 | **Validation harness** exercises the live runtime path end-to-end — paste the command and the final assertion line | ✅ |
| 6 | **Operator-observed** — operator (or executor via `cargo run` / `npm start` / etc.) saw the targeted behaviour in stdout / logs / UI | ✅ |

If the task targets runtime-observable behaviour (logging, CLI args, TUI, server endpoints, file outputs, side effects), level 5 or 6 is **required** before flipping to ✅. If the task only adds an internal helper covered by unit tests, level 2 may be sufficient — but in that case the row's `Verified by` should explicitly say "unit-test-only; no runtime surface" so future readers don't mistake silence for verification.

## Rule

**The task-executor commits at 🟡 by default.** Only the main session (after spec-verifier APPROVE + the appropriate level-5/6 evidence) updates the row to ✅, in a separate commit titled `verify: confirm task NNN — <level-5/6 evidence>`. This keeps the verification step visible in git history and prevents "merged ≠ done" drift.
