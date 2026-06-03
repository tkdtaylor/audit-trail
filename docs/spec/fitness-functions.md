# Fitness functions

**Project:** audit-trail
**Last updated:** 2026-06-03

## What this file is

Fitness functions are **executable architectural invariants** — automated checks that verify
the code still obeys the rules this project commits to. This file is the declarative spec for
those checks; the implementation lives in the runner each rule points to (a Makefile target or
a Go test).

## Why this is separate from the rest of the spec

| Mechanism | What it guards | When it runs |
|-----------|---------------|--------------|
| `spec-coverage-check` hook | Active task's TC markers have test references before commit | Pre-commit |
| `architect` drift-audit mode | Spec docs and diagrams still describe the code | On demand |
| **Fitness functions (this file)** | **Architectural invariants the code must always satisfy** | **Continuously — `make fitness`** |

## How to run

```bash
make fitness          # run all fitness functions
make fitness-<rule>   # run one rule by name
```

> **Status:** `make fitness` is wired for the currently enforceable rules below, including the
> FF-004 core emit guard accepted in
> [ADR-002](../architecture/decisions/002-enforce-no-float-audit-values.md).

## Rules

| ID | Rule | Category | Asserts | Threshold | Check command | Severity | Why this rule earns its row | Status |
|----|------|----------|---------|-----------|---------------|----------|----------------------------|--------|
| FF-001 | No third-party dependencies | structural | `go.mod` has zero `require` directives (stdlib only) | 0 deps | `make fitness-no-deps` | block | ADR-001 D1: a forensic spine minimizes trust surface. Any dependency is code that could weaken the integrity claim. Currently true and must stay true. | wired |
| FF-002 | Tamper detection holds | security | A one-byte flip on any past entry fails `verify()` | pass | `make fitness-tamper-detection` | block | This is the entire product promise (behaviors.md B-003). If it regresses, the log is no longer forensic. Already covered by a test — promote it to a named gate. | wired |
| FF-003 | Canonicalization is order-independent & stable | security | Reordered keys produce identical canonical bytes/hash | pass | `make fitness-canonical-stability` | block | An independent verifier must reproduce a hash without knowing emit order (B-007). Drift in canonical.go silently breaks every hash. | wired |
| FF-004 | No floats reach canonicalization through emit | security | `Chain.Emit` rejects float32/float64 in audited event values before hashing or append | 0 floats | `make fitness-no-floats` | block | ADR-001 D2 and ADR-002: floats are the one JCS-divergence point. The core guard keeps direct callers and transports from feeding floats into audited record hashes. | wired |
| FF-005 | `gofmt` clean | hygiene | All `.go` files are gofmt-formatted | 0 diffs | `make fitness-gofmt` | warn | Keeps diffs reviewable; cheap to enforce. `make fmt` already exists. | wired |
| FF-006 | Checkpoint payload bytes are stable | security | The committed fixture checkpoint payload canonicalizes to the committed `fixture-payload.jcs` bytes | pass | `make fitness-checkpoint-stability` | block | Checkpoint signatures and future anchoring depend on byte-stable payload canonicalization. A drift here would invalidate existing signed checkpoints even if ordinary tests still pass. | wired |
| FF-007 | Checkpoint signature tamper rejection holds | security | Altered fixture payload content and altered fixture signature bytes both fail verification | pass | `make fitness-checkpoint-tamper-detection` | block | Signed checkpoints are only useful if changed signed content or signatures fail closed. This promotes the ADR-003 tamper cases to named gates before anchoring/rotation work builds on them. | wired |

Categories: `structural`, `hygiene`, `performance`, `complexity`, `security`, `coverage`.
Severity: `block` (fails the runner) / `warn` (surfaces only).

## Rules considered but rejected

| Proposed rule | Why rejected |
|---------------|--------------|
| Test coverage ≥ N% | The spec-coverage hook + spec-verifier give better signal than a coverage % for a 4-file project; would drive cosmetic tests. |

## Source-of-truth links

- FF-001 ← ADR-001 D1, [SPEC.md](SPEC.md) top-level invariants
- FF-002, FF-003 ← [behaviors.md](behaviors.md) B-003 / B-007
- FF-004 ← ADR-001 D2, ADR-002, [behaviors.md](behaviors.md) B-001 / B-007
- FF-006, FF-007 ← ADR-003, [behaviors.md](behaviors.md) B-009 / B-010

## Notes

- FF-004 covers the core `Chain.Emit` path. IPC-specific JSON number preservation and
  fractional-number error mapping are handled separately by
  [task 003](../tasks/completed/003-normalize-ipc-json-numbers.md).
- FF-006 and FF-007 use safe test fixtures under `testdata/checkpoints/`: a deterministic
  two-record log, an Ed25519 test key pair, the signed checkpoint, and the exact canonical
  payload bytes. The private key is fixture-only test material and must not be reused outside
  tests.
