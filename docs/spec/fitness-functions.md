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

> **Status:** the rows below are **proposed**. The audit surfaced them from the code; each
> still needs (a) user confirmation it's load-bearing and (b) a `fitness-<rule>` Makefile
> target + check wired up. There is no `make fitness` target yet — adding the first rule means
> adding the umbrella target too.

## Rules

| ID | Rule | Category | Asserts | Threshold | Check command | Severity | Why this rule earns its row | Status |
|----|------|----------|---------|-----------|---------------|----------|----------------------------|--------|
| FF-001 | No third-party dependencies | structural | `go.mod` has zero `require` directives (stdlib only) | 0 deps | `make fitness-no-deps` (`! grep -q '^require' go.mod`) | block | ADR-001 D1: a forensic spine minimizes trust surface. Any dependency is code that could weaken the integrity claim. Currently true and must stay true. | proposed |
| FF-002 | Tamper detection holds | security | A one-byte flip on any past entry fails `verify()` | pass | `go test -run TestEmitVerifyAndTamperDetection` | block | This is the entire product promise (behaviors.md B-003). If it regresses, the log is no longer forensic. Already covered by a test — promote it to a named gate. | proposed |
| FF-003 | Canonicalization is order-independent & stable | security | Reordered keys produce identical canonical bytes/hash | pass | `go test -run TestCanonicalIsOrderIndependent` | block | An independent verifier must reproduce a hash without knowing emit order (B-007). Drift in canonical.go silently breaks every hash. | proposed |
| FF-004 | No floats reach canonicalization | security | Audited event values are int/string/bool/null/array/object only | 0 floats | *(needs a guard or test — none today)* | block | ADR-001 D2: floats are the one JCS-divergence point. Today this is an unenforced convention (behaviors.md B-007 TODO). Enforcing it is the natural fitness function. | proposed |
| FF-005 | `gofmt` clean | hygiene | All `.go` files are gofmt-formatted | 0 diffs | `test -z "$(gofmt -l .)"` | warn | Keeps diffs reviewable; cheap to enforce. `make fmt` already exists. | proposed |

Categories: `structural`, `hygiene`, `performance`, `complexity`, `security`, `coverage`.
Severity: `block` (fails the runner) / `warn` (surfaces only).

## Rules considered but rejected

| Proposed rule | Why rejected |
|---------------|--------------|
| Test coverage ≥ N% | The spec-coverage hook + spec-verifier give better signal than a coverage % for a 4-file project; would drive cosmetic tests. |

## Source-of-truth links

- FF-001 ← ADR-001 D1, [SPEC.md](SPEC.md) top-level invariants
- FF-002, FF-003 ← [behaviors.md](behaviors.md) B-003 / B-007
- FF-004 ← ADR-001 D2, [behaviors.md](behaviors.md) B-007 TODO

## Notes

- FF-004 is the highest-value rule that **isn't** enforced yet — a float in `context` would
  canonicalize via Go's default float formatting and could diverge from JCS. Decide between an
  input-time reject and a documented-only convention.
