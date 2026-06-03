# ADR-002 — Enforce no-float audited values at emit boundaries

**Status:** Accepted · **Date:** 2026-06-03

## Context

ADR-001 freezes canonicalization around RFC 8785/JCS semantics while deliberately excluding
floats from audited event values. That exclusion is currently documented but not enforced by
the emit path. A float that reaches canonicalization can diverge from strict JCS behavior,
which weakens independent verification of the hash equation.

The main ambiguity is the IPC boundary: Go's default `encoding/json` unmarshals all JSON
numbers into `float64` when decoding into `map[string]any`. If the core simply rejects all Go
float values, IPC would also reject integer JSON payloads such as `"context":{"n":1}` unless
the socket decoder preserves numbers deliberately.

## Decision

Enforce the no-floats invariant in two layers:

1. The core `Chain.Emit` path rejects `float32` and `float64` values anywhere in audited event
   values before hashing or appending a record.
2. The IPC decoder preserves JSON numbers, normalizes integer JSON numbers to integer Go
   values before calling `Chain.Emit`, and rejects fractional JSON numbers as `bad_request`.

Allowed audited values remain integer, string, bool, null, array, and object values. Rejection
is a client/input validation failure, not an internal server error.

## Consequences

- The JCS subset becomes executable instead of relying on caller discipline.
- Direct Go callers and all transports inherit the core guard.
- IPC keeps accepting integer JSON values while refusing fractional numeric values.
- The v1 `emit` and `verify` shapes stay intact; this narrows invalid input rather than
  changing the contract verbs or response envelope.
- The implementation is split across task 002 (core guard and FF-004) and task 003 (IPC number
  decoding and error mapping).

## Links

- [ADR-001 D2](001-foundational-stack.md) — canonicalization: RFC 8785/JCS via `encoding/json`,
  floats excluded.
- [docs/spec/fitness-functions.md](../../spec/fitness-functions.md) — FF-004.
- [docs/tasks/backlog/002-reject-floats-in-core.md](../../tasks/backlog/002-reject-floats-in-core.md)
- [docs/tasks/backlog/003-normalize-ipc-json-numbers.md](../../tasks/backlog/003-normalize-ipc-json-numbers.md)
