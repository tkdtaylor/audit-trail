# Test spec: 002 — reject floats in core emit path

## Scope

Enforce the documented "no floats in audited events" invariant in the core `Chain.Emit` path.
This task covers direct Go callers and the core validation behavior. IPC-specific JSON number
normalization is task 003. The accepted design decision is
[ADR-002](../../architecture/decisions/002-enforce-no-float-audit-values.md).

## Requirements traced

- REQ-002-01: `Chain.Emit` rejects float32 and float64 values anywhere in audited event input
  fields that are copied into the record.
- REQ-002-02: validation recurses through arrays and objects in `refs` and `context`.
- REQ-002-03: valid integer, string, bool, nil, array, and object values continue to emit and
  verify successfully.
- REQ-002-04: validation errors are explicit enough for callers to identify a rejected float.
- REQ-002-05: behavior, data-model, and fitness docs no longer describe float rejection as only
  proposed.

## Test cases

### TC-002-01 — context float is rejected

- Input: `Chain.Emit(map[string]any{"actor":"a","action":"x","target":"t","context":map[string]any{"score":1.5}})`
- Expected:
  - returns a non-nil error
  - does not append a record to the logfile
  - error message identifies a float value

### TC-002-02 — nested float is rejected

- Input: a float inside a nested `context` object or array.
- Expected:
  - returns a non-nil error
  - does not append a record
  - error message identifies the nested location enough to debug the payload

### TC-002-03 — refs float is rejected

- Input: `refs` containing a map with a float value.
- Expected:
  - returns a non-nil error
  - does not append a record

### TC-002-04 — allowed value types still emit

- Input: event with string, int, int64, bool, nil, arrays, and maps but no floats.
- Expected:
  - `Emit` succeeds
  - `Verify` returns `valid:true`
  - emitted record remains canonicalizable

### TC-002-05 — FF-004 is wired to the guard

- Command: `make fitness-no-floats`
- Expected:
  - exits 0
  - runs the test case proving float rejection
