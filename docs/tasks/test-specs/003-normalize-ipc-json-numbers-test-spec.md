# Test spec: 003 — normalize IPC JSON numbers

## Scope

Make the Unix-socket IPC boundary compatible with the no-floats invariant by decoding JSON
numbers deliberately instead of accepting `encoding/json`'s default float64 conversion.

## Requirements traced

- REQ-003-01: IPC request decoding preserves integer JSON numbers as integer values before
  calling `Chain.Emit`.
- REQ-003-02: IPC rejects non-integer numeric values in emitted events with a client error.
- REQ-003-03: IPC maps event validation failures to the shared bad-request error shape rather
  than reporting them as internal server errors.
- REQ-003-04: existing `emit`, `verify`, `ping`, unknown-op, and malformed-request behavior
  remains unchanged except for the improved validation category.
- REQ-003-05: interface and behavior docs describe the IPC numeric validation behavior.

## Test cases

### TC-003-01 — integer JSON context value emits successfully

- Request: `{"op":"emit","event":{"actor":"a","action":"x","target":"t","context":{"n":1}}}`
- Expected:
  - response is `{seq,hash}`
  - subsequent verify response is valid
  - stored record contains an integer value, not a float64-derived fractional value

### TC-003-02 — fractional JSON context value is bad_request

- Request: `{"op":"emit","event":{"actor":"a","action":"x","target":"t","context":{"n":1.25}}}`
- Expected:
  - response shape is `{error:{code:"bad_request",message,retryable:false}}`
  - message identifies numeric or float rejection
  - no record is appended

### TC-003-03 — validation failures are not internal errors

- Request: any event payload rejected by the core validator from task 002.
- Expected:
  - IPC response code is `bad_request`
  - response does not use `internal`

### TC-003-04 — existing IPC ops still work

- Requests:
  - `{"op":"ping"}`
  - `{"op":"verify"}`
  - malformed JSON
  - `{"op":"unknown"}`
- Expected:
  - ping returns `{"ok":true}`
  - verify returns the current verify object
  - malformed JSON remains `bad_request`
  - unknown op remains `unknown_op`

### TC-003-05 — runtime socket path confirms behavior

- Command: run `audit-trail serve` against a temp socket/logfile and send the integer and
  fractional emit requests over the Unix socket.
- Expected:
  - observed responses match TC-003-01 and TC-003-02 over the live daemon path
