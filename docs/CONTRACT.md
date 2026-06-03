# audit-trail v1 contract

Mirrors the ecosystem's v1 interface contract (audit-trail), validated
by the tracer-bullet (A6).

## Verbs

### `emit(event) -> { seq, hash }`
```
event = {
  ts:        int,            # unix seconds (set by emitter; immutable at emission)
  actor:     string,         # requester identity (block/agent/user)
  action:    string,         # verb: resolve | inject | decide | scan | spawn | exit | ...
  target:    string,         # resource: vault://…, host, sandbox-id, …
  decision?: string,         # allow | deny | require_approval | block
  refs:      [{type,id}],    # related attestation refs (in-toto/SLSA, findings, cve, …)
  context?:  object,         # emitter-specific; integer/string values only
  # server-assigned:
  seq:       int,            # monotonic
  prev_hash: string,         # hash of the previous entry
  hash:      string,         # SHA256(prev_hash + JCS(record_without_hash))
}
```

### `verify() -> { valid, tamper_detected_at, message }`
Walks the chain: checks each `prev_hash` links the prior `hash`, and each `hash` recomputes
from the entry's canonical content. Returns the `seq` of the first broken entry.

## Transports

- **IPC (hot path):** newline-delimited JSON over a Unix socket (`--socket`).
  `{"op":"emit","event":{…}}` · `{"op":"verify"}` · `{"op":"ping"}`.
- **CLI (standalone/CI):** `audit-trail emit …` / `audit-trail verify …`.

## Canonicalization (RFC 8785 / JCS)

Sorted object keys, no insignificant whitespace, UTF-8, shortest-decimal integers. Floats
are excluded from audited events by convention. See [../canonical.go](../canonical.go).
