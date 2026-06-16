# Test spec: 017 - rotation runtime surface

## Scope

Expose log rotation through the CLI and Unix-socket IPC surfaces defined by ADR-005, while
preserving all existing v1 `emit`/`verify`/`ping`/`checkpoint_*` shapes unchanged. The emit
path must not block on rotation. All new surfaces are additive.

## Requirements traced

- REQ-017-01: Add a CLI command or flag to trigger log rotation and display the resulting
  segment manifest or rotation summary as JSON, as specified by ADR-005.
- REQ-017-02: Add the ADR-005-specified IPC operation for rotation; the daemon uses rotation
  configuration from startup flags, not per-request paths.
- REQ-017-03: The `emit` write path is never blocked by rotation — if rotation is automatic,
  it must not hold the emit lock beyond the rotation operation itself, and a rotation in
  progress must not stall a queued emit indefinitely.
- REQ-017-04: Missing or unconfigured rotation settings return the shared
  `{error:{code,message,retryable}}` shape over IPC.
- REQ-017-05: All existing v1 IPC ops (`emit`, `verify`, `ping`) and CLI operations produce
  unchanged responses after this task.
- REQ-017-06: Update `docs/spec/interfaces.md` and `docs/spec/behaviors.md` for the new
  runtime-visible rotation surface.

## Test cases

### TC-017-01 - CLI triggers rotation and reports result

- Command: run the ADR-005-specified CLI rotation command against a temp logfile that exceeds
  the rotation threshold.
- Expected:
  - Exits 0.
  - Prints the rotation result (segment manifest summary or similar) as JSON to stdout.
  - A new active segment file exists at the ADR-005-specified path.
  - The rotated-out segment file exists and its signed checkpoint is present.

### TC-017-02 - CLI verify works across segments after rotation

- Command: after TC-017-01, run `audit-trail verify --logfile <active-segment-or-manifest>`.
- Expected:
  - Exits 0.
  - Returns `{valid:true, tamper_detected_at:null, message:"chain intact"}`.
  - Existing v1 verify response shape is unchanged.

### TC-017-03 - IPC rotate operation succeeds

- Command: start `audit-trail serve` with rotation configuration and send the ADR-005 IPC
  rotation request over the Unix socket.
- Expected:
  - Returns the rotation result JSON.
  - A new active segment file exists after the response.
  - The rotated-out segment's signed checkpoint is present.

### TC-017-04 - IPC rotate without configuration returns structured error

- Command: start `audit-trail serve` without rotation configuration and send the IPC rotation
  request.
- Expected:
  - Returns `{error:{code:"rotation_not_configured"|similar,message:"...",retryable:false}}`.
  - The daemon does not crash or produce a partial rotation.

### TC-017-05 - existing IPC and CLI ops are unchanged after rotation

- Command: after a rotation, send `emit`, `verify`, `ping`, and `checkpoint_create` over the
  Unix socket; run CLI `emit` and `verify`.
- Expected:
  - All existing response shapes are identical to pre-rotation behavior.
  - `emit` appends to the new active segment with correct `prev_hash` and incremented seq.
  - `verify` walks all segments and returns `{valid:true,...}`.
  - `ping` returns `{"ok":true}`.
  - `checkpoint_create` returns a signed checkpoint for the current active segment head.

### TC-017-06 - runtime documentation is updated

- Command: inspect `docs/spec/interfaces.md` and `docs/spec/behaviors.md`.
- Expected:
  - New CLI rotation command is documented.
  - New IPC rotation op is documented with its request/response shapes.
  - IPC error shape for missing configuration is documented.
  - All docs stay present-tense.
