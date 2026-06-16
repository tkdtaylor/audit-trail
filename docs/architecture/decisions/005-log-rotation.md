# ADR-005 — Log rotation / checkpointing

**Status:** Accepted · **Date:** 2026-06-16

## Context

ADR-001 names log rotation/checkpointing as a v1+ roadmap item. Today the chain is a single
append-only JSONL file at `Chain.path`: `Emit()` appends one record under the `Chain` mutex,
`loadState()` resumes `seq`/`prevHash` by scanning the file, and `Verify()` (via
`verifyChainState`) walks that one file from disk, starting at `Genesis`, checking each
`prev_hash` link and recomputing each `hash`. ADR-003 added signed checkpoints over a verified,
disk-backed chain head; ADR-004 added asynchronous Rekor anchoring of those checkpoints.

An unbounded single file becomes operationally awkward: it cannot be archived, shipped, or
expired in pieces, and a full `Verify()` must always read the whole file. Rotation splits the
log into ordered *segments* so that closed segments can be archived and checkpointed while a
small active segment keeps taking writes.

Rotation is the most integrity-sensitive change since checkpoints: a naive split could break the
hash chain at the seam, or let an attacker drop/reorder/truncate segments and have `Verify()`
still report `valid:true`. This ADR settles the load-bearing forks **before** any Go is written
(tasks 015–018), so the design is reviewable and the implementation tasks have explicit
invariants to satisfy. The frozen v1 `emit`/`verify` contract (docs/CONTRACT.md) must not
change and no contracts bump is required.

## Decision

Add log rotation as an additive feature behind the existing emit/verify seam. The log becomes
an ordered sequence of segments held together by the same SHA-256 hash chain that already
links records; rotation never weakens that chain, and tamper-evidence stays **cryptographic**,
not index-based.

### 1. Segment boundary trigger — event-count, explicit `Rotate()`

Rotation is triggered by an **event-count threshold**, enforced by a discrete
`Chain.Rotate()` operation. Rotation is **not** automatic inside `Emit()`: it is a separate
runtime operation (CLI command + IPC op, wired in task 017). `Rotate()`:

- counts the records in the **active** segment (the file at `chain.path`);
- if the active segment holds **fewer** records than the configured threshold, it **declines**
  — a sentinel no-op (e.g. `errBelowRotationThreshold` / a `rotated:false` result), changing
  nothing on disk;
- if the active segment holds records **at or above** the threshold, it proceeds.

The threshold is operator-configurable with a **documented default** (e.g. `--rotate-after N`
records; the v1+ default is recorded in docs/spec/configuration.md when task 017 lands).

**Forks considered:**

- **Size-based (byte threshold).** Rotate when the active file exceeds N bytes. Pro: bounds raw
  file size directly, which is the most operationally intuitive knob. Con: boundaries depend on
  record sizes, so fixture bytes are non-deterministic across runs and harder for task 018 to
  pin; it also nudges the size check toward the emit hot path.
- **Event-count (chosen).** Rotate at N records. Pro: deterministic fixtures (task 018 can
  commit stable bytes because a known record count produces a known segment), trivial to test,
  and the count is already cheap to know. Con: raw byte size of a segment is not directly
  bounded — a run of large records yields a larger file.
- **Checkpoint-triggered.** Rotate whenever a signed checkpoint is created. Pro: every closed
  segment is automatically checkpointed. Con: conflates two independent operations (a verifier
  may want a checkpoint without rotating), and makes segment size a side effect of checkpoint
  cadence rather than an operator choice.

Event-count wins for **deterministic fixtures, simple testing, and keeping the emit hot path
off the rotation path**. The trade-off — raw byte size is not directly bounded — is acceptable
for a forensic archive, where the operator controls record shape and rotation cadence and where
predictable segment contents matter more than a hard byte cap. A future size-based mode can be
added as an additional trigger without superseding this ADR, because both reduce to "call
`Rotate()` when condition X holds."

### 2. Chain continuity across the seam (REQ-014-03)

The hash chain is what holds segments together. Continuity invariant:

> The `prev_hash` of the **first** record in segment N+1 equals the `hash` of the **last**
> record in segment N.

This falls out of the existing design for free: rotation does **not** reset chain state. When
`Rotate()` closes the active segment and opens the new one, `Chain.prevHash` and `Chain.seq` are
**carried over** unchanged. The next `Emit()` into the new active segment therefore writes a
record whose `prev_hash` is the closed segment's last `hash` and whose `seq` continues the
global monotonic sequence — exactly as if no rotation had happened. There is no separate
"bridge" record; the chain link itself is the bridge.

- **Enforced at rotation time:** `Rotate()` preserves `c.prevHash`/`c.seq`, so the first
  post-rotation `Emit` carries the seam link automatically.
- **Verified at cross-segment Verify() time:** the walker (fork 3) carries the ending `hash` of
  segment N forward as the starting `prev_hash` for segment N+1. The first record of N+1 must
  link to it; if it does not, `Verify()` reports a broken link — this is the **seam check**.

**Empty-segment case (TC-014-03):** under the count-threshold-plus-decline rule, an empty (or
below-threshold) active segment is below threshold, so `Rotate()` no-ops. An empty segment can
therefore never be rotated out, and no zero-record segment can ever appear in the manifest. This
removes the degenerate "empty segment" from the design entirely rather than having to handle it.

### 3. Parameterized segment walk (REQ-014-03 / REQ-014-04)

Today `verifyChainState(path)` hard-codes two assumptions: record 0's `prev_hash` is `Genesis`,
and the seq/tree-size offset starts at 0. A rotated segment N>0 begins with
`prev_hash = segment N-1's last hash`, **not** `Genesis`, so the current walker cannot verify it
directly.

The implementation refactors the walk into a **per-segment walker** that accepts:

- a starting `prev_hash` (defaulting to `Genesis`), and
- a starting seq / tree-size offset (defaulting to `0`).

With both defaults, the walker reproduces today's single-file behavior **byte-for-byte** — the
single-segment log is the degenerate 1-segment case and `Verify()` returns identical results to
today. Cross-segment `Verify()` (task 016) then:

1. reads the manifest to learn the ordered segment list;
2. for each segment in order, walks it with the **carried** ending `prev_hash` and seq offset
   from the previous segment (Genesis/0 for the first);
3. between segments, applies the **seam check** (the next segment's first `prev_hash` must equal
   the prior segment's last `hash`);
4. cross-checks each segment's walked result (ending hash, first/last seq) against the
   manifest's recorded values for that segment.

A tamper anywhere — inside a record, at a seam, or in a manifest field — surfaces as
`valid:false`. `Verify()` always reads from disk; it never trusts the in-memory `Chain.prevHash`
or `Chain.seq`. The v1 `emit`/`verify` response shapes are unchanged and **no contracts bump**
is required: a multi-segment log still returns `{valid, tamper_detected_at, message}`, and
`tamper_detected_at` reports the global `seq` of the first broken record (or the seam, reported
at the seq where the link should have continued). This generalization is **shared** by task 015
(checkpoint a rotated-out segment at its boundary head), task 016 (chain the walk across all
manifest segments), and task 018 (deterministic multi-segment fixtures).

### 4. Re-anchoring at boundaries (REQ-014-07)

Each rotated-out segment receives a **signed checkpoint created synchronously at rotation time**,
using the existing ADR-003 `CreateSignedCheckpoint` / `BuildCheckpointPayload` machinery. The
checkpoint is local and offline (Ed25519 signing only — no network). It commits to the
**cumulative** chain head as of that boundary: `tree_size`, `last_seq`, and `root_hash` reflect
the **global** chain up to and including that segment's last record (not a per-segment subtree).
This reuses ADR-003 semantics exactly: `hash_algorithm` stays `sha256-linear-chain-v1` and
`root_hash` is the linear-chain head, so a rotated-segment checkpoint is indistinguishable in
shape from today's whole-log checkpoint.

**Rekor re-anchoring (ADR-004) is out of scope for the rotation operation and remains
asynchronous.** `Rotate()` and `Emit()` never touch the network. Operators anchor a per-segment
checkpoint separately, after the fact, via the existing `checkpoint anchor` surface. This keeps
the write path (emit) and the rotation path both fully offline and non-blocking, consistent with
ADR-004's "emitters run completely offline" rule.

### 5. Single-writer / concurrency (REQ-014-06)

`Rotate()` is a **write** and runs under the existing single-writer invariant. It acquires the
`Chain` mutex (`c.mu`) **before** touching any file and holds it across the entire operation:

1. count records in the active segment; decline (release lock, no-op) if below threshold;
2. create the rotated-out segment's signed checkpoint (synchronous, offline);
3. rename the active segment to its `<base>.NNN` sibling;
4. write the per-segment checkpoint file `<base>.NNN.checkpoint`;
5. write/update the `<base>.manifest` atomically (temp file + rename, mode 0600);
6. open a fresh active segment file at `chain.path`, preserving carried-over
   `c.prevHash`/`c.seq`.

The lock is held until all file operations succeed or the operation fails cleanly (on failure,
disk is left in a consistent, verifiable state — see Integrity risks). Because `Emit()`,
`BuildCheckpointPayload()`, and `Rotate()` all take `c.mu`, **no emit or checkpoint operation
can race with rotation**: writes are fully serialized through the one mutex.

### Runtime surface

Rotation is triggered by a runtime surface added in **task 017** (details deferred to that task
and its ADR-worthy decisions, if any):

- **CLI:** `audit-trail rotate --logfile <path> [...]` — runs `Rotate()`, prints whether
  rotation occurred (e.g. `{rotated, segment, seq_range}`) or that it declined below threshold;
  exit code reflects success.
- **IPC:** `{"op":"rotate"}` — success returns the rotation result object; below-threshold and
  error cases use the shared `{error:{code,message,retryable}}` shape (e.g.
  `rotation_below_threshold` non-retryable, or a `rotated:false` success — settled in task 017).

The v1 `emit`/`verify`/`ping` surfaces are untouched. Rotation never happens implicitly inside
`Emit()`.

## Data schemas

### Segment

A segment is a JSONL file of audit records, identical in record format to today's single log.

| Aspect | Value |
|--------|-------|
| Active segment | File at `chain.path` (e.g. `audit.log`) — a never-rotated log is byte-identical to today's single file (the degenerate case). |
| Rotated-out segment | Sibling file `<base>.NNN`, zero-padded monotonic (e.g. `audit.log.001`, `audit.log.002`). |
| Per-segment checkpoint | `<base>.NNN.checkpoint` — an ADR-003 signed checkpoint over the cumulative chain head at that boundary. |
| Record format | Unchanged: `{seq, ts, actor, action, target, decision, refs, context, prev_hash, hash}`. |
| Continuity | First record's `prev_hash` = previous segment's last `hash` (Genesis for segment 0). |

### SegmentManifest

JSON index at `<base>.manifest`, mode 0600, written atomically (temp file + rename). The
manifest is an **ordered list** of segment entries. It is an index for enumeration, **not** the
root of trust — tamper-evidence is cryptographic (see Integrity risks).

Top-level manifest object:

| Field | Type | Meaning |
|-------|------|---------|
| `format` | string | Literal manifest format tag (e.g. `audit-trail-manifest-v1`). |
| `version` | int | Literal `1`. |
| `segments` | array | Ordered list of segment entries (oldest first); the active segment may be represented as the trailing/open entry or omitted, settled in task 015. |

Each `segments[]` entry:

| Field | Type | Meaning |
|-------|------|---------|
| `segment` | string | Segment filename (e.g. `audit.log.001`). |
| `first_seq` | int | Global `seq` of the segment's first record. |
| `last_seq` | int | Global `seq` of the segment's last record. |
| `start_prev_hash` | string | The `prev_hash` the segment's first record must carry (Genesis for segment 0; previous segment's end hash otherwise). |
| `end_hash` | string | The segment's last record's `hash` (the chain head as of this segment's end). |
| `issued_at` | int | Unix seconds when the segment was rotated out. |

`Verify()` cross-checks every record of every segment against these recorded values; the
manifest cannot make a tampered segment pass, and a tampered manifest cannot make an intact
chain fail silently (a mismatch surfaces as `valid:false`).

## Integrity risks

- **Seam tamper-detection (Verify silently missing a boundary break).** Risk: a reordered or
  dropped-middle segment leaves a chain that looks locally intact within each file. **Mitigation:**
  the cross-segment **seam check** — segment N+1's first `prev_hash` must equal segment N's last
  `hash`. A reorder or a dropped-middle segment breaks this link and `Verify()` returns
  `valid:false`. Task 016 must prove this with a dedicated test.
- **Manifest integrity (drop / reorder / field tamper).** The manifest is only an index, so the
  cryptographic chain catches manipulation:
  - *Segment listed in manifest but missing from disk* → `Verify()` returns `valid:false`
    naming the missing file.
  - *Attacker drops the manifest **and** old segments to truncate the log* → the surviving
    active segment's first record has `prev_hash != Genesis`, so `Verify()` reports a broken
    link at `seq 0` (the chain does not start at Genesis). **This property is explicit:** a
    truncated chain that does not begin at Genesis is invalid by definition.
  - *Reordered / dropped-middle segment* → seam check breaks (above).
  - *Manifest entry field tampered (e.g. recorded `end_hash` or seq range)* → `Verify()`
    cross-checks the manifest's recorded `end_hash`/`first_seq`/`last_seq`/`start_prev_hash`
    against the actual walked segment contents; any divergence is `valid:false`.
- **Concurrent rotation vs emit (race).** Risk: an `Emit()` interleaving with the rename +
  manifest write could lose a record or write to a renamed file. **Mitigation:** `Rotate()`
  holds `c.mu` across the whole operation; `Emit()` and `BuildCheckpointPayload()` also take
  `c.mu`. All writes are serialized through the single mutex (single-writer invariant). The
  manifest is written atomically (temp + rename) so a crash never leaves a half-written index.
- **Re-anchoring freshness.** Risk: a per-segment checkpoint signed at rotation could go stale
  relative to Rekor, or an operator forgets to anchor. **Mitigation:** the local signed
  checkpoint is created synchronously at the boundary and commits to the exact boundary head, so
  it is always fresh *as of that boundary*; Rekor anchoring is decoupled and asynchronous via
  the existing `checkpoint anchor` surface. Rotation never blocks on the network, and an
  un-anchored segment is still locally verifiable by its signed checkpoint.

## Required verification evidence for implementation tasks 015–018

Later tasks must provide the following test evidence:

- **Cross-segment tamper detection (task 016).** A test that tampers a record in a
  rotated-out segment (not the active one) and asserts `Verify()` returns `valid:false` with
  `tamper_detected_at` at the global seq of the tampered record.
- **Seam continuity (tasks 015 + 016).** A test proving the first record of each segment N+1
  carries `prev_hash` equal to segment N's last `hash` (enforced at rotation), and a test that
  corrupts the seam link and asserts `Verify()` reports a broken link at the seam.
- **Single-writer isolation (task 015 / 017).** A concurrency test that runs `Emit()` and
  `Rotate()` against the same `Chain` and asserts no record is lost, no record is written to a
  renamed file, and the resulting multi-segment log verifies.
- **Dropped / reordered segment detection (task 016).** Tests that (a) delete a segment file
  listed in the manifest → `valid:false` naming the missing file; (b) reorder two segment
  entries / swap two segment files → seam check fails; (c) truncate by dropping the manifest and
  old segments → `valid:false` because the surviving chain does not start at Genesis; (d) tamper
  a manifest `end_hash`/seq field → `valid:false` from the manifest-vs-content cross-check.
- **Degenerate single-segment equivalence (tasks 016 + 018).** A test proving a never-rotated
  log produces `Verify()` results and bytes identical to today's single-file behavior, plus
  deterministic committed fixtures for both the single-segment and a multi-segment chain.
- **Re-anchoring at boundaries (task 015).** A test proving each rotated-out segment gets a
  valid ADR-003 signed checkpoint over the cumulative boundary head, created without any network
  call.

## Consequences

- A long-running log can be split into archivable, individually-checkpointed segments without
  changing the frozen v1 `emit`/`verify` contract and without a contracts bump.
- The hash chain remains the single root of trust; the manifest is a convenience index and
  cannot weaken tamper-evidence. Truncation, reorder, drop, and field-tamper attacks are all
  caught cryptographically.
- `Verify()` cost is unchanged per byte but now spans multiple files; a multi-segment verify
  reads every segment from disk in order (no in-memory shortcuts), preserving the
  read-from-disk invariant.
- The emit hot path is untouched: rotation is an explicit, mutex-guarded operation, never an
  implicit side effect of `Emit()`. This is harder for operators who expect automatic rotation
  — they must invoke `rotate` (manually or via a scheduler) — which is a deliberate trade for
  keeping emit simple and the seam off the hot path.
- Raw segment byte size is not directly bounded (event-count trigger); operators who need a
  hard byte cap will need a future size-based trigger, which can be added additively.
- The verification walker becomes parameterized (starting `prev_hash` + offset), which is
  slightly more code than the single-file walker but is reused by checkpointing and cross-segment
  verify. The degenerate defaults keep the single-file path byte-identical.
- Standard-library-only design is preserved: rotation uses `os` rename/atomic-write and the
  existing `crypto/ed25519` checkpoint machinery; no new dependency.

## Links

- [ADR-001](001-foundational-stack.md) — foundational architecture and v1+ roadmap.
- [ADR-003](003-signed-checkpoints.md) — signed checkpoints (reused at segment boundaries).
- [ADR-004](004-witness-anchoring.md) — Rekor anchoring (asynchronous, out of scope for rotation).
- [docs/CONTRACT.md](../../CONTRACT.md) — frozen v1 emit/verify contract (unchanged).
- [docs/spec/configuration.md](../../spec/configuration.md) — rotation threshold default (task 017).
- [docs/tasks/backlog/015-segment-and-manifest-core.md](../../tasks/backlog/015-segment-and-manifest-core.md)
- [docs/tasks/backlog/016-cross-segment-verify.md](../../tasks/backlog/016-cross-segment-verify.md)
- [docs/tasks/backlog/017-rotation-runtime-surface.md](../../tasks/backlog/017-rotation-runtime-surface.md)
- [docs/tasks/backlog/018-rotation-fitness-and-fixtures.md](../../tasks/backlog/018-rotation-fitness-and-fixtures.md)
