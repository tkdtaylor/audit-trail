# Architecture Diagrams

**Project:** audit-trail
**Last updated:** 2026-06-03

C4-structured Mermaid diagrams plus the primary runtime flows. See [overview.md](overview.md)
for prose context, [decisions/](decisions/) for ADRs, and [`../spec/architecture.md`](../spec/architecture.md)
for the structured element catalog these diagrams render.

These diagrams are part of the **authoritative spec**. Code changes that contradict a diagram
either invalidate the change or the diagram — one must be updated to match in the same commit.

GitHub and most IDE previewers render Mermaid natively; no build step required.

> **Scaling note.** audit-trail is a single deployable unit (one binary, two transports) with
> no external dependencies, so the Container and Component levels collapse into one diagram.

---

## 1. System Context — who uses it and what it touches

> The system as one box: the ecosystem blocks that emit events, the auditor who verifies, and
> the on-disk log. No external services — integrity is offline and self-contained.

```mermaid
C4Context
    title System Context for audit-trail

    Person(auditor, "Auditor / CI", "Runs verify() to confirm the chain is intact")
    System_Ext(emitters, "Ecosystem blocks", "vault, scanner, sandbox, … — emit events as they act")
    System(audit, "audit-trail", "Hash-chained, append-only forensic log")
    System_Ext(logfile, "JSONL logfile", "On-disk append-only chain (source of truth)")

    Rel(emitters, audit, "emit(event)", "CLI / Unix socket")
    Rel(auditor, audit, "verify()", "CLI / Unix socket")
    Rel(audit, logfile, "appends / re-reads", "filesystem")
```

---

## 2. Container + Component — inside the binary

> One binary, one Go package. Two transports (CLI, IPC) drive the same `Chain` core, which is
> the only thing that touches the logfile.

```mermaid
C4Container
    title Container/Component view of audit-trail

    Person(auditor, "Auditor / CI")
    System_Ext(emitters, "Ecosystem blocks")
    System_Ext(rekor, "Rekor Transparency Log")

    System_Boundary(b, "audit-trail binary") {
        Component(cli, "CLI", "main.go", "serve / emit / verify / checkpoint / rotate / query dispatch")
        Component(ipc, "IPC server", "ipc.go", "Unix socket dispatch for emit, verify, checkpoint, rotate, query")
        Component(chain, "Chain core", "chain.go", "Emit, Verify, loadState, hashRecord, mutex")
        Component(canon, "Canonicalizer", "canonical.go", "RFC 8785 / JCS encoding")
        Component(checkpoint, "Checkpoints", "checkpoint.go", "RFC 6962 STH signing and verification")
        Component(rekor_client, "Rekor client", "rekor.go", "Transparency log anchoring and receipt verification")
        Component(segment, "Log rotation", "segment.go", "Segment sealing, manifest, and cross-segment verification")
        Component(query, "Query engine", "query.go", "Filtered cross-segment scan and pagination")
    }

    ContainerDb(logfile, "JSONL logfile", "append-only", "one JSON record per line")

    Rel(emitters, ipc, "emit(event)", "JSON / Unix socket")
    Rel(emitters, cli, "emit", "argv")
    Rel(auditor, cli, "verify / checkpoint / rotate / query", "argv")
    Rel(auditor, ipc, "verify / checkpoint / rotate / query", "JSON / Unix socket")
    Rel(cli, chain, "Emit / Verify")
    Rel(ipc, chain, "Emit / Verify")
    Rel(cli, checkpoint, "create / verify / anchor")
    Rel(cli, segment, "Rotate")
    Rel(cli, query, "runQuery")
    Rel(ipc, checkpoint, "checkpoint_*")
    Rel(ipc, segment, "Rotate")
    Rel(ipc, query, "runQuery")
    Rel(chain, canon, "canonical(record)")
    Rel(chain, logfile, "append / re-read")
    Rel(segment, logfile, "archive / manifest")
    Rel(query, logfile, "read-only scan")
    Rel(rekor_client, rekor, "anchor / verify", "HTTPS")
```

**Key contracts**
- `Chain` is the **single writer**. One `sync.Mutex` serializes `Emit`; IPC goroutines funnel
  through it.
- `Verify()` reads the **logfile from disk**, never the in-memory `Chain` — this is what
  detects a tamper. (ADR-001)
- `canonical()` must stay byte-stable: sorted keys, no insignificant whitespace, shortest
  integers, no floats. Drift here silently breaks every hash. (ADR-001)

---

## 3. Primary runtime flow — emit then verify

```mermaid
sequenceDiagram
    autonumber
    participant E as Emitter
    participant C as Chain (chain.go)
    participant J as canonical (canonical.go)
    participant F as logfile (disk)

    Note over C,F: open: loadState() replays the JSONL → resumes seq + prevHash
    E->>C: Emit(event)
    C->>C: build record {seq, ts, actor, …, prev_hash}
    C->>J: canonical(record_without_hash)
    J-->>C: canonical bytes
    C->>C: hash = SHA256(prev_hash + bytes)
    C->>F: append "<json>\n" (O_APPEND)
    C->>C: advance seq, prevHash
    C-->>E: {seq, hash}

    Note over C,F: later — possibly a different process
    E->>C: Verify()
    C->>F: re-read every line
    loop each entry
        C->>C: check prev_hash links prior hash
        C->>J: recompute hash from content
        C->>C: compare to stored hash
    end
    C-->>E: {valid, tamper_detected_at, message}
```

---

## Shipped and future flows

Shipped flows implemented behind the contract seam:
- **Signed checkpoints (RFC 6962 STH):** checkpoint generation and witness anchoring (`checkpoint.go`, `rekor.go`, ADR-003, ADR-004).
- **Log rotation / checkpointing:** how rotated segments link back to predecessors and verify cross-segment (`segment.go`, ADR-005).
- **Indexed query API:** read-only filtered event queries across segments with verification status (`query.go`, ADR-006).

Future flows worth their own numbered section as the project grows toward the v1+ roadmap:
- **Pluggable backends:** the emit/verify seam fronting immudb or Postgres.

One concept per diagram. Split any diagram that mixes layout and runtime sequence.

---

## Maintaining these diagrams

- **Trigger to update:** a new transport, a new component file, a backend behind the seam, or
  an ADR that changes a diagrammed flow. Keep [`../spec/architecture.md`](../spec/architecture.md)
  in sync — the catalog and these diagrams describe the same elements.
- **Edit existing over adding new.** Duplicates rot independently.
- **Update the date at the top** when you change anything substantive.
