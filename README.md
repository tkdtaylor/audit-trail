# audit-trail — tamper-evident, hash-chained action log

The **spine** of the secure-agent ecosystem. Every block emits to it; nothing else is trusted to record what happened. It is a *forensic archive*, not observability telemetry — it must survive agent compromise.

- **Append-only & hash-chained:** `hash = SHA256( prev_hash + JCS(event) )`
- **Tamper-evident:** any alteration — down to a single byte — fails `verify()`
- **Deterministic & offline:** `verify()` walks the chain with no external oracle
- **Standalone:** any process or block can emit; CLI + Unix-socket IPC forms

> Prior-art verdict: **BUILD** the hash-chain (RFC 6962 pattern + RFC 8785/JCS canonicalization). sigstore/Rekor and immudb (both Apache-2.0) are reference designs + optional v1 pluggable backends. The value-add is the agent-centric event schema + deterministic verify + multi-block integration. **License: Apache-2.0.**

## Scope

**What audit-trail does:** a tamper-evident, hash-chained forensic log of agent actions, with an offline verify API.

**What it does *not* do (it records; others act on the record):**
- Detect rogue agents or cascading failures — external monitoring does
- Prevent or enforce actions → **[policy-engine](https://github.com/tkdtaylor/policy-engine)**
- Raise real-time alerts or trip kill-switches → observability tooling / **[agent-mesh](https://github.com/tkdtaylor/agent-mesh)**

`audit-trail` is one block in a composable secure-agent ecosystem — each block is standalone and independently usable, and composes with its siblings over published contracts rather than absorbing their responsibilities (no central "god object").

## Contract (interface-contracts.md §2, v1)

```
emit(event) -> { seq, hash }
event = { ts, actor, action, target, decision?, refs:[{type,id}], context?, prev_hash }
verify() -> { valid, tamper_detected_at, message }
```

Canonicalization is **RFC 8785 (JCS)** — validated by the tracer-bullet (decisions.md D2); audited events use integer/string values only (floats are kept out, the one JCS-divergence point).

## Build & run

```sh
go build ./...
go test ./...

audit-trail serve  --socket /run/audit.sock --logfile audit.log   # IPC daemon (hot path)
audit-trail emit   --logfile audit.log --actor vault --action resolve --target vault://x
audit-trail verify --logfile audit.log                            # exits non-zero on tamper
```

IPC request shape (newline-delimited JSON on the Unix socket): `{"op":"emit","event":{…}}`, `{"op":"verify"}`, `{"op":"ping"}`.

## Documentation

- [docs/architecture/overview.md](docs/architecture/overview.md) — system design and design principles
- [docs/architecture/diagrams.md](docs/architecture/diagrams.md) — C4 diagrams and runtime flows
- [docs/spec/SPEC.md](docs/spec/SPEC.md) — authoritative spec

## Status

🚧 **v0 implementation, v1 contract.** Functional emit/verify + RFC 8785 + IPC/CLI + tests (ported from the tracer-bullet reference). Deferred to v1+: signed checkpoints (RFC 6962 STH), witness/Rekor anchoring, log rotation, indexed query API, pluggable backends. See [docs/CONTRACT.md](docs/CONTRACT.md).

## Adapter seam & standards

Adopts **RFC 6962** (Merkle/transparency-log pattern), **RFC 8785** (canonical JSON),
**in-toto/SLSA** attestation refs in `refs`, **OpenTelemetry** logs as an optional export.
Pluggable backends behind the emit/verify seam: Rekor, immudb, PostgreSQL, SQLite.

## License

audit-trail is licensed under the **Apache License 2.0** — free to use, modify, and distribute, including in commercial and proprietary products. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

> **Security notice:** audit-trail is a security tool provided **as-is, without warranty**. It does not guarantee the security of any system. See the disclaimer in [NOTICE](NOTICE).

## Enterprise Support

Need hardened deployments, integration help, or a support SLA? **Commercial support and consulting are available.**

📧 Contact **[tools@taylorguard.me](mailto:tools@taylorguard.me)**

## Sponsorship

audit-trail is independent, open-source security tooling. If it saves you time or risk, consider sponsoring continued development:

- 💜 [GitHub Sponsors](https://github.com/sponsors/tkdtaylor)

## Contributing

Contributions are welcome and become part of the project under Apache-2.0. See [CONTRIBUTING.md](CONTRIBUTING.md). We use the **Developer Certificate of Origin (DCO)** — sign off your commits with `git commit -s`. No CLA required.
