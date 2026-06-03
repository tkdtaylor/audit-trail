# Configuration

**Project:** audit-trail · **Last updated:** 2026-06-03

audit-trail has **no config file and reads no environment variables**. All runtime behavior is
controlled by CLI flags ([main.go](../../main.go)).

## Runtime flags

| Flag | Subcommands | Default | Meaning |
|------|-------------|---------|---------|
| `--logfile` | serve, emit, verify | `audit.log` | Path to the JSONL chain. Created `0600` if absent. |
| `--socket` | serve | *(required)* | Unix socket path. Stale socket is removed, then `chmod 0600`. |
| `--actor` | emit | `""` | Event `actor`. |
| `--action` | emit | `""` | Event `action`. |
| `--target` | emit | `""` | Event `target`. |
| `--decision` | emit | `""` | Event `decision`; omitted from the event when empty. |

## File permissions

| Artifact | Mode | Set in |
|----------|------|--------|
| logfile | `0600` (owner read/write) | chain.go `loadState`/`Emit` `OpenFile` |
| socket | `0600` | ipc.go `serve` |

## Secrets

**None.** audit-trail stores no credentials and authenticates no callers. Access control is
entirely filesystem/socket permissions — anyone who can write the socket or the logfile can
emit. (Audited `context`/`target` values should not contain secrets; that is the emitter's
responsibility.)

## Scanner buffer limits

`loadState` and `Verify` use a `bufio.Scanner` with a 16 MiB max line size (1 MiB initial).
A single record larger than 16 MiB would fail to scan. Not a tunable today.

> **TODO (user confirm):** Is the 16 MiB per-line ceiling an intended hard limit, or should it
> be configurable / removed for very large `context` blobs? Candidate fitness/limit decision.
