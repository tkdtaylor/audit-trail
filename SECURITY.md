# Security Policy

## Supported versions

audit-trail has not yet cut a tagged release. Until a `v1.0.0` ships, only the
current `main` branch receives security fixes. This table will be filled in once
releases begin.

| Version | Security fixes |
|---------|---------------|
| `main` (pre-release) | ✅ Yes |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
A public report exposes the flaw to everyone before a fix is available.

### Option 1 — GitHub private vulnerability reporting (preferred)

Use GitHub's built-in private advisory flow:
<https://github.com/tkdtaylor/audit-trail/security/advisories/new>

GitHub keeps the report confidential and notifies only maintainers.

### Option 2 — Email

Send a report to <tools@taylorguard.me> with:

- A concise description of the vulnerability
- Reproduction steps (emit/verify input, log/segment shape)
- The commit or `main` state you observed it on
- Your assessment of severity (CVSS or plain English is fine)
- Any suggested mitigations

Encrypt with PGP if you prefer — open an issue requesting a public key and
we will publish one.

## Response expectations

- **Acknowledgement:** within 7 days of receipt.
- **Status update:** within 30 days (triaged, confirmed, or declined with
  reasoning).
- **Fix shipped:** within 90 days for confirmed vulnerabilities. Critical
  issues (CVSS ≥ 9.0) target a 14-day patch window. If more time is needed
  we will coordinate a disclosure date with the reporter.

## Scope

**In scope:**

- The hash-chain integrity guarantee — any way to tamper with a logged record
  (insert, delete, reorder, or modify an event) without `verify` detecting it
- RFC 8785 / JCS canonicalization correctness (a canonicalization mismatch that
  lets two distinct payloads collide or bypass verification)
- The `emit`/`verify` API and the CLI + Unix-socket IPC surface (parsing,
  injection, path handling)
- Checkpoint signing / signature verification where wired (RFC 6962 STH path)

**Out of scope:**

- The test fixtures under `testdata/` (e.g. `fixture-private.pem`) — these are
  throwaway keys for tests, not production credentials
- Vulnerabilities in the ecosystem blocks consumed over their contracts
  (`policy-engine`, `agent-mesh`, `vault`) — report those to their repositories
- Bugs in upstream reference designs (sigstore/Rekor, immudb) or third-party
  libraries with no exploitable path through audit-trail
- Findings that require an already-compromised host or operator-supplied
  malicious configuration

## Recognition

Reporters are credited in the changelog and release notes unless they
request anonymity. We do not currently offer a bug bounty.

## Maintainer note

After merging this file, enable **Settings → Code security and analysis →
Private vulnerability reporting** in the GitHub repository settings so the
"Report a vulnerability" button is visible on the repo page.
