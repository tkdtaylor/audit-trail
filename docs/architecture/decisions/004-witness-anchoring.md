# ADR-004 — Witness / Rekor Anchoring

**Status:** Proposed · **Date:** 2026-06-04

## Context

ADR-003 introduced signed checkpoints which commit to a specific log head (`tree_size`, `root_hash`, etc.) signed by the log operator. While this establishes authenticity and auditability, it does not prevent split-view attacks. A malicious log operator could sign two conflicting checkpoints for the same log, presenting different histories to different auditors.

To mitigate split-view attacks, checkpoints must be anchored to a globally consistent public ledger or witness. Rekor (part of the Sigstore project) is an open-source signature transparency log that provides an append-only, tamper-evident record of metadata. By submitting a signed checkpoint to Rekor, the checkpoint is assigned a globally synchronized log index and a Signed Entry Timestamp (SET). Emitters and verifiers can query Rekor to ensure they are looking at the same log head, making split-view attacks easily detectable.

## Decision

Introduce Witness/Rekor anchoring as an additive feature behind the existing emit/verify seam. All network interactions are asynchronous relative to the critical write path (`emit`); the daemon will never block client writes on network calls.

We will support the standard Rekor `hashedrekord` entry type.

### 1. Rekor Entry Schema (hashedrekord)

The `hashedrekord` type expects a SHA-256 hash of the data, the signature, and the signer's public key. We will format the request to Rekor's `POST /api/v1/log/entries` endpoint as follows:

```json
{
  "kind": "hashedrekord",
  "apiVersion": "0.0.1",
  "spec": {
    "data": {
      "hash": {
        "algorithm": "sha256",
        "value": "<hex-encoded SHA-256 of canonical checkpoint payload bytes>"
      }
    },
    "signature": {
      "content": "<base64-encoded signature bytes>",
      "publicKey": {
        "content": "<base64-encoded PEM public key bytes>"
      }
    }
  }
}
```

- **Hash Value**: The hex-encoded SHA-256 digest of the canonical checkpoint payload bytes (`JCS(checkpoint.payload)`).
- **Signature Content**: The raw signature bytes (base64-encoded, not base64url).
- **Public Key Content**: The PEM public key bytes (base64-encoded).

### 2. Rekor Receipt / Inclusion Proof

Upon successful submission, Rekor returns a JSON response containing an inclusion proof. We will decode and serialize this into a stable **Rekor Receipt** structure:

| Field | Type | Meaning |
|---|---|---|
| `log_id` | string | Rekor log identifier (hex string). |
| `log_index` | int64 | The sequential index of the entry in the Rekor log. |
| `integrated_time` | int64 | Unix time (seconds) when the entry was integrated. |
| `signed_entry_timestamp` | string | Base64-encoded SET signature signed by the Rekor server key. |
| `entry_id` | string | Unique Rekor entry identifier. |

We will define a `RekorReceipt` struct to store this proof locally on disk or return it over IPC.

### 3. Verification Rules

Anchor verification can be performed offline (fast) or online (thorough).

#### Offline Verification:
1. Load the Rekor public key.
2. Verify the checkpoint signature itself.
3. Construct the payload Rekor signed over: a combination of the entry's `log_index`, `integrated_time`, and the hashed rekord spec bytes.
4. Verify the `signed_entry_timestamp` signature against this payload using the Rekor public key.
   *(Note: This proves the Rekor server officially committed to this entry at that index.)*

#### Online Verification:
1. Perform offline verification.
2. Query Rekor's `GET /api/v1/log/entries/<entry_id>` or `GET /api/v1/log/entries?logIndex=<log_index>`.
3. Verify that the entry exists in Rekor and matches the local checkpoint hash, signature, and public key.

---

## Runtime Surface

### CLI

Add two subcommands to the `checkpoint` command group:

```bash
# Submit a checkpoint to Rekor and write the receipt
audit-trail checkpoint anchor \
  --checkpoint <path-to-checkpoint> \
  --rekor-url <rekor-endpoint-url> \
  --public-key <path-to-operator-public-pem> \
  [--out <path-to-receipt>]

# Verify a checkpoint along with its Rekor receipt
audit-trail checkpoint verify-anchor \
  --checkpoint <path-to-checkpoint> \
  --receipt <path-to-receipt> \
  --rekor-public-key <path-to-rekor-public-pem> \
  [--rekor-url <rekor-endpoint-url>] # Triggers online verification if URL is supplied
```

### IPC

To prevent SSRF and arbitrary local file read vulnerabilities, the daemon will not accept raw URLs or file paths in client requests. Instead, Rekor configuration is provided to the daemon at startup:

```bash
audit-trail serve \
  --socket /run/audit.sock \
  --logfile audit.log \
  --checkpoint-log-id prod \
  --checkpoint-signing-key /keys/signing.pem \
  --checkpoint-public-key /keys/public.pem \
  --rekor-url https://rekor.sigstore.dev \
  --rekor-public-key /keys/rekor-public.pem
```

#### IPC Commands:

| Request | Success Response | Error Response |
|---|---|---|
| `{"op":"checkpoint_anchor"}` | `RekorReceipt` object | `{error:{code,message,retryable}}` |
| `{"op":"checkpoint_verify","checkpoint":{...},"receipt":{...},"online":bool}` | `{"valid":bool,"signature_valid":bool,"rekor_valid":bool,"rekor_online_match":bool\|null,"message":"..."}` | `{error:{code,message,retryable}}` |

- If the daemon is started without `--rekor-url` or `--rekor-public-key`, calling `checkpoint_anchor` returns `{error:{code:"checkpoint_not_configured",message:"Rekor anchoring not configured",retryable:false}}`.

---

## Integrity & Security Risks

- **SSRF (Server-Side Request Forgery)**: Clients sending malicious URLs to the daemon's IPC could probe internal network services. **Mitigation**: The daemon only makes HTTP requests to the URL specified by the administrator in the `--rekor-url` startup flag.
- **IPC Key-Path Injection**: Clients specifying arbitrary public key paths could read files or verify with wrong keys. **Mitigation**: The daemon loads keys only from configuration paths provided at startup.
- **Network Hangs/Timeouts**: HTTP requests to external servers could hang and block connection handlers. **Mitigation**: All HTTP clients will have a strict, non-configurable 5-second timeout.
- **Write-path Blocking**: Emitters must never wait for Rekor. **Mitigation**: Emitters run completely offline. Anchoring is decoupled and executed asynchronously.

## Consequences

- Checkpoints can be cryptographically anchored to Rekor to prove existence at a specific time and prevent split-view attacks.
- Standard-library-only design is preserved using `net/http` and `encoding/json` standard packages.
- The daemon remains secure against SSRF and key-path injection.
- Emitters remain highly performant and offline-capable.

## Links

- [ADR-001](001-foundational-stack.md) — foundational architecture.
- [ADR-003](003-signed-checkpoints.md) — signed checkpoints.
- [docs/ROADMAP.md](../../ROADMAP.md) — v1+ items.
