# Test spec: 011 - offline and online anchor verification

## Scope

Implement offline verification of Rekor Signed Entry Timestamps (SET) and online log verification to ensure the anchored checkpoint is valid and matches the transparency log. Verify it with unit tests and a mock HTTP server.

## Requirements traced

- REQ-011-01: Support loading the Rekor server's verification public key from PEM format.
- REQ-011-02: Implement offline verification: decode and verify the `signed_entry_timestamp` (SET) signature over Rekor's commit payload using Rekor's public key.
- REQ-011-03: Implement online verification: fetch the entry from Rekor by index or ID and compare its hash/signature with the local checkpoint.
- REQ-011-04: Reject any mismatches or invalid signatures, ensuring the verification fails closed.

## Test cases

### TC-011-01 - Load Rekor server verification public key
- Command: Run unit tests for public key PEM loading.
- Expected:
  - Supports loading valid ECDSA and Ed25519 public keys from PEM.
  - Returns appropriate errors for invalid PEM blocks, wrong PEM types (e.g. PRIVATE KEY instead of PUBLIC KEY), empty files, or malformed key material.

### TC-011-02 - Offline verification of SET
- Command: Run offline verification unit tests.
- Expected:
  - Properly constructs the signed payload from the `RekorReceipt` fields (`body`, `integratedTime`, `logID`, `logIndex`) and JCS-canonicalizes it.
  - Verifies valid ECDSA and Ed25519 SET signatures successfully.
  - Fails verification if:
    - The signature bytes are modified.
    - Any of the receipt fields (`logID`, `logIndex`, `integratedTime`, `body` hash/sig) are modified.
    - An invalid or mismatched public key is used.
  - Fails closed with a error message or returns false/error.

### TC-011-03 - Online verification logic
- Command: Run online verification tests with a mock HTTP server.
- Expected:
  - Fetches the entry from the mock Rekor server using `GET /api/v1/log/entries/<entry_id>` or `GET /api/v1/log/entries?logIndex=<log_index>`.
  - Verifies that the fetched entry matches the local receipt and local checkpoint.
  - Verification fails if:
    - Rekor returns a different hash for the checkpoint.
    - Rekor returns different signature content.
    - Rekor returns a different public key.
    - Rekor returns mismatched metadata (`logID`, `logIndex`, `integratedTime`).
    - The server returns 404/500/timeout or malformed JSON.
