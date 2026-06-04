# Task 011 - offline and online anchor verification

## Goal

Implement offline verification of Rekor Signed Entry Timestamps (SET) and online log verification to ensure the anchored checkpoint is valid and matches the transparency log.

Design decision: [ADR-004](../../architecture/decisions/004-witness-anchoring.md).

## Requirements

- REQ-011-01: Support loading the Rekor server's verification public key from PEM format.
- REQ-011-02: Implement offline verification: decode and verify the `signed_entry_timestamp` (SET) signature over Rekor's commit payload using Rekor's public key.
- REQ-011-03: Implement online verification: fetch the entry from Rekor by index or ID and compare its hash/signature with the local checkpoint.
- REQ-011-04: Reject any mismatches or invalid signatures, ensuring the verification fails closed.

## Acceptance criteria

- TC-011-01: Unit tests verify loading valid and invalid Rekor public key PEM files.
- TC-011-02: Offline verification tests verify that modified SET signatures or modified checkpoint fields fail to verify.
- TC-011-03: Mock HTTP server tests verify that online verification fails if Rekor returns different entry data.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 010, because verification depends on parsing receipts and making HTTP requests.
