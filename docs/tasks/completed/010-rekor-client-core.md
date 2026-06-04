# Task 010 - Rekor client and receipt core

## Goal

Implement the client logic to submit a signed checkpoint to Rekor and parse the resulting receipt using only Go standard library components.

Design decision: [ADR-004](../../architecture/decisions/004-witness-anchoring.md).

## Requirements

- REQ-010-01: Define Go structures matching the Rekor `hashedrekord` JSON schema (including signature, public key, and payload hash fields).
- REQ-010-02: Define the `RekorReceipt` struct for holding log index, integration time, log ID, SET, and entry ID.
- REQ-010-03: Implement the HTTP client logic to POST to Rekor's `/api/v1/log/entries` endpoint with a strict 5-second timeout.
- REQ-010-04: Verify the client returns appropriate errors for network timeouts, bad request bodies, and non-2xx HTTP responses.

## Acceptance criteria

- TC-010-01: Unit tests verify the `hashedrekord` JSON structure matches Sigstore Rekor schema specifications.
- TC-010-02: Mock HTTP server tests verify that the client parses successful Rekor responses into `RekorReceipt` correctly.
- TC-010-03: Mock HTTP server tests verify the client fails closed on connection timeouts or 4xx/5xx responses.
- `make check` and `make fitness` both exit 0.

## Dependencies

- Task 009, which establishes the design.
