# Test spec: 010 - rekor client core

## Scope

Implement the Go client to submit a signed checkpoint to Rekor and parse the resulting receipt using only Go standard library components. Verify it with unit tests and a mock HTTP server.

## Requirements traced

- REQ-010-01: Define Go structures matching the Rekor `hashedrekord` JSON schema.
- REQ-010-02: Define the `RekorReceipt` struct for holding log index, integration time, log ID, SET, and entry ID.
- REQ-010-03: Implement the HTTP client logic to POST to Rekor's `/api/v1/log/entries` endpoint with a strict 5-second timeout.
- REQ-010-04: Verify the client returns appropriate errors for network timeouts, bad request bodies, and non-2xx HTTP responses.

## Test cases

### TC-010-01 - Go structure schema match
- Command: Run tests that validate `hashedrekord` JSON marshalling.
- Expected:
  - Marshalled JSON exactly matches the Sigstore Rekor `hashedrekord` JSON schema specifications.
  - Test verifies correct encoding of the payload hash (hex-encoded SHA-256), signature (standard base64), and public key (base64-encoded PEM).

### TC-010-02 - Mock server successful response parsing
- Command: Run mock HTTP server tests.
- Expected:
  - Mock server returns a successful 201 response with a sample Rekor entry JSON.
  - The client successfully parses the JSON response and populates all fields of the `RekorReceipt` struct correctly (log_index, integrated_time, log_id, signed_entry_timestamp, and entry_id).

### TC-010-03 - Timeout enforcement
- Command: Run mock HTTP server tests with simulated latency.
- Expected:
  - If the server response takes longer than 5 seconds, the HTTP request times out.
  - The client fails closed and returns a context deadline exceeded error or a timeout error.

### TC-010-04 - HTTP error handling
- Command: Run mock HTTP server tests returning 4xx and 5xx errors.
- Expected:
  - If the server returns non-2xx status (e.g. 400 Bad Request, 500 Internal Server Error), the client returns a detailed error message containing the response status and body, without panic.
