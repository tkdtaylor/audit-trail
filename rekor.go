// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// HashedRekordSpec represents the inner spec of a Rekor hashedrekord entry.
type HashedRekordSpec struct {
	Data struct {
		Hash struct {
			Algorithm string `json:"algorithm"`
			Value     string `json:"value"`
		} `json:"hash"`
	} `json:"data"`
	Signature struct {
		Content   string `json:"content"`
		PublicKey struct {
			Content string `json:"content"`
		} `json:"publicKey"`
	} `json:"signature"`
}

// HashedRekord represents the top-level structure of a Rekor hashedrekord request.
type HashedRekord struct {
	Kind       string           `json:"kind"`
	APIVersion string           `json:"apiVersion"`
	Spec       HashedRekordSpec `json:"spec"`
}

// RekorReceipt represents the inclusion proof and metadata returned from Rekor.
type RekorReceipt struct {
	LogID                string `json:"log_id"`
	LogIndex             int64  `json:"log_index"`
	IntegratedTime       int64  `json:"integrated_time"`
	SignedEntryTimestamp string `json:"signed_entry_timestamp"`
	EntryID              string `json:"entry_id"`
}

// RekorClient is a client for submitting signed checkpoints to Rekor.
type RekorClient struct {
	URL        string
	HTTPClient *http.Client
}

// NewRekorClient creates a new RekorClient with the specified endpoint URL.
func NewRekorClient(url string) *RekorClient {
	return &RekorClient{
		URL: url,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// SubmitCheckpoint submits a signed checkpoint to Rekor and returns the receipt.
func (rc *RekorClient) SubmitCheckpoint(ctx context.Context, checkpoint SignedCheckpoint, publicKeyPEM []byte) (RekorReceipt, error) {
	// 1. Calculate SHA-256 of the canonical checkpoint payload bytes
	payloadBytes, err := CheckpointPayloadBytes(checkpoint.Payload)
	if err != nil {
		return RekorReceipt{}, fmt.Errorf("rekor: get payload bytes: %w", err)
	}
	hashVal := sha256.Sum256(payloadBytes)
	hexHash := hex.EncodeToString(hashVal[:])

	// 2. Decode the base64url-encoded signature and re-encode to standard base64
	sigBytes, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature.Sig)
	if err != nil {
		return RekorReceipt{}, fmt.Errorf("rekor: decode signature: %w", err)
	}
	b64Sig := base64.StdEncoding.EncodeToString(sigBytes)

	// 3. Base64-encode the public key PEM bytes
	b64PubKey := base64.StdEncoding.EncodeToString(publicKeyPEM)

	// 4. Construct the hashedrekord payload
	var reqData HashedRekord
	reqData.Kind = "hashedrekord"
	reqData.APIVersion = "0.0.1"
	reqData.Spec.Data.Hash.Algorithm = "sha256"
	reqData.Spec.Data.Hash.Value = hexHash
	reqData.Spec.Signature.Content = b64Sig
	reqData.Spec.Signature.PublicKey.Content = b64PubKey

	// 5. Serialize request payload
	reqBytes, err := json.Marshal(reqData)
	if err != nil {
		return RekorReceipt{}, fmt.Errorf("rekor: marshal request: %w", err)
	}

	// 6. Send POST request
	reqURL := fmt.Sprintf("%s/api/v1/log/entries", rc.URL)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader(reqBytes))
	if err != nil {
		return RekorReceipt{}, fmt.Errorf("rekor: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := rc.HTTPClient.Do(req)
	if err != nil {
		return RekorReceipt{}, fmt.Errorf("rekor: POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return RekorReceipt{}, fmt.Errorf("rekor: server returned status %s: %s", resp.Status, string(bodyBytes))
	}

	// 7. Parse response
	var rekorResp map[string]struct {
		Body           any    `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
		Verification   struct {
			SignedEntryTimestamp string `json:"signedEntryTimestamp"`
		} `json:"verification"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rekorResp); err != nil {
		return RekorReceipt{}, fmt.Errorf("rekor: decode response: %w", err)
	}

	if len(rekorResp) == 0 {
		return RekorReceipt{}, errors.New("rekor: empty response")
	}

	// Retrieve the entry (there should only be one)
	for entryID, entry := range rekorResp {
		return RekorReceipt{
			LogID:                entry.LogID,
			LogIndex:             entry.LogIndex,
			IntegratedTime:       entry.IntegratedTime,
			SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
			EntryID:              entryID,
		}, nil
	}

	return RekorReceipt{}, errors.New("rekor: no entry found")
}

// ParseRekorPublicKeyPEM parses a PKIX public key (ECDSA, Ed25519, RSA, etc.) from a PEM-encoded block.
func ParseRekorPublicKeyPEM(pemBytes []byte) (crypto.PublicKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: public key is not PEM", errInvalidCheckpointKey)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("%w: public key has trailing data", errInvalidCheckpointKey)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: public key PEM type %q, want PUBLIC KEY", errInvalidCheckpointKey, block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse public key: %w", errInvalidCheckpointKey, err)
	}
	return key, nil
}

// LoadRekorPublicKey reads a PEM public key from a file path.
func LoadRekorPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Rekor public key: %w", err)
	}
	return ParseRekorPublicKeyPEM(data)
}

// CheckpointHashedRekord generates the HashedRekord structure for a given signed checkpoint and operator public key PEM.
func CheckpointHashedRekord(checkpoint SignedCheckpoint, publicKeyPEM []byte) (HashedRekord, error) {
	payloadBytes, err := CheckpointPayloadBytes(checkpoint.Payload)
	if err != nil {
		return HashedRekord{}, fmt.Errorf("rekor: get payload bytes: %w", err)
	}
	hashVal := sha256.Sum256(payloadBytes)
	hexHash := hex.EncodeToString(hashVal[:])

	sigBytes, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature.Sig)
	if err != nil {
		return HashedRekord{}, fmt.Errorf("rekor: decode signature: %w", err)
	}
	b64Sig := base64.StdEncoding.EncodeToString(sigBytes)
	b64PubKey := base64.StdEncoding.EncodeToString(publicKeyPEM)

	var reqData HashedRekord
	reqData.Kind = "hashedrekord"
	reqData.APIVersion = "0.0.1"
	reqData.Spec.Data.Hash.Algorithm = "sha256"
	reqData.Spec.Data.Hash.Value = hexHash
	reqData.Spec.Signature.Content = b64Sig
	reqData.Spec.Signature.PublicKey.Content = b64PubKey

	return reqData, nil
}

// CanonicalHashedRekordBytes returns the JCS-canonical bytes of the HashedRekord.
func CanonicalHashedRekordBytes(hr HashedRekord) ([]byte, error) {
	b, err := json.Marshal(hr)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return canonical(m)
}

// VerifyRekorReceiptOffline verifies the Rekor SET signature in the receipt offline.
func VerifyRekorReceiptOffline(receipt RekorReceipt, checkpoint SignedCheckpoint, operatorPubKeyPEM []byte, rekorPubKey crypto.PublicKey) error {
	// 1. Reconstruct the HashedRekord
	hr, err := CheckpointHashedRekord(checkpoint, operatorPubKeyPEM)
	if err != nil {
		return fmt.Errorf("reconstruct hashedrekord: %w", err)
	}

	// 2. Canonicalize HashedRekord to get canonical bytes
	canonicalBytes, err := CanonicalHashedRekordBytes(hr)
	if err != nil {
		return fmt.Errorf("canonicalize hashedrekord: %w", err)
	}

	// 3. Construct the LogEntryAnon signed payload
	m := map[string]any{
		"body":           base64.StdEncoding.EncodeToString(canonicalBytes),
		"integratedTime": receipt.IntegratedTime,
		"logID":          receipt.LogID,
		"logIndex":       receipt.LogIndex,
	}

	setPayloadBytes, err := canonical(m)
	if err != nil {
		return fmt.Errorf("canonicalize SET payload: %w", err)
	}

	// 4. Decode the SET signature
	sigBytes, err := base64.StdEncoding.DecodeString(receipt.SignedEntryTimestamp)
	if err != nil {
		return fmt.Errorf("decode SET signature: %w", err)
	}

	// 5. Verify the signature using Rekor's public key
	switch k := rekorPubKey.(type) {
	case *ecdsa.PublicKey:
		hash := sha256.Sum256(setPayloadBytes)
		if !ecdsa.VerifyASN1(k, hash[:], sigBytes) {
			return errors.New("invalid Rekor SET ECDSA signature")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, setPayloadBytes, sigBytes) {
			return errors.New("invalid Rekor SET Ed25519 signature")
		}
		return nil
	case *rsa.PublicKey:
		hash := sha256.Sum256(setPayloadBytes)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, hash[:], sigBytes); err == nil {
			return nil
		}
		if err := rsa.VerifyPSS(k, crypto.SHA256, hash[:], sigBytes, nil); err == nil {
			return nil
		}
		return errors.New("invalid Rekor SET RSA signature")
	default:
		return fmt.Errorf("unsupported Rekor public key type: %T", rekorPubKey)
	}
}

type rekorEntryResponse struct {
	Body           any    `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"verification"`
}

func (rc *RekorClient) fetchEntry(ctx context.Context, path string) (RekorReceipt, string, error) {
	reqURL := fmt.Sprintf("%s%s", rc.URL, path)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return RekorReceipt{}, "", fmt.Errorf("rekor: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := rc.HTTPClient.Do(req)
	if err != nil {
		return RekorReceipt{}, "", fmt.Errorf("rekor: GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return RekorReceipt{}, "", fmt.Errorf("rekor: server returned status %s: %s", resp.Status, string(bodyBytes))
	}

	var rekorResp map[string]rekorEntryResponse
	if err := json.NewDecoder(resp.Body).Decode(&rekorResp); err != nil {
		return RekorReceipt{}, "", fmt.Errorf("rekor: decode response: %w", err)
	}

	if len(rekorResp) == 0 {
		return RekorReceipt{}, "", errors.New("rekor: empty response")
	}

	for entryID, entry := range rekorResp {
		receipt := RekorReceipt{
			LogID:                entry.LogID,
			LogIndex:             entry.LogIndex,
			IntegratedTime:       entry.IntegratedTime,
			SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
			EntryID:              entryID,
		}
		var bodyStr string
		switch b := entry.Body.(type) {
		case string:
			bodyStr = b
		default:
			bBytes, err := json.Marshal(b)
			if err != nil {
				return RekorReceipt{}, "", fmt.Errorf("rekor: marshal body: %w", err)
			}
			bodyStr = base64.StdEncoding.EncodeToString(bBytes)
		}
		return receipt, bodyStr, nil
	}

	return RekorReceipt{}, "", errors.New("rekor: no entry found")
}

// GetEntryByID fetches a Rekor entry by its UUID.
func (rc *RekorClient) GetEntryByID(ctx context.Context, entryID string) (RekorReceipt, string, error) {
	return rc.fetchEntry(ctx, "/api/v1/log/entries/"+entryID)
}

// GetEntryByIndex fetches a Rekor entry by its log index.
func (rc *RekorClient) GetEntryByIndex(ctx context.Context, logIndex int64) (RekorReceipt, string, error) {
	return rc.fetchEntry(ctx, fmt.Sprintf("/api/v1/log/entries?logIndex=%d", logIndex))
}

// ExtractOperatorPublicKeyPEM decodes the entry body and extracts the operator public key PEM.
func ExtractOperatorPublicKeyPEM(fetchedBodyStr string) ([]byte, error) {
	bodyBytes, err := base64.StdEncoding.DecodeString(fetchedBodyStr)
	if err != nil {
		return nil, fmt.Errorf("decode fetched entry body base64: %w", err)
	}

	var fetchedHR HashedRekord
	if err := json.Unmarshal(bodyBytes, &fetchedHR); err != nil {
		return nil, fmt.Errorf("parse fetched entry body JSON: %w", err)
	}

	pubKeyPEM, err := base64.StdEncoding.DecodeString(fetchedHR.Spec.Signature.PublicKey.Content)
	if err != nil {
		return nil, fmt.Errorf("decode fetched operator public key PEM: %w", err)
	}

	return pubKeyPEM, nil
}

// VerifyRekorReceiptOnline performs offline verification, then fetches the entry from Rekor and validates that it matches.
func (rc *RekorClient) VerifyRekorReceiptOnline(ctx context.Context, receipt RekorReceipt, checkpoint SignedCheckpoint, operatorPubKeyPEM []byte, rekorPubKey crypto.PublicKey) error {
	// 1. Fetch the entry from Rekor (try by EntryID/UUID first, then fallback to LogIndex)
	var fetchedReceipt RekorReceipt
	var fetchedBodyStr string
	var err error
	if receipt.EntryID != "" {
		fetchedReceipt, fetchedBodyStr, err = rc.GetEntryByID(ctx, receipt.EntryID)
	} else {
		fetchedReceipt, fetchedBodyStr, err = rc.GetEntryByIndex(ctx, receipt.LogIndex)
	}
	if err != nil {
		return fmt.Errorf("fetch entry from Rekor: %w", err)
	}

	// 2. If operatorPubKeyPEM is empty, extract it from the fetched entry body
	if len(operatorPubKeyPEM) == 0 {
		operatorPubKeyPEM, err = ExtractOperatorPublicKeyPEM(fetchedBodyStr)
		if err != nil {
			return fmt.Errorf("extract operator public key: %w", err)
		}
	}

	// 3. Perform offline verification
	if err := VerifyRekorReceiptOffline(receipt, checkpoint, operatorPubKeyPEM, rekorPubKey); err != nil {
		return fmt.Errorf("offline verification failed: %w", err)
	}

	// 4. Compare metadata fields
	if fetchedReceipt.LogID != receipt.LogID {
		return fmt.Errorf("log ID mismatch: local %q, fetched %q", receipt.LogID, fetchedReceipt.LogID)
	}
	if fetchedReceipt.LogIndex != receipt.LogIndex {
		return fmt.Errorf("log index mismatch: local %d, fetched %d", receipt.LogIndex, fetchedReceipt.LogIndex)
	}
	if fetchedReceipt.IntegratedTime != receipt.IntegratedTime {
		return fmt.Errorf("integrated time mismatch: local %d, fetched %d", receipt.IntegratedTime, fetchedReceipt.IntegratedTime)
	}
	if fetchedReceipt.SignedEntryTimestamp != receipt.SignedEntryTimestamp {
		return fmt.Errorf("SET signature mismatch: local %q, fetched %q", receipt.SignedEntryTimestamp, fetchedReceipt.SignedEntryTimestamp)
	}

	// 5. Decode and parse the fetched body
	bodyBytes, err := base64.StdEncoding.DecodeString(fetchedBodyStr)
	if err != nil {
		return fmt.Errorf("decode fetched entry body base64: %w", err)
	}

	var fetchedHR HashedRekord
	if err := json.Unmarshal(bodyBytes, &fetchedHR); err != nil {
		return fmt.Errorf("parse fetched entry body JSON: %w", err)
	}

	// 6. Reconstruct local HashedRekord
	localHR, err := CheckpointHashedRekord(checkpoint, operatorPubKeyPEM)
	if err != nil {
		return fmt.Errorf("reconstruct local hashedrekord: %w", err)
	}

	// 7. Compare HashedRekord fields
	if fetchedHR.Kind != localHR.Kind {
		return fmt.Errorf("entry kind mismatch: expected %q, got %q", localHR.Kind, fetchedHR.Kind)
	}
	if fetchedHR.APIVersion != localHR.APIVersion {
		return fmt.Errorf("entry API version mismatch: expected %q, got %q", localHR.APIVersion, fetchedHR.APIVersion)
	}
	if fetchedHR.Spec.Data.Hash.Algorithm != localHR.Spec.Data.Hash.Algorithm {
		return fmt.Errorf("hash algorithm mismatch: expected %q, got %q", localHR.Spec.Data.Hash.Algorithm, fetchedHR.Spec.Data.Hash.Algorithm)
	}
	if fetchedHR.Spec.Data.Hash.Value != localHR.Spec.Data.Hash.Value {
		return fmt.Errorf("checkpoint hash mismatch: expected %q, got %q", localHR.Spec.Data.Hash.Value, fetchedHR.Spec.Data.Hash.Value)
	}
	if fetchedHR.Spec.Signature.Content != localHR.Spec.Signature.Content {
		return fmt.Errorf("checkpoint signature mismatch: expected %q, got %q", localHR.Spec.Signature.Content, fetchedHR.Spec.Signature.Content)
	}
	if fetchedHR.Spec.Signature.PublicKey.Content != localHR.Spec.Signature.PublicKey.Content {
		return fmt.Errorf("operator public key mismatch: expected %q, got %q", localHR.Spec.Signature.PublicKey.Content, fetchedHR.Spec.Signature.PublicKey.Content)
	}

	return nil
}
