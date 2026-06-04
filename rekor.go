package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
