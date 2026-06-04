package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHashedRekordJSON(t *testing.T) {
	// TC-010-01: Unit tests verify the hashedrekord JSON structure matches Sigstore Rekor schema specifications.
	privateKey, publicKey := deterministicCheckpointKey(1)
	payload := validCheckpointPayload()
	checkpoint, err := SignCheckpointPayload(payload, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	pubDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})

	payloadBytes, err := CheckpointPayloadBytes(checkpoint.Payload)
	if err != nil {
		t.Fatal(err)
	}
	hashVal := sha256.Sum256(payloadBytes)
	hexHash := hex.EncodeToString(hashVal[:])

	sigBytes, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature.Sig)
	if err != nil {
		t.Fatal(err)
	}
	b64Sig := base64.StdEncoding.EncodeToString(sigBytes)
	b64PubKey := base64.StdEncoding.EncodeToString(pubPEM)

	var reqData HashedRekord
	reqData.Kind = "hashedrekord"
	reqData.APIVersion = "0.0.1"
	reqData.Spec.Data.Hash.Algorithm = "sha256"
	reqData.Spec.Data.Hash.Value = hexHash
	reqData.Spec.Signature.Content = b64Sig
	reqData.Spec.Signature.PublicKey.Content = b64PubKey

	reqBytes, err := json.Marshal(reqData)
	if err != nil {
		t.Fatal(err)
	}

	// Verify JSON structure using a map
	var raw map[string]any
	if err := json.Unmarshal(reqBytes, &raw); err != nil {
		t.Fatal(err)
	}

	if raw["kind"] != "hashedrekord" {
		t.Errorf("expected kind 'hashedrekord', got %v", raw["kind"])
	}
	if raw["apiVersion"] != "0.0.1" {
		t.Errorf("expected apiVersion '0.0.1', got %v", raw["apiVersion"])
	}

	spec, ok := raw["spec"].(map[string]any)
	if !ok {
		t.Fatal("spec is missing or not a map")
	}

	data, ok := spec["data"].(map[string]any)
	if !ok {
		t.Fatal("spec.data is missing or not a map")
	}

	hash, ok := data["hash"].(map[string]any)
	if !ok {
		t.Fatal("spec.data.hash is missing or not a map")
	}
	if hash["algorithm"] != "sha256" {
		t.Errorf("expected algorithm 'sha256', got %v", hash["algorithm"])
	}
	if hash["value"] != hexHash {
		t.Errorf("expected hash value %q, got %v", hexHash, hash["value"])
	}

	signature, ok := spec["signature"].(map[string]any)
	if !ok {
		t.Fatal("spec.signature is missing or not a map")
	}
	if signature["content"] != b64Sig {
		t.Errorf("expected signature content %q, got %v", b64Sig, signature["content"])
	}

	publicKeyMap, ok := signature["publicKey"].(map[string]any)
	if !ok {
		t.Fatal("spec.signature.publicKey is missing or not a map")
	}
	if publicKeyMap["content"] != b64PubKey {
		t.Errorf("expected publicKey content %q, got %v", b64PubKey, publicKeyMap["content"])
	}
}

func TestSubmitCheckpointSuccess(t *testing.T) {
	// TC-010-02: Mock HTTP server tests verify that the client parses successful Rekor responses into RekorReceipt correctly.
	privateKey, publicKey := deterministicCheckpointKey(1)
	payload := validCheckpointPayload()
	checkpoint, err := SignCheckpointPayload(payload, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	pubDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})

	expectedEntryID := "d9e03d40608cfb2ea24c94d0bc5069a5a3a7f8b9e6022e6b2c8a24c94d0bc506"
	expectedLogID := "c0ee4787a2da8cb5f41fa6e0a8b9f0ee"
	expectedLogIndex := int64(1234)
	expectedIntegratedTime := int64(1684345600)
	expectedSET := "TUlJQkpnWUpLb1pJaHZjTkFRY0NvSUlCRlRjQ0FVRUNBUU14QURBTkJna3Foa2lHOXcwQkFRVUZBREEx"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/log/entries" {
			t.Errorf("expected path /api/v1/log/entries, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected JSON Content-Type, got %s", r.Header.Get("Content-Type"))
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var req HashedRekord
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("failed to unmarshal request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		respJSON := fmt.Sprintf(`{
			%q: {
				"body": "ey...",
				"integratedTime": %d,
				"logID": %q,
				"logIndex": %d,
				"verification": {
					"signedEntryTimestamp": %q
				}
			}
		}`, expectedEntryID, expectedIntegratedTime, expectedLogID, expectedLogIndex, expectedSET)
		w.Write([]byte(respJSON))
	}))
	defer server.Close()

	client := NewRekorClient(server.URL)
	receipt, err := client.SubmitCheckpoint(context.Background(), checkpoint, pubPEM)
	if err != nil {
		t.Fatalf("SubmitCheckpoint failed: %v", err)
	}

	if receipt.EntryID != expectedEntryID {
		t.Errorf("expected EntryID %q, got %q", expectedEntryID, receipt.EntryID)
	}
	if receipt.LogID != expectedLogID {
		t.Errorf("expected LogID %q, got %q", expectedLogID, receipt.LogID)
	}
	if receipt.LogIndex != expectedLogIndex {
		t.Errorf("expected LogIndex %d, got %d", expectedLogIndex, receipt.LogIndex)
	}
	if receipt.IntegratedTime != expectedIntegratedTime {
		t.Errorf("expected IntegratedTime %d, got %d", expectedIntegratedTime, receipt.IntegratedTime)
	}
	if receipt.SignedEntryTimestamp != expectedSET {
		t.Errorf("expected SignedEntryTimestamp %q, got %q", expectedSET, receipt.SignedEntryTimestamp)
	}
}

func TestSubmitCheckpointTimeout(t *testing.T) {
	// TC-010-03: Mock HTTP server tests verify the client fails closed on connection timeouts.
	privateKey, publicKey := deterministicCheckpointKey(1)
	checkpoint := mustSignCheckpoint(t, validCheckpointPayload(), privateKey)

	pubDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(6 * time.Second):
			w.WriteHeader(http.StatusCreated)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()

	client := NewRekorClient(server.URL)
	start := time.Now()
	_, err = client.SubmitCheckpoint(context.Background(), checkpoint, pubPEM)
	duration := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	if duration >= 6*time.Second {
		t.Errorf("expected request to timeout at 5 seconds, took %v", duration)
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "Client.Timeout") {
		t.Errorf("expected timeout error message, got %q", err.Error())
	}
}

func TestSubmitCheckpointErrors(t *testing.T) {
	// TC-010-04: Verify the client returns appropriate errors for network timeouts, bad request bodies, and non-2xx HTTP responses.
	privateKey, publicKey := deterministicCheckpointKey(1)
	checkpoint := mustSignCheckpoint(t, validCheckpointPayload(), privateKey)

	pubDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})

	t.Run("HTTP 400 Bad Request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid signature"))
		}))
		defer server.Close()

		client := NewRekorClient(server.URL)
		_, err := client.SubmitCheckpoint(context.Background(), checkpoint, pubPEM)
		if err == nil {
			t.Fatal("expected error on 400 Bad Request, got nil")
		}
		if !strings.Contains(err.Error(), "status 400") || !strings.Contains(err.Error(), "invalid signature") {
			t.Errorf("expected error message to contain status and body, got %q", err.Error())
		}
	})

	t.Run("HTTP 500 Internal Server Error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal database error"))
		}))
		defer server.Close()

		client := NewRekorClient(server.URL)
		_, err := client.SubmitCheckpoint(context.Background(), checkpoint, pubPEM)
		if err == nil {
			t.Fatal("expected error on 500 Internal Server Error, got nil")
		}
		if !strings.Contains(err.Error(), "status 500") || !strings.Contains(err.Error(), "internal database error") {
			t.Errorf("expected error message to contain status and body, got %q", err.Error())
		}
	})

	t.Run("Malformed JSON Response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("{invalid json"))
		}))
		defer server.Close()

		client := NewRekorClient(server.URL)
		_, err := client.SubmitCheckpoint(context.Background(), checkpoint, pubPEM)
		if err == nil {
			t.Fatal("expected error on malformed JSON response, got nil")
		}
		if !strings.Contains(err.Error(), "decode response") {
			t.Errorf("expected decode response error message, got %q", err.Error())
		}
	})

	t.Run("Empty JSON Response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("{}"))
		}))
		defer server.Close()

		client := NewRekorClient(server.URL)
		_, err := client.SubmitCheckpoint(context.Background(), checkpoint, pubPEM)
		if err == nil {
			t.Fatal("expected error on empty JSON response, got nil")
		}
		if !strings.Contains(err.Error(), "empty response") {
			t.Errorf("expected empty response error message, got %q", err.Error())
		}
	})
}
