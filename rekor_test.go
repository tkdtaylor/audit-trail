// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
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
	"os"
	"path/filepath"
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

func TestLoadRekorPublicKey(t *testing.T) {
	// TC-011-01: Unit tests verify loading valid and invalid Rekor public key PEM files.
	dir := t.TempDir()

	// 1. Valid ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaDer, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecdsaDer})
	ecdsaPath := filepath.Join(dir, "ecdsa.pem")
	if err := os.WriteFile(ecdsaPath, ecdsaPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	loadedECDSA, err := LoadRekorPublicKey(ecdsaPath)
	if err != nil {
		t.Fatalf("failed to load valid ECDSA key: %v", err)
	}
	if _, ok := loadedECDSA.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected ECDSA public key, got %T", loadedECDSA)
	}

	// 2. Valid Ed25519 key
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	_ = edPriv
	if err != nil {
		t.Fatal(err)
	}
	edDer, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	edPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDer})
	edPath := filepath.Join(dir, "ed25519.pem")
	if err := os.WriteFile(edPath, edPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	loadedEd, err := LoadRekorPublicKey(edPath)
	if err != nil {
		t.Fatalf("failed to load valid Ed25519 key: %v", err)
	}
	if _, ok := loadedEd.(ed25519.PublicKey); !ok {
		t.Fatalf("expected Ed25519 public key, got %T", loadedEd)
	}

	// 3. Error cases
	cases := []struct {
		name    string
		content []byte
	}{
		{
			name:    "not PEM",
			content: []byte("not pem"),
		},
		{
			name:    "wrong block type",
			content: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecdsaDer}),
		},
		{
			name:    "trailing data",
			content: append(ecdsaPEM, []byte("trailing")...),
		},
		{
			name:    "invalid public key DER",
			content: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid der")}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".pem")
			if err := os.WriteFile(path, tc.content, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadRekorPublicKey(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestVerifyRekorReceiptOffline(t *testing.T) {
	// TC-011-02: Offline verification tests verify that modified SET signatures or modified checkpoint fields fail to verify.
	rekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	operatorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operatorDer, err := x509.MarshalPKIXPublicKey(&operatorKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Sign a checkpoint
	opEdPriv, opEdPub := deterministicCheckpointKey(1)
	opEdPubDer, err := x509.MarshalPKIXPublicKey(opEdPub)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := mustSignCheckpoint(t, validCheckpointPayload(), opEdPriv)

	hr, err := CheckpointHashedRekord(checkpoint, opEdPubDer)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBytes, err := CanonicalHashedRekordBytes(hr)
	if err != nil {
		t.Fatal(err)
	}
	bodyStr := base64.StdEncoding.EncodeToString(canonicalBytes)

	logIndex := int64(42)
	integratedTime := int64(1700000000)
	logID := "c0ee4787a2da8cb5f41fa6e0a8b9f0ee"
	setSig := signMockSET(t, rekorKey, bodyStr, integratedTime, logID, logIndex)

	receipt := RekorReceipt{
		LogID:                logID,
		LogIndex:             logIndex,
		IntegratedTime:       integratedTime,
		SignedEntryTimestamp: setSig,
		EntryID:              "dummy-entry-id",
	}

	// 1. Success case
	err = VerifyRekorReceiptOffline(receipt, checkpoint, opEdPubDer, &rekorKey.PublicKey)
	if err != nil {
		t.Fatalf("offline verification failed: %v", err)
	}

	// 2. Mismatched/altered signature
	t.Run("altered signature", func(t *testing.T) {
		badSigBytes, err := base64.StdEncoding.DecodeString(receipt.SignedEntryTimestamp)
		if err != nil {
			t.Fatal(err)
		}
		badSigBytes[0] ^= 0xFF
		badReceipt := receipt
		badReceipt.SignedEntryTimestamp = base64.StdEncoding.EncodeToString(badSigBytes)
		err = VerifyRekorReceiptOffline(badReceipt, checkpoint, opEdPubDer, &rekorKey.PublicKey)
		if err == nil {
			t.Fatal("expected failure on altered signature, got nil")
		}
	})

	// 3. Altered checkpoint root hash
	t.Run("altered checkpoint root hash", func(t *testing.T) {
		badCheckpoint := checkpoint
		badCheckpoint.Payload.RootHash = strings.Repeat("2", 64)
		err = VerifyRekorReceiptOffline(receipt, badCheckpoint, opEdPubDer, &rekorKey.PublicKey)
		if err == nil {
			t.Fatal("expected failure on altered checkpoint payload, got nil")
		}
	})

	// 4. Altered receipt logIndex
	t.Run("altered receipt logIndex", func(t *testing.T) {
		badReceipt := receipt
		badReceipt.LogIndex = 999
		err = VerifyRekorReceiptOffline(badReceipt, checkpoint, opEdPubDer, &rekorKey.PublicKey)
		if err == nil {
			t.Fatal("expected failure on altered logIndex, got nil")
		}
	})

	// 5. Mismatched Rekor public key
	t.Run("mismatched public key", func(t *testing.T) {
		wrongRekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyRekorReceiptOffline(receipt, checkpoint, opEdPubDer, &wrongRekorKey.PublicKey)
		if err == nil {
			t.Fatal("expected failure on mismatched public key, got nil")
		}
	})

	// 6. Mismatched operator public key PEM
	t.Run("mismatched operator public key", func(t *testing.T) {
		err = VerifyRekorReceiptOffline(receipt, checkpoint, operatorDer, &rekorKey.PublicKey)
		if err == nil {
			t.Fatal("expected failure on mismatched operator key, got nil")
		}
	})
}

func TestVerifyRekorReceiptOnline(t *testing.T) {
	// TC-011-03: Mock HTTP server tests verify that online verification fails if Rekor returns different entry data.
	rekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	opEdPriv, opEdPub := deterministicCheckpointKey(1)
	opEdPubDer, err := x509.MarshalPKIXPublicKey(opEdPub)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := mustSignCheckpoint(t, validCheckpointPayload(), opEdPriv)

	hr, err := CheckpointHashedRekord(checkpoint, opEdPubDer)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBytes, err := CanonicalHashedRekordBytes(hr)
	if err != nil {
		t.Fatal(err)
	}
	bodyStr := base64.StdEncoding.EncodeToString(canonicalBytes)

	logIndex := int64(100)
	integratedTime := int64(1700000100)
	logID := "c0ee4787a2da8cb5f41fa6e0a8b9f0ee"
	setSig := signMockSET(t, rekorKey, bodyStr, integratedTime, logID, logIndex)

	receipt := RekorReceipt{
		LogID:                logID,
		LogIndex:             logIndex,
		IntegratedTime:       integratedTime,
		SignedEntryTimestamp: setSig,
		EntryID:              "abcd1234ef",
	}

	t.Run("matching entry succeeds", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			if r.URL.Path != "/api/v1/log/entries/abcd1234ef" {
				t.Errorf("expected path /api/v1/log/entries/abcd1234ef, got %s", r.URL.Path)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			respJSON := fmt.Sprintf(`{
				"abcd1234ef": {
					"body": %q,
					"integratedTime": %d,
					"logID": %q,
					"logIndex": %d,
					"verification": {
						"signedEntryTimestamp": %q
					}
				}
			}`, bodyStr, integratedTime, logID, logIndex, setSig)
			w.Write([]byte(respJSON))
		}))
		defer server.Close()

		client := NewRekorClient(server.URL)
		err = client.VerifyRekorReceiptOnline(context.Background(), receipt, checkpoint, opEdPubDer, &rekorKey.PublicKey)
		if err != nil {
			t.Fatalf("expected successful online verification, got %v", err)
		}
	})

	t.Run("query by logIndex succeeds", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			if r.URL.Path != "/api/v1/log/entries" || r.URL.Query().Get("logIndex") != "100" {
				t.Errorf("expected path /api/v1/log/entries?logIndex=100, got %s?%s", r.URL.Path, r.URL.RawQuery)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			respJSON := fmt.Sprintf(`{
				"abcd1234ef": {
					"body": %q,
					"integratedTime": %d,
					"logID": %q,
					"logIndex": %d,
					"verification": {
						"signedEntryTimestamp": %q
					}
				}
			}`, bodyStr, integratedTime, logID, logIndex, setSig)
			w.Write([]byte(respJSON))
		}))
		defer server.Close()

		noIDReceipt := receipt
		noIDReceipt.EntryID = ""

		client := NewRekorClient(server.URL)
		err = client.VerifyRekorReceiptOnline(context.Background(), noIDReceipt, checkpoint, opEdPubDer, &rekorKey.PublicKey)
		if err != nil {
			t.Fatalf("expected successful online verification by index, got %v", err)
		}
	})

	t.Run("body hash mismatch", func(t *testing.T) {
		badCheckpoint := checkpoint
		badCheckpoint.Payload.RootHash = strings.Repeat("3", 64)
		badHR, err := CheckpointHashedRekord(badCheckpoint, opEdPubDer)
		if err != nil {
			t.Fatal(err)
		}
		badCanonicalBytes, err := CanonicalHashedRekordBytes(badHR)
		if err != nil {
			t.Fatal(err)
		}
		badBodyStr := base64.StdEncoding.EncodeToString(badCanonicalBytes)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			respJSON := fmt.Sprintf(`{
				"abcd1234ef": {
					"body": %q,
					"integratedTime": %d,
					"logID": %q,
					"logIndex": %d,
					"verification": {
						"signedEntryTimestamp": %q
					}
				}
			}`, badBodyStr, integratedTime, logID, logIndex, setSig)
			w.Write([]byte(respJSON))
		}))
		defer server.Close()

		client := NewRekorClient(server.URL)
		err = client.VerifyRekorReceiptOnline(context.Background(), receipt, checkpoint, opEdPubDer, &rekorKey.PublicKey)
		if err == nil {
			t.Fatal("expected failure on body hash mismatch, got nil")
		}
	})

	t.Run("metadata mismatch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			respJSON := fmt.Sprintf(`{
				"abcd1234ef": {
					"body": %q,
					"integratedTime": %d,
					"logID": "different-log-id",
					"logIndex": %d,
					"verification": {
						"signedEntryTimestamp": %q
					}
				}
			}`, bodyStr, integratedTime, logIndex, setSig)
			w.Write([]byte(respJSON))
		}))
		defer server.Close()

		client := NewRekorClient(server.URL)
		err = client.VerifyRekorReceiptOnline(context.Background(), receipt, checkpoint, opEdPubDer, &rekorKey.PublicKey)
		if err == nil {
			t.Fatal("expected failure on logID mismatch, got nil")
		}
	})

	t.Run("http server 500 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := NewRekorClient(server.URL)
		err = client.VerifyRekorReceiptOnline(context.Background(), receipt, checkpoint, opEdPubDer, &rekorKey.PublicKey)
		if err == nil {
			t.Fatal("expected failure on server 500, got nil")
		}
	})
}

func signMockSET(t *testing.T, rekorPriv crypto.PrivateKey, body string, integratedTime int64, logID string, logIndex int64) string {
	t.Helper()
	m := map[string]any{
		"body":           body,
		"integratedTime": integratedTime,
		"logID":          logID,
		"logIndex":       logIndex,
	}
	payloadBytes, err := canonical(m)
	if err != nil {
		t.Fatal(err)
	}

	var sig []byte
	switch priv := rekorPriv.(type) {
	case *ecdsa.PrivateKey:
		hash := sha256.Sum256(payloadBytes)
		sig, err = ecdsa.SignASN1(rand.Reader, priv, hash[:])
		if err != nil {
			t.Fatal(err)
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(priv, payloadBytes)
	default:
		t.Fatalf("unsupported private key type for signing SET mock: %T", rekorPriv)
	}

	return base64.StdEncoding.EncodeToString(sig)
}
