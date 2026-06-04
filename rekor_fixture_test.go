package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	rekorFixturePublicKey  = "testdata/checkpoints/rekor-public.pem"
	rekorFixtureCheckpoint = "testdata/checkpoints/rekor-checkpoint.json"
	rekorFixtureReceipt    = "testdata/checkpoints/rekor-receipt.json"
	rekorFixtureOperatorPub = "testdata/checkpoints/fixture-public.pem"
)

func TestRekorFixtureVerifies(t *testing.T) {
	// TC-013-01: Offline verification of the committed fixture receipt and checkpoint succeeds.
	checkpoint, receipt, operatorPubPEM, rekorPubKey := readRekorFixtureAssets(t)

	err := VerifyRekorReceiptOffline(receipt, checkpoint, operatorPubPEM, rekorPubKey)
	if err != nil {
		t.Fatalf("expected fixture Rekor receipt to verify, got error: %v", err)
	}
}

func TestRekorTamperFixtureDetection(t *testing.T) {
	// TC-013-02: Tampered receipt, checkpoint, or public key bytes successfully fail validation.
	checkpoint, receipt, operatorPubPEM, rekorPubKey := readRekorFixtureAssets(t)

	t.Run("altered receipt logIndex", func(t *testing.T) {
		tampered := receipt
		tampered.LogIndex = 999
		err := VerifyRekorReceiptOffline(tampered, checkpoint, operatorPubPEM, rekorPubKey)
		if err == nil {
			t.Fatal("expected failure on altered receipt logIndex, got nil")
		}
	})

	t.Run("altered receipt integratedTime", func(t *testing.T) {
		tampered := receipt
		tampered.IntegratedTime = 1234567890
		err := VerifyRekorReceiptOffline(tampered, checkpoint, operatorPubPEM, rekorPubKey)
		if err == nil {
			t.Fatal("expected failure on altered receipt integratedTime, got nil")
		}
	})

	t.Run("altered receipt logID", func(t *testing.T) {
		tampered := receipt
		tampered.LogID = "different-log-id"
		err := VerifyRekorReceiptOffline(tampered, checkpoint, operatorPubPEM, rekorPubKey)
		if err == nil {
			t.Fatal("expected failure on altered receipt logID, got nil")
		}
	})

	t.Run("altered receipt signature", func(t *testing.T) {
		tampered := receipt
		sigBytes, err := base64.StdEncoding.DecodeString(tampered.SignedEntryTimestamp)
		if err != nil {
			t.Fatal(err)
		}
		sigBytes[len(sigBytes)-1] ^= 0xff
		tampered.SignedEntryTimestamp = base64.StdEncoding.EncodeToString(sigBytes)

		err = VerifyRekorReceiptOffline(tampered, checkpoint, operatorPubPEM, rekorPubKey)
		if err == nil {
			t.Fatal("expected failure on altered receipt signature, got nil")
		}
	})

	t.Run("altered checkpoint root hash", func(t *testing.T) {
		tampered := checkpoint
		tampered.Payload.RootHash = strings.Repeat("a", 64)
		err := VerifyRekorReceiptOffline(receipt, tampered, operatorPubPEM, rekorPubKey)
		if err == nil {
			t.Fatal("expected failure on altered checkpoint root hash, got nil")
		}
	})

	t.Run("altered operator public key PEM", func(t *testing.T) {
		badOperatorPEM := []byte(string(operatorPubPEM) + "\n")
		// Let's modify one of the base64 characters in the PEM block
		badPEMStr := string(operatorPubPEM)
		badPEMStr = strings.Replace(badPEMStr, "MCow", "MCoX", 1)
		badOperatorPEM = []byte(badPEMStr)

		err := VerifyRekorReceiptOffline(receipt, checkpoint, badOperatorPEM, rekorPubKey)
		if err == nil {
			t.Fatal("expected failure on altered operator public key, got nil")
		}
	})

	t.Run("mismatched Rekor public key", func(t *testing.T) {
		wrongRekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyRekorReceiptOffline(receipt, checkpoint, operatorPubPEM, &wrongRekorKey.PublicKey)
		if err == nil {
			t.Fatal("expected failure on mismatched Rekor public key, got nil")
		}
	})
}

func TestRekorFitnessDocsAreUpdated(t *testing.T) {
	docs := []struct {
		path  string
		terms []string
	}{
		{
			path: "docs/spec/fitness-functions.md",
			terms: []string{
				"FF-008",
				"FF-009",
				"`make fitness-anchor-stability`",
				"`make fitness-anchor-tamper-detection`",
			},
		},
		{
			path: "docs/tasks/test-specs/coverage-tracker.md",
			terms: []string{
				"013",
				"Anchoring fitness and fixtures",
				"fitness-anchor-stability",
				"fitness-anchor-tamper-detection",
			},
		},
	}

	for _, doc := range docs {
		t.Run(doc.path, func(t *testing.T) {
			data, err := os.ReadFile(doc.path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			for _, term := range doc.terms {
				if !strings.Contains(text, term) {
					t.Fatalf("expected %s to contain %q", doc.path, term)
				}
			}
		})
	}
}

func readRekorFixtureAssets(t *testing.T) (SignedCheckpoint, RekorReceipt, []byte, any) {
	t.Helper()

	// Load checkpoint
	checkpointData, err := os.ReadFile(rekorFixtureCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := DecodeSignedCheckpoint(checkpointData)
	if err != nil {
		t.Fatal(err)
	}

	// Load receipt
	receiptData, err := os.ReadFile(rekorFixtureReceipt)
	if err != nil {
		t.Fatal(err)
	}
	var receipt RekorReceipt
	if err := json.Unmarshal(receiptData, &receipt); err != nil {
		t.Fatal(err)
	}

	// Load operator PEM bytes
	operatorPubPEM, err := os.ReadFile(rekorFixtureOperatorPub)
	if err != nil {
		t.Fatal(err)
	}

	// Load Rekor public key
	rekorPubKey, err := LoadRekorPublicKey(rekorFixturePublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return checkpoint, receipt, operatorPubPEM, rekorPubKey
}
