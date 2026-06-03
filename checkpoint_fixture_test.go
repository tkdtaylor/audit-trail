package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

const (
	checkpointFixtureLog        = "testdata/checkpoints/fixture.log"
	checkpointFixturePayload    = "testdata/checkpoints/fixture-payload.jcs"
	checkpointFixtureCheckpoint = "testdata/checkpoints/fixture-checkpoint.json"
	checkpointFixturePublicKey  = "testdata/checkpoints/fixture-public.pem"
)

func TestCheckpointFixtureVerifies(t *testing.T) {
	chain, err := NewChain(checkpointFixtureLog)
	if err != nil {
		t.Fatal(err)
	}
	if result := chain.Verify(); !result.Valid {
		t.Fatalf("expected fixture log to verify, got %+v", result)
	}

	checkpoint := readFixtureCheckpoint(t)
	publicKey := readFixturePublicKey(t)
	result := VerifySignedCheckpointForLog(checkpoint, publicKey, checkpointFixtureLog)
	if !result.Valid || !result.SignatureValid || result.LogMatch == nil || !*result.LogMatch {
		t.Fatalf("expected fixture checkpoint to verify against fixture log, got %+v", result)
	}
}

func TestCheckpointPayloadFixtureStability(t *testing.T) {
	checkpoint := readFixtureCheckpoint(t)
	got, err := CheckpointPayloadBytes(checkpoint.Payload)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(checkpointFixturePayload)
	if err != nil {
		t.Fatal(err)
	}
	want = []byte(strings.TrimRight(string(want), "\n"))
	if string(got) != string(want) {
		t.Fatalf("checkpoint payload bytes changed:\nwant %s\ngot  %s", want, got)
	}
}

func TestCheckpointTamperFixtureDetection(t *testing.T) {
	publicKey := readFixturePublicKey(t)
	checkpoint := readFixtureCheckpoint(t)

	t.Run("altered payload", func(t *testing.T) {
		tampered := checkpoint
		tampered.Payload.LogID = "fixture-bad"
		result := VerifySignedCheckpoint(tampered, publicKey)
		if result.Valid || result.SignatureValid {
			t.Fatalf("expected altered payload to fail, got %+v", result)
		}
	})

	t.Run("altered signature", func(t *testing.T) {
		tampered := checkpoint
		sig, err := base64.RawURLEncoding.DecodeString(tampered.Signature.Sig)
		if err != nil {
			t.Fatal(err)
		}
		sig[len(sig)-1] ^= 0xff
		tampered.Signature.Sig = base64.RawURLEncoding.EncodeToString(sig)

		result := VerifySignedCheckpoint(tampered, publicKey)
		if result.Valid || result.SignatureValid {
			t.Fatalf("expected altered signature to fail, got %+v", result)
		}
	})
}

func TestCheckpointFitnessDocsAreUpdated(t *testing.T) {
	docs := []struct {
		path  string
		terms []string
	}{
		{
			path: "docs/spec/fitness-functions.md",
			terms: []string{
				"FF-006",
				"FF-007",
				"`make fitness-checkpoint-stability`",
				"`make fitness-checkpoint-tamper-detection`",
			},
		},
		{
			path: "docs/tasks/test-specs/coverage-tracker.md",
			terms: []string{
				"008",
				"Checkpoint fitness and fixtures",
				"fitness-checkpoint-stability",
				"fitness-checkpoint-tamper-detection",
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

func readFixtureCheckpoint(t *testing.T) SignedCheckpoint {
	t.Helper()
	data, err := os.ReadFile(checkpointFixtureCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := DecodeSignedCheckpoint(data)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func readFixturePublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	publicKey, err := LoadCheckpointVerificationKey(checkpointFixturePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}
