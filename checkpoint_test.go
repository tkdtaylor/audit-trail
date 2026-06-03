package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

const checkpointIssuedAt = int64(1700000000)

func TestCheckpointPayloadReflectsIntactChainHead(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Emit(map[string]any{"actor": "a", "action": "x", "target": "t"}); err != nil {
		t.Fatal(err)
	}
	second, err := c.Emit(map[string]any{"actor": "b", "action": "y", "target": "t"})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := c.BuildCheckpointPayload("test-log", checkpointIssuedAt)
	if err != nil {
		t.Fatal(err)
	}

	if payload.Format != CheckpointFormat {
		t.Fatalf("expected format %q, got %q", CheckpointFormat, payload.Format)
	}
	if payload.Version != CheckpointVersion {
		t.Fatalf("expected version %d, got %d", CheckpointVersion, payload.Version)
	}
	if payload.Contract != CheckpointContract {
		t.Fatalf("expected contract %q, got %q", CheckpointContract, payload.Contract)
	}
	if payload.LogID != "test-log" {
		t.Fatalf("expected log_id test-log, got %q", payload.LogID)
	}
	if payload.TreeSize != 2 {
		t.Fatalf("expected tree_size 2, got %d", payload.TreeSize)
	}
	if payload.LastSeq != 1 {
		t.Fatalf("expected last_seq 1, got %d", payload.LastSeq)
	}
	if payload.RootHash != second["hash"] {
		t.Fatalf("expected root_hash %q, got %q", second["hash"], payload.RootHash)
	}
	if payload.HashAlgorithm != CheckpointHashAlgorithm {
		t.Fatalf("expected hash algorithm %q, got %q", CheckpointHashAlgorithm, payload.HashAlgorithm)
	}
	if payload.IssuedAt != checkpointIssuedAt {
		t.Fatalf("expected issued_at %d, got %d", checkpointIssuedAt, payload.IssuedAt)
	}
}

func TestCheckpointPayloadIsBuiltFromDisk(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Emit(map[string]any{"actor": "vault", "action": "resolve", "target": "vault://test/k"}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"actor":"vault"`, `"actor":"Vault"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	payload, err := c.BuildCheckpointPayload("test-log", checkpointIssuedAt)
	if err == nil {
		t.Fatalf("expected tampered disk log to fail closed, got payload %+v", payload)
	}
	if !errors.Is(err, errInvalidCheckpointLog) {
		t.Fatalf("expected invalid checkpoint log error, got %v", err)
	}
}

func TestCheckpointPayloadBytesAreStable(t *testing.T) {
	payload := CheckpointPayload{
		Format:        CheckpointFormat,
		Version:       CheckpointVersion,
		Contract:      CheckpointContract,
		LogID:         "test-log",
		TreeSize:      2,
		LastSeq:       1,
		RootHash:      "1111111111111111111111111111111111111111111111111111111111111111",
		HashAlgorithm: CheckpointHashAlgorithm,
		IssuedAt:      checkpointIssuedAt,
	}

	a, err := CheckpointPayloadBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonical(map[string]any{
		"version":        int64(1),
		"tree_size":      int64(2),
		"root_hash":      "1111111111111111111111111111111111111111111111111111111111111111",
		"log_id":         "test-log",
		"last_seq":       int64(1),
		"issued_at":      checkpointIssuedAt,
		"hash_algorithm": CheckpointHashAlgorithm,
		"format":         CheckpointFormat,
		"contract":       CheckpointContract,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical payload bytes differ:\n%s\n%s", a, b)
	}

	const want = `{"contract":"audit-trail-v1","format":"audit-trail-checkpoint-v1","hash_algorithm":"sha256-linear-chain-v1","issued_at":1700000000,"last_seq":1,"log_id":"test-log","root_hash":"1111111111111111111111111111111111111111111111111111111111111111","tree_size":2,"version":1}`
	if string(a) != want {
		t.Fatalf("unexpected canonical checkpoint bytes:\n%s", a)
	}
}

func TestCheckpointPayloadEmptyAndMalformedLogs(t *testing.T) {
	t.Run("empty log", func(t *testing.T) {
		path := tempLog(t)
		c, err := NewChain(path)
		if err != nil {
			t.Fatal(err)
		}

		payload, err := c.BuildCheckpointPayload("empty-log", checkpointIssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		if payload.TreeSize != 0 {
			t.Fatalf("expected empty tree_size 0, got %d", payload.TreeSize)
		}
		if payload.LastSeq != -1 {
			t.Fatalf("expected empty last_seq -1, got %d", payload.LastSeq)
		}
		if payload.RootHash != Genesis {
			t.Fatalf("expected empty root_hash Genesis, got %q", payload.RootHash)
		}
	})

	t.Run("malformed log", func(t *testing.T) {
		path := tempLog(t)
		c, err := NewChain(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{not-json}\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		payload, err := c.BuildCheckpointPayload("bad-log", checkpointIssuedAt)
		if err == nil {
			t.Fatalf("expected malformed log to fail closed, got payload %+v", payload)
		}
		if !errors.Is(err, errInvalidCheckpointLog) {
			t.Fatalf("expected invalid checkpoint log error, got %v", err)
		}
	})

	t.Run("fractional JSON number", func(t *testing.T) {
		path := tempLog(t)
		c, err := NewChain(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Emit(map[string]any{"ts": int64(1), "actor": "a", "action": "x", "target": "t"}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		tampered := strings.Replace(string(data), `"ts":1`, `"ts":1.25`, 1)
		if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
			t.Fatal(err)
		}

		payload, err := c.BuildCheckpointPayload("bad-log", checkpointIssuedAt)
		if err == nil {
			t.Fatalf("expected fractional log number to fail closed, got payload %+v", payload)
		}
		if !strings.Contains(err.Error(), "non-integer JSON number") {
			t.Fatalf("expected non-integer JSON number error, got %v", err)
		}
	})
}

func TestCheckpointPayloadSpecsAreUpdated(t *testing.T) {
	docs := []struct {
		path  string
		terms []string
	}{
		{
			path: "docs/spec/data-model.md",
			terms: []string{
				"Checkpoint payload",
				"`log_id`",
				"`tree_size`",
				"`last_seq`",
				"`root_hash`",
				"`issued_at`",
			},
		},
		{
			path: "docs/spec/behaviors.md",
			terms: []string{
				"B-008",
				"Build a checkpoint payload",
				"verified on-disk chain",
				"fails closed",
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
