package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPCCheckpointCreateAndVerify(t *testing.T) {
	path := tempLog(t)
	chain, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Emit(map[string]any{"actor": "a", "action": "x", "target": "t"}); err != nil {
		t.Fatal(err)
	}

	privateKey, publicKey := deterministicCheckpointKey(1)
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	writeCheckpointPrivateKeyPEM(t, privatePath, privateKey)
	writeCheckpointPublicKeyPEM(t, publicPath, publicKey)

	config := CheckpointServerConfig{
		LogID:          "ipc-log",
		SigningKeyPath: privatePath,
		PublicKeyPath:  publicPath,
	}
	createResp := ipcRoundTripWithConfig(t, chain, config, `{"op":"checkpoint_create"}`)
	if createResp["error"] != nil {
		t.Fatalf("expected checkpoint_create success, got %+v", createResp)
	}
	checkpointBytes, err := json.Marshal(createResp)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := DecodeSignedCheckpoint(checkpointBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result := VerifySignedCheckpointForLog(checkpoint, publicKey, path); !result.Valid {
		t.Fatalf("expected created checkpoint to verify against log, got %+v", result)
	}

	verifyReq, err := json.Marshal(map[string]any{
		"op":          "checkpoint_verify",
		"checkpoint":  checkpoint,
		"compare_log": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyResp := ipcRoundTripWithConfig(t, chain, config, string(verifyReq))
	if verifyResp["valid"] != true {
		t.Fatalf("expected valid checkpoint_verify response, got %+v", verifyResp)
	}
	if verifyResp["signature_valid"] != true {
		t.Fatalf("expected signature_valid true, got %+v", verifyResp)
	}
	if verifyResp["log_match"] != true {
		t.Fatalf("expected log_match true, got %+v", verifyResp)
	}
}

func TestIPCCheckpointErrorsUseSharedShape(t *testing.T) {
	path := tempLog(t)
	chain, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}

	createResp := ipcRoundTrip(t, chain, `{"op":"checkpoint_create"}`)
	assertIPCError(t, createResp, "checkpoint_not_configured", "checkpoint not configured")

	verifyResp := ipcRoundTrip(t, chain, `{"op":"checkpoint_verify"}`)
	assertIPCError(t, verifyResp, "checkpoint_not_configured", "checkpoint not configured")

	_, publicKey := deterministicCheckpointKey(1)
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "public.pem")
	writeCheckpointPublicKeyPEM(t, publicPath, publicKey)

	config := CheckpointServerConfig{PublicKeyPath: publicPath}
	missingCheckpoint := ipcRoundTripWithConfig(t, chain, config, `{"op":"checkpoint_verify"}`)
	assertIPCError(t, missingCheckpoint, "bad_request", "missing checkpoint")
}

func TestCheckpointRuntimeSpecsAreUpdated(t *testing.T) {
	docs := []struct {
		path  string
		terms []string
	}{
		{
			path: "docs/spec/interfaces.md",
			terms: []string{
				"`checkpoint create`",
				"`checkpoint verify`",
				"`checkpoint_create`",
				"`checkpoint_verify`",
				"`checkpoint_not_configured`",
			},
		},
		{
			path: "docs/spec/behaviors.md",
			terms: []string{
				"B-010",
				"Create and verify checkpoints through runtime surfaces",
				"`checkpoint create`",
				"`checkpoint_verify`",
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
