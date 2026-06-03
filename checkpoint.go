package main

import (
	"errors"
	"fmt"
)

const (
	CheckpointFormat        = "audit-trail-checkpoint-v1"
	CheckpointVersion       = int64(1)
	CheckpointContract      = "audit-trail-v1"
	CheckpointHashAlgorithm = "sha256-linear-chain-v1"
)

var errInvalidCheckpointLog = errors.New("invalid checkpoint source log")

// CheckpointPayload is the deterministic statement over a verified on-disk chain head.
type CheckpointPayload struct {
	Format        string `json:"format"`
	Version       int64  `json:"version"`
	Contract      string `json:"contract"`
	LogID         string `json:"log_id"`
	TreeSize      int64  `json:"tree_size"`
	LastSeq       int64  `json:"last_seq"`
	RootHash      string `json:"root_hash"`
	HashAlgorithm string `json:"hash_algorithm"`
	IssuedAt      int64  `json:"issued_at"`
}

// BuildCheckpointPayload creates a payload from the verified logfile, not in-memory state.
func (c *Chain) BuildCheckpointPayload(logID string, issuedAt int64) (CheckpointPayload, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	state, res := verifyChainState(c.path)
	if !res.Valid {
		return CheckpointPayload{}, fmt.Errorf("%w: %s", errInvalidCheckpointLog, res.Message)
	}

	return CheckpointPayload{
		Format:        CheckpointFormat,
		Version:       CheckpointVersion,
		Contract:      CheckpointContract,
		LogID:         logID,
		TreeSize:      state.treeSize,
		LastSeq:       state.lastSeq,
		RootHash:      state.rootHash,
		HashAlgorithm: CheckpointHashAlgorithm,
		IssuedAt:      issuedAt,
	}, nil
}

// CheckpointPayloadBytes returns the canonical bytes that checkpoint signatures cover.
func CheckpointPayloadBytes(payload CheckpointPayload) ([]byte, error) {
	return canonical(checkpointPayloadMap(payload))
}

func checkpointPayloadMap(payload CheckpointPayload) map[string]any {
	return map[string]any{
		"format":         payload.Format,
		"version":        payload.Version,
		"contract":       payload.Contract,
		"log_id":         payload.LogID,
		"tree_size":      payload.TreeSize,
		"last_seq":       payload.LastSeq,
		"root_hash":      payload.RootHash,
		"hash_algorithm": payload.HashAlgorithm,
		"issued_at":      payload.IssuedAt,
	}
}
