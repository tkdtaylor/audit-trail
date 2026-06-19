// SPDX-License-Identifier: Apache-2.0
//go:build ignore

// Generator for testdata/segments/ multi-segment rotation fixtures.
//
// Usage (from the repo root):
//
//	go run ./testdata/segments/generate/
//
// This program is INTENTIONALLY excluded from normal go test / make runs via the
// `//go:build ignore` constraint. The generated fixtures are committed stable bytes.
// Re-run only when the chain format or rotation logic changes and a fresh fixture
// baseline is needed.
//
// Determinism guarantees:
//   - Ed25519 signing key: reuses testdata/checkpoints/fixture-private.pem (the all-0x01
//     seed key). Same key → same signature bytes.
//   - Event timestamps: fixed constant starting at baseTS. No time.Now().
//   - Event content: fixed strings. Same content → same hash chain.
//   - Rotation issued_at: fixed constant rotationIssuedAt.
//   - Layout: 2 rotated-out segments of 3 records each + 3 active records.
//     Global seqs 0–2 → audit.log.001, 3–5 → audit.log.002, 6–8 → audit.log (active).
//
// Output: testdata/segments/ relative to the repo root (cwd when this is run).
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	outDir     = "testdata/segments"
	privKeyPEM = "testdata/checkpoints/fixture-private.pem"

	logID            = "fixture-segment-log"
	rotationIssuedAt = int64(1750000100)
	baseTS           = int64(1750000001)

	genesis = "0000000000000000000000000000000000000000000000000000000000000000"

	cpFormat    = "audit-trail-checkpoint-v1"
	cpVersion   = int64(1)
	cpContract  = "audit-trail-v1"
	cpHashAlg   = "sha256-linear-chain-v1"
	cpSigAlg    = "ed25519"
	cpKeyPrefix = "ed25519-sha256:"

	mfFormat  = "audit-trail-manifest-v1"
	mfVersion = int64(1)
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "generate: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	priv, err := loadPrivateKey(privKeyPEM)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	base := filepath.Join(outDir, "audit.log")

	// Remove stale outputs.
	for _, name := range []string{
		"audit.log", "audit.log.manifest",
		"audit.log.001", "audit.log.001.checkpoint",
		"audit.log.002", "audit.log.002.checkpoint",
	} {
		_ = os.Remove(filepath.Join(outDir, name))
	}

	// Chain state.
	seq := int64(0)
	prev := genesis
	ts := baseTS

	var mf manifest
	mf.Format = mfFormat
	mf.Version = mfVersion

	// Two rotated-out segments of 3 records each.
	for segIdx := 0; segIdx < 2; segIdx++ {
		segStart := seq
		segStartPrev := prev

		// Create (or recreate) the active file for this segment.
		if err := os.WriteFile(base, nil, 0o600); err != nil {
			return fmt.Errorf("create active: %w", err)
		}

		for i := 0; i < 3; i++ {
			hash, err := appendRecord(base, seq, ts, prev)
			if err != nil {
				return fmt.Errorf("emit seq=%d: %w", seq, err)
			}
			prev = hash
			seq++
			ts++
		}

		// Rotate: rename active → <base>.NNN
		segNum := int64(segIdx + 1)
		segFile := fmt.Sprintf("%s.%03d", base, segNum)
		if err := os.Rename(base, segFile); err != nil {
			return fmt.Errorf("rename to %s: %w", segFile, err)
		}

		// Sign checkpoint over cumulative head at this boundary.
		signed, err := signCheckpoint(priv, seq, seq-1, prev)
		if err != nil {
			return fmt.Errorf("sign checkpoint seg%d: %w", segNum, err)
		}
		cpBytes, err := json.MarshalIndent(signed, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal checkpoint: %w", err)
		}
		cpPath := segFile + ".checkpoint"
		if err := os.WriteFile(cpPath, cpBytes, 0o600); err != nil {
			return fmt.Errorf("write checkpoint: %w", err)
		}

		mf.Segments = append(mf.Segments, seg{
			Segment:       filepath.Base(segFile),
			FirstSeq:      segStart,
			LastSeq:       seq - 1,
			StartPrevHash: segStartPrev,
			EndHash:       prev,
			IssuedAt:      rotationIssuedAt,
		})
	}

	// Write manifest atomically.
	mfBytes, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	mfPath := base + ".manifest"
	tmp, err := os.CreateTemp(outDir, ".manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp manifest: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod tmp manifest: %w", err)
	}
	if _, err := tmp.Write(mfBytes); err != nil {
		tmp.Close()
		return fmt.Errorf("write tmp manifest: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync tmp manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp manifest: %w", err)
	}
	if err := os.Rename(tmpName, mfPath); err != nil {
		return fmt.Errorf("rename manifest: %w", err)
	}

	// Emit 3 active records into new audit.log.
	if err := os.WriteFile(base, nil, 0o600); err != nil {
		return fmt.Errorf("create new active segment: %w", err)
	}
	for i := 0; i < 3; i++ {
		hash, err := appendRecord(base, seq, ts, prev)
		if err != nil {
			return fmt.Errorf("emit active seq=%d: %w", seq, err)
		}
		prev = hash
		seq++
		ts++
	}

	// Print summary.
	fmt.Printf("Generated multi-segment fixtures in %s/:\n", outDir)
	entries, _ := os.ReadDir(outDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, _ := e.Info()
		fmt.Printf("  %-42s %d bytes\n", e.Name(), info.Size())
	}
	return nil
}

// appendRecord writes one deterministic audit record to path and returns its hash.
func appendRecord(path string, seq, ts int64, prev string) (string, error) {
	rec := map[string]any{
		"seq":       seq,
		"ts":        ts,
		"actor":     "fixture-agent",
		"action":    "fixture-action",
		"target":    fmt.Sprintf("fixture://target/%d", seq),
		"decision":  "allow",
		"refs":      []any{},
		"context":   map[string]any{},
		"prev_hash": prev,
	}
	hash, err := computeHash(prev, rec)
	if err != nil {
		return "", err
	}
	rec["hash"] = hash

	line, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return "", err
	}
	return hash, f.Close()
}

// computeHash returns SHA256(prevHash || JCS(recWithoutHash)).
func computeHash(prevHash string, rec map[string]any) (string, error) {
	body := make(map[string]any, len(rec))
	for k, v := range rec {
		if k != "hash" {
			body[k] = v
		}
	}
	cb, err := jcsCanonical(body)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(cb)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// jcsCanonical is a self-contained minimal RFC 8785 implementation for the types
// used by audit records (string, int64, []any, map[string]any, bool, nil).
func jcsCanonical(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		return jcsObject(val)
	case []any:
		return jcsArray(val)
	case string:
		return json.Marshal(val)
	case int64:
		return json.Marshal(val)
	case int:
		return json.Marshal(int64(val))
	case bool:
		return json.Marshal(val)
	case nil:
		return []byte("null"), nil
	default:
		return nil, fmt.Errorf("jcsCanonical: unsupported type %T", v)
	}
}

func jcsObject(obj map[string]any) ([]byte, error) {
	// Sort keys lexicographically (correct for pure-ASCII keys under JCS).
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	var buf []byte
	buf = append(buf, '{')
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf = append(buf, kb...)
		buf = append(buf, ':')
		vb, err := jcsCanonical(obj[k])
		if err != nil {
			return nil, err
		}
		buf = append(buf, vb...)
	}
	buf = append(buf, '}')
	return buf, nil
}

func jcsArray(arr []any) ([]byte, error) {
	var buf []byte
	buf = append(buf, '[')
	for i, elem := range arr {
		if i > 0 {
			buf = append(buf, ',')
		}
		eb, err := jcsCanonical(elem)
		if err != nil {
			return nil, err
		}
		buf = append(buf, eb...)
	}
	buf = append(buf, ']')
	return buf, nil
}

// signCheckpoint produces a signed checkpoint envelope.
func signCheckpoint(priv ed25519.PrivateKey, treeSize, lastSeq int64, rootHash string) (any, error) {
	payload := map[string]any{
		"format":         cpFormat,
		"version":        cpVersion,
		"contract":       cpContract,
		"log_id":         logID,
		"tree_size":      treeSize,
		"last_seq":       lastSeq,
		"root_hash":      rootHash,
		"hash_algorithm": cpHashAlg,
		"issued_at":      rotationIssuedAt,
	}
	payloadBytes, err := jcsCanonical(payload)
	if err != nil {
		return nil, fmt.Errorf("canonical payload: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("no ed25519 public key")
	}
	sum := sha256.Sum256(pub)
	keyID := cpKeyPrefix + hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, payloadBytes)
	return map[string]any{
		"payload": map[string]any{
			"format":         cpFormat,
			"version":        cpVersion,
			"contract":       cpContract,
			"log_id":         logID,
			"tree_size":      treeSize,
			"last_seq":       lastSeq,
			"root_hash":      rootHash,
			"hash_algorithm": cpHashAlg,
			"issued_at":      rotationIssuedAt,
		},
		"signature": map[string]any{
			"algorithm": cpSigAlg,
			"key_id":    keyID,
			"sig":       base64.RawURLEncoding.EncodeToString(sig),
		},
	}, nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("not PEM")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("trailing data after PEM")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("PEM type %q, want PRIVATE KEY", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return priv, nil
}

// manifest types (self-contained to avoid importing main package).
type seg struct {
	Segment       string `json:"segment"`
	FirstSeq      int64  `json:"first_seq"`
	LastSeq       int64  `json:"last_seq"`
	StartPrevHash string `json:"start_prev_hash"`
	EndHash       string `json:"end_hash"`
	IssuedAt      int64  `json:"issued_at"`
}

type manifest struct {
	Format   string `json:"format"`
	Version  int64  `json:"version"`
	Segments []seg  `json:"segments"`
}
