// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SEC-001 (High): a checkpoint created over a ROTATED (multi-segment) log must verify against
// that same log as log_match:true. Before the fix, CreateSignedCheckpoint committed to the
// cumulative cross-segment head while VerifySignedCheckpointForLog re-walked only the active
// segment (single-segment verifyChainState), so a freshly created valid checkpoint was reported
// as not matching its own log ("prev_hash link broken" / log_match:false). Both sides now use
// the SAME walker (verifyAllSegments). This test FAILS before the fix.
func TestVerifyCheckpointForRotatedLogMatches(t *testing.T) {
	// 3 records, rotate, then 3 more in the active segment → cumulative tree_size = 6.
	c, priv := buildMultiSegmentChain(t, 1, 3, 3)
	pub := priv.Public().(ed25519.PublicKey)

	signed, err := c.CreateSignedCheckpoint("log-x", segmentIssuedAt, priv)
	if err != nil {
		t.Fatalf("create signed checkpoint over rotated log: %v", err)
	}

	// Sanity: the checkpoint commits to the cumulative global head, not just the active segment.
	if signed.Payload.TreeSize != 6 {
		t.Fatalf("expected cumulative tree_size=6 over rotated log, got %d", signed.Payload.TreeSize)
	}
	if signed.Payload.LastSeq != 5 {
		t.Fatalf("expected cumulative last_seq=5, got %d", signed.Payload.LastSeq)
	}

	res := VerifySignedCheckpointForLog(signed, pub, c.path)
	if !res.Valid {
		t.Fatalf("checkpoint over rotated log reported invalid: %q", res.Message)
	}
	if !res.SignatureValid {
		t.Fatalf("expected signature_valid=true, got %+v", res)
	}
	if res.LogMatch == nil || !*res.LogMatch {
		t.Fatalf("expected log_match=true for a freshly created checkpoint over its own rotated log, got %+v (msg=%q)", res.LogMatch, res.Message)
	}
}

// SEC-001 over more than one rotation, exercised through the same code path the CLI uses
// (LoadCheckpointVerificationKey + VerifySignedCheckpointForLog against the active log).
func TestVerifyCheckpointForMultiRotationLogMatches(t *testing.T) {
	// 2 rotations of 4 records each + 2 active → cumulative tree_size = 10.
	c, priv := buildMultiSegmentChain(t, 2, 4, 2)
	pub := priv.Public().(ed25519.PublicKey)

	signed, err := c.CreateSignedCheckpoint("log-x", segmentIssuedAt, priv)
	if err != nil {
		t.Fatalf("create signed checkpoint: %v", err)
	}
	if signed.Payload.TreeSize != 10 {
		t.Fatalf("expected cumulative tree_size=10, got %d", signed.Payload.TreeSize)
	}

	res := VerifySignedCheckpointForLog(signed, pub, c.path)
	if res.LogMatch == nil || !*res.LogMatch || !res.Valid {
		t.Fatalf("expected valid log_match=true over multi-rotation log, got %+v (msg=%q)", res, res.Message)
	}
}

// SEC-002 (Medium): "checkpointable ⟺ verifiable" — BuildCheckpointPayload / CreateSignedCheckpoint
// must FAIL CLOSED (errInvalidCheckpointLog) for any multi-segment state that Chain.Verify()
// rejects. Before the fix, verifyFullChain omitted the orphan/truncation defense, the
// manifest-vs-content cross-check, and the empty-manifest orphan scan, so a checkpoint could be
// created over a log Verify() would reject.
func TestCheckpointFailsClosedWhenVerifyRejects(t *testing.T) {
	tests := []struct {
		name string
		// mutate corrupts the on-disk multi-segment log into a state Verify() must reject.
		mutate func(t *testing.T, c *Chain)
	}{
		{
			// Orphan / truncation: an on-disk <base>.NNN segment beyond manifest coverage.
			// verifyFullChain ignored disk segments entirely; verifyAllSegments runs the
			// orphan scan, so the checkpoint must now fail closed.
			name: "orphan segment beyond manifest coverage",
			mutate: func(t *testing.T, c *Chain) {
				t.Helper()
				m := loadManifestForTest(t, c.path)
				// Drop the last manifest entry while leaving its <base>.NNN file on disk.
				if len(m.Segments) < 1 {
					t.Fatalf("setup: expected at least one segment, got %d", len(m.Segments))
				}
				m.Segments = m.Segments[:len(m.Segments)-1]
				writeManifestForTest(t, c.path, m)
			},
		},
		{
			// Empty-manifest orphan: manifest lists zero segments but a real <base>.001 is on
			// disk. verifyFullChain would have fallen through to a single-file walk.
			name: "empty manifest with on-disk segment",
			mutate: func(t *testing.T, c *Chain) {
				t.Helper()
				m := loadManifestForTest(t, c.path)
				m.Segments = nil
				writeManifestForTest(t, c.path, m)
			},
		},
		{
			// Manifest-field tamper: end_hash recorded in the manifest no longer matches the
			// segment's real on-disk end hash. verifyFullChain did not cross-check this field.
			name: "manifest end_hash mismatch",
			mutate: func(t *testing.T, c *Chain) {
				t.Helper()
				m := loadManifestForTest(t, c.path)
				m.Segments[0].EndHash = strings.Repeat("a", 64)
				writeManifestForTest(t, c.path, m)
			},
		},
		{
			// Manifest-field tamper: first_seq / last_seq range no longer matches content.
			name: "manifest seq range mismatch",
			mutate: func(t *testing.T, c *Chain) {
				t.Helper()
				m := loadManifestForTest(t, c.path)
				m.Segments[0].LastSeq = m.Segments[0].LastSeq + 100
				writeManifestForTest(t, c.path, m)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, priv := buildMultiSegmentChain(t, 1, 3, 3)

			tc.mutate(t, c)

			// Cross-check the premise: Verify() must reject this state.
			if vr := c.Verify(); vr.Valid {
				t.Fatalf("premise broken: Verify() accepted a state we expect it to reject")
			}

			// BuildCheckpointPayload must fail closed with errInvalidCheckpointLog.
			if _, err := c.BuildCheckpointPayload("log-x", segmentIssuedAt); !errors.Is(err, errInvalidCheckpointLog) {
				t.Fatalf("expected errInvalidCheckpointLog from BuildCheckpointPayload, got %v", err)
			}

			// CreateSignedCheckpoint (the wrapper used by CLI/IPC) must fail closed too.
			if _, err := c.CreateSignedCheckpoint("log-x", segmentIssuedAt, priv); !errors.Is(err, errInvalidCheckpointLog) {
				t.Fatalf("expected errInvalidCheckpointLog from CreateSignedCheckpoint, got %v", err)
			}
		})
	}
}

// SEC-001 (CLI surface): exercise the literal CLI verify-against-log path — load the public key
// from PEM, decode the checkpoint envelope from disk, then VerifySignedCheckpointForLog against
// the active log — to confirm log_match:true end to end after a rotation.
func TestCLICheckpointVerifyAgainstRotatedLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	privatePath, publicPath, priv, _ := writeTestKeyPair(t, dir)

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	const n = 5
	emitN(t, c, n)
	if _, err := c.Rotate(n, "cli-log", segmentIssuedAt, priv); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	emitN(t, c, 2)

	// Create the checkpoint and write the envelope to disk (mirrors `checkpoint create --out`).
	signed, err := c.CreateSignedCheckpoint("cli-log", segmentIssuedAt, priv)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	cpBytes, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	cpPath := filepath.Join(dir, "cp.json")
	if err := os.WriteFile(cpPath, cpBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// Now mirror `checkpoint verify --checkpoint cp.json --public-key public.pem --logfile <active>`.
	_ = privatePath
	pub, err := LoadCheckpointVerificationKey(publicPath)
	if err != nil {
		t.Fatalf("load verification key: %v", err)
	}
	data, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedCheckpoint(data)
	if err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	res := VerifySignedCheckpointForLog(decoded, pub, logPath)
	if res.LogMatch == nil || !*res.LogMatch || !res.Valid {
		t.Fatalf("CLI verify-against-rotated-log expected log_match:true, got %+v (msg=%q)", res, res.Message)
	}
}
