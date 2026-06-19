// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const segmentIssuedAt = int64(1700000123)

func newSegmentSigningKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// emitN appends n events to the chain and returns the chain.
func emitN(t *testing.T, c *Chain, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := c.Emit(map[string]any{
			"actor": "vault", "action": "resolve", "target": "vault://test/k",
		}); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
}

// lastHashOf returns the hash of the last record in the JSONL file at path.
func lastHashOf(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var last string
	for _, line := range splitNonEmptyLines(data) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if h, ok := rec["hash"].(string); ok {
			last = h
		}
	}
	return last
}

func splitNonEmptyLines(data []byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			if i > start {
				out = append(out, string(data[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, string(data[start:]))
	}
	return out
}

// TC-015-01: Segment and SegmentManifest models round-trip to disk with mode 0600.
func TestManifestRoundTripAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log"+ManifestSuffix)
	want := SegmentManifest{
		Format:  ManifestFormat,
		Version: ManifestVersion,
		Segments: []Segment{
			{
				Segment:       "audit.log.001",
				FirstSeq:      0,
				LastSeq:       9,
				StartPrevHash: Genesis,
				EndHash:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				IssuedAt:      segmentIssuedAt,
			},
			{
				Segment:       "audit.log.002",
				FirstSeq:      10,
				LastSeq:       19,
				StartPrevHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				EndHash:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				IssuedAt:      segmentIssuedAt + 1,
			},
		},
	}

	if err := writeManifestAtomic(path, want); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode = %v, want 0600", info.Mode().Perm())
	}

	got, err := loadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != want.Format || got.Version != want.Version {
		t.Fatalf("top-level mismatch: got %+v", got)
	}
	if len(got.Segments) != len(want.Segments) {
		t.Fatalf("segment count = %d, want %d", len(got.Segments), len(want.Segments))
	}
	for i := range want.Segments {
		if got.Segments[i] != want.Segments[i] {
			t.Fatalf("segment %d mismatch:\n got %+v\nwant %+v", i, got.Segments[i], want.Segments[i])
		}
	}
}

// TC-015-02: manifest write is atomic — no partial file is visible and the swap is all-or-nothing.
func TestManifestWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log"+ManifestSuffix)

	old := SegmentManifest{Format: ManifestFormat, Version: ManifestVersion, Segments: []Segment{
		{Segment: "audit.log.001", FirstSeq: 0, LastSeq: 0, StartPrevHash: Genesis,
			EndHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"[:64], IssuedAt: segmentIssuedAt},
	}}
	if err := writeManifestAtomic(path, old); err != nil {
		t.Fatal(err)
	}

	// A reader concurrently polling the manifest path must always see a fully-decodable manifest
	// (either the old one or the complete new one) — never a partial write.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	bad := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue // mid-rename window: acceptable (old or new only after rename)
			}
			var m SegmentManifest
			if err := json.Unmarshal(data, &m); err != nil {
				select {
				case bad <- "partial/undecodable manifest observed: " + err.Error():
				default:
				}
				return
			}
		}
	}()

	for i := 0; i < 200; i++ {
		m := SegmentManifest{Format: ManifestFormat, Version: ManifestVersion}
		for j := 0; j <= i; j++ {
			m.Segments = append(m.Segments, Segment{
				Segment: "audit.log.001", FirstSeq: int64(j), LastSeq: int64(j),
				StartPrevHash: Genesis, EndHash: lastHashRepeat(j), IssuedAt: segmentIssuedAt,
			})
		}
		if err := writeManifestAtomic(path, m); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()

	select {
	case msg := <-bad:
		t.Fatal(msg)
	default:
	}

	// No leftover temp files from the write-then-rename strategy.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Fatalf("unexpected leftover file in dir: %s", e.Name())
		}
	}
}

// TC-015-02 (failure path): a write that fails BEFORE the rename completes must leave no
// partial/leftover temp file on disk — the `defer os.Remove(tmpName)` cleanup must fire. We
// force the rename to fail (the temp file is successfully created and written first) and assert
// the manifest directory is clean afterward.
func TestManifestWriteFailureLeavesNoTempFile(t *testing.T) {
	cases := []struct {
		name string
		// setup prepares dir and returns the manifest path to write to; writeManifestAtomic must
		// fail AFTER creating the temp file but on or before the rename.
		setup func(t *testing.T, dir string) (path string)
	}{
		{
			name: "rename target is a non-empty directory",
			setup: func(t *testing.T, dir string) string {
				// Make the manifest "path" itself an existing non-empty directory so os.Rename of
				// the temp file onto it fails (ENOTEMPTY/EISDIR) — but only after CreateTemp+write
				// have already produced the temp file in dir.
				path := filepath.Join(dir, "audit.log"+ManifestSuffix)
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "blocker"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tc.setup(t, dir)

			m := SegmentManifest{Format: ManifestFormat, Version: ManifestVersion, Segments: []Segment{
				{Segment: "audit.log.001", FirstSeq: 0, LastSeq: 0, StartPrevHash: Genesis,
					EndHash: lastHashRepeat(0), IssuedAt: segmentIssuedAt},
			}}

			err := writeManifestAtomic(path, m)
			if err == nil {
				t.Fatal("expected writeManifestAtomic to fail before/at rename")
			}

			// The temp file is created with the ".manifest-*.tmp" prefix in dir; the deferred
			// cleanup must have removed it. Assert no such leftover remains.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, ".manifest-") && strings.HasSuffix(name, ".tmp") {
					t.Fatalf("leftover temp file after failed write: %s", name)
				}
			}
		})
	}
}

func lastHashRepeat(n int) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte('a' + (n % 6))
	}
	return string(b)
}

// TC-015-03: Rotate() acquires the mutex, creates the new segment, and chain state continues.
func TestRotateUpdatesChainState(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	const n = 5
	emitN(t, c, n)
	lastHash := lastHashOf(t, path)

	_, priv := newSegmentSigningKey(t)
	res, err := c.Rotate(n, "test-log", segmentIssuedAt, priv)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !res.Rotated {
		t.Fatal("expected Rotated true")
	}

	// Rotated-out segment file exists at the ADR-005 path; active path is fresh (empty).
	segPath := segmentPath(path, 1)
	if _, err := os.Stat(segPath); err != nil {
		t.Fatalf("rotated segment missing: %v", err)
	}
	segCount, err := countRecords(segPath)
	if err != nil {
		t.Fatal(err)
	}
	if segCount != n {
		t.Fatalf("rotated segment record count = %d, want %d", segCount, n)
	}
	activeCount, err := countRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	if activeCount != 0 {
		t.Fatalf("new active segment record count = %d, want 0", activeCount)
	}

	// Next emit continues the global seq and links to the rotated-out segment's last hash.
	out, err := c.Emit(map[string]any{"actor": "a", "action": "x", "target": "t"})
	if err != nil {
		t.Fatal(err)
	}
	if out["seq"].(int64) != int64(n) {
		t.Fatalf("post-rotate emit seq = %v, want %d", out["seq"], n)
	}
	firstNew := firstRecordOf(t, path)
	if firstNew["prev_hash"] != lastHash {
		t.Fatalf("seam broken: new first prev_hash = %v, want %v", firstNew["prev_hash"], lastHash)
	}
}

func firstRecordOf(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitNonEmptyLines(data)
	if len(lines) == 0 {
		t.Fatal("no records in file")
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// TC-015-04: rotation trigger threshold is enforced (decline below, proceed at/above).
func TestRotateThresholdEnforced(t *testing.T) {
	_, priv := newSegmentSigningKey(t)

	t.Run("below threshold declines and touches no files", func(t *testing.T) {
		path := tempLog(t)
		c, err := NewChain(path)
		if err != nil {
			t.Fatal(err)
		}
		emitN(t, c, 3)

		dir := filepath.Dir(path)
		before, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}

		res, err := c.Rotate(5, "test-log", segmentIssuedAt, priv)
		if err == nil {
			t.Fatal("expected errBelowRotationThreshold")
		}
		if !isBelowThreshold(err) {
			t.Fatalf("expected below-threshold sentinel, got %v", err)
		}
		if res.Rotated {
			t.Fatal("expected Rotated false")
		}

		after, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before) {
			t.Fatalf("files changed on declined rotation: before %d, after %d", len(before), len(after))
		}
		if _, err := os.Stat(manifestPath(path)); !os.IsNotExist(err) {
			t.Fatal("manifest should not exist after declined rotation")
		}
	})

	t.Run("at threshold proceeds and writes manifest", func(t *testing.T) {
		path := tempLog(t)
		c, err := NewChain(path)
		if err != nil {
			t.Fatal(err)
		}
		emitN(t, c, 5)

		res, err := c.Rotate(5, "test-log", segmentIssuedAt, priv)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Rotated {
			t.Fatal("expected Rotated true")
		}
		m, err := loadManifest(manifestPath(path))
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Segments) != 1 {
			t.Fatalf("manifest segments = %d, want 1", len(m.Segments))
		}
		if m.Segments[0].FirstSeq != 0 || m.Segments[0].LastSeq != 4 {
			t.Fatalf("segment seq range = [%d,%d], want [0,4]", m.Segments[0].FirstSeq, m.Segments[0].LastSeq)
		}
		if m.Segments[0].StartPrevHash != Genesis {
			t.Fatalf("segment 0 start_prev_hash = %q, want Genesis", m.Segments[0].StartPrevHash)
		}
	})
}

func isBelowThreshold(err error) bool {
	return err != nil && err == errBelowRotationThreshold
}

// TC-015-05: chain continuity at the seam + loadState global resume from the new active segment.
func TestSeamContinuityAndLoadStateResume(t *testing.T) {
	const m = 4
	const k = 3
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	emitN(t, c, m)
	rotatedLastHash := lastHashOf(t, path)

	_, priv := newSegmentSigningKey(t)
	if _, err := c.Rotate(m, "test-log", segmentIssuedAt, priv); err != nil {
		t.Fatal(err)
	}
	emitN(t, c, k)

	// First record in the new active segment links to the rotated-out segment's last hash.
	first := firstRecordOf(t, path)
	if first["prev_hash"] != rotatedLastHash {
		t.Fatalf("seam: first prev_hash = %v, want %v", first["prev_hash"], rotatedLastHash)
	}
	finalHash := lastHashOf(t, path)

	// loadState on the new active segment alone must resume the GLOBAL seq and prevHash.
	resumed, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.seq != int64(m+k) {
		t.Fatalf("resumed seq = %d, want %d", resumed.seq, m+k)
	}
	if resumed.prevHash != finalHash {
		t.Fatalf("resumed prevHash = %v, want %v", resumed.prevHash, finalHash)
	}

	// A further emit on the resumed chain continues the global count and links correctly.
	out, err := resumed.Emit(map[string]any{"actor": "z", "action": "q", "target": "t"})
	if err != nil {
		t.Fatal(err)
	}
	if out["seq"].(int64) != int64(m+k) {
		t.Fatalf("resumed emit seq = %v, want %d", out["seq"], m+k)
	}
}

// TC-015-06: the rotated-out segment receives a signed checkpoint over the cumulative head, and
// VerifySignedCheckpoint succeeds with the matching public key (re-anchoring at boundaries).
func TestRotateWritesSignedCheckpoint(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	const n = 6
	emitN(t, c, n)
	segHead := lastHashOf(t, path)

	pub, priv := newSegmentSigningKey(t)
	res, err := c.Rotate(n, "test-log", segmentIssuedAt, priv)
	if err != nil {
		t.Fatal(err)
	}

	segPath := segmentPath(path, 1)
	cpPath := checkpointPath(segPath)
	if _, err := os.Stat(cpPath); err != nil {
		t.Fatalf("checkpoint missing: %v", err)
	}
	info, err := os.Stat(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode = %v, want 0600", info.Mode().Perm())
	}

	data, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := DecodeSignedCheckpoint(data)
	if err != nil {
		t.Fatal(err)
	}

	// Cumulative boundary head: tree_size = n, last_seq = n-1, root_hash = segment head.
	if signed.Payload.TreeSize != int64(n) {
		t.Fatalf("checkpoint tree_size = %d, want %d", signed.Payload.TreeSize, n)
	}
	if signed.Payload.LastSeq != int64(n-1) {
		t.Fatalf("checkpoint last_seq = %d, want %d", signed.Payload.LastSeq, n-1)
	}
	if signed.Payload.RootHash != segHead {
		t.Fatalf("checkpoint root_hash = %v, want %v", signed.Payload.RootHash, segHead)
	}
	if res.LastSeq != int64(n-1) {
		t.Fatalf("result LastSeq = %d, want %d", res.LastSeq, n-1)
	}

	vr := VerifySignedCheckpoint(signed, pub)
	if !vr.Valid || !vr.SignatureValid {
		t.Fatalf("VerifySignedCheckpoint failed: %+v", vr)
	}
}

// TC-015-06 (re-anchoring, second boundary): a second rotation checkpoints the CUMULATIVE head,
// proving the parameterized walker re-anchors a segment whose first record is not Genesis.
func TestRotateSecondBoundaryReanchorsCumulativeHead(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv := newSegmentSigningKey(t)

	emitN(t, c, 3)
	if _, err := c.Rotate(3, "test-log", segmentIssuedAt, priv); err != nil {
		t.Fatal(err)
	}
	emitN(t, c, 4) // global seq 3..6
	cumulativeHead := lastHashOf(t, path)

	if _, err := c.Rotate(4, "test-log", segmentIssuedAt+1, priv); err != nil {
		t.Fatal(err)
	}

	cpPath := checkpointPath(segmentPath(path, 2))
	data, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := DecodeSignedCheckpoint(data)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Payload.TreeSize != 7 {
		t.Fatalf("second checkpoint tree_size = %d, want 7 (cumulative)", signed.Payload.TreeSize)
	}
	if signed.Payload.LastSeq != 6 {
		t.Fatalf("second checkpoint last_seq = %d, want 6 (global)", signed.Payload.LastSeq)
	}
	if signed.Payload.RootHash != cumulativeHead {
		t.Fatalf("second checkpoint root_hash = %v, want cumulative head %v", signed.Payload.RootHash, cumulativeHead)
	}
	if vr := VerifySignedCheckpoint(signed, pub); !vr.Valid {
		t.Fatalf("second checkpoint verify failed: %+v", vr)
	}

	// Manifest second entry start_prev_hash must equal the first segment's end hash (seam).
	m, err := loadManifest(manifestPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Segments) != 2 {
		t.Fatalf("manifest segments = %d, want 2", len(m.Segments))
	}
	if m.Segments[1].StartPrevHash != m.Segments[0].EndHash {
		t.Fatalf("seam in manifest broken: seg2 start_prev_hash %v != seg1 end_hash %v",
			m.Segments[1].StartPrevHash, m.Segments[0].EndHash)
	}
}

// SEC-001: Rotate() must never overwrite an existing <base>.NNN segment, even when the manifest
// (an untrusted index) under-counts or is missing. A deleted/forged/truncated manifest must not
// drive Rotate to a low segment number and clobber a real segment file via os.Rename.
func TestRotateDoesNotOverwriteExistingSegment(t *testing.T) {
	t.Run("disk-derived number skips an existing segment", func(t *testing.T) {
		path := tempLog(t)
		c, err := NewChain(path)
		if err != nil {
			t.Fatal(err)
		}
		_, priv := newSegmentSigningKey(t)

		// Plant a pre-existing rotated-out segment at <base>.001 holding irreplaceable bytes,
		// WITHOUT a corresponding manifest entry (the manifest under-counts — the attacker model).
		existing := segmentPath(path, 1)
		const sentinel = "do-not-destroy-this-segment\n"
		if err := os.WriteFile(existing, []byte(sentinel), 0o600); err != nil {
			t.Fatal(err)
		}

		const n = 4
		emitN(t, c, n)

		res, err := c.Rotate(n, "test-log", segmentIssuedAt, priv)
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		if !res.Rotated {
			t.Fatal("expected Rotated true")
		}

		// The pre-existing .001 must be byte-for-byte intact.
		got, err := os.ReadFile(existing)
		if err != nil {
			t.Fatalf("existing segment vanished: %v", err)
		}
		if string(got) != sentinel {
			t.Fatalf("existing segment .001 was overwritten: got %q, want %q", string(got), sentinel)
		}

		// Rotation must have picked the next free number (.002), not clobbered .001.
		if res.Segment != filepath.Base(segmentPath(path, 2)) {
			t.Fatalf("rotated segment = %q, want %q (next free number)", res.Segment, filepath.Base(segmentPath(path, 2)))
		}
		segCount, err := countRecords(segmentPath(path, 2))
		if err != nil {
			t.Fatal(err)
		}
		if segCount != n {
			t.Fatalf("new segment .002 record count = %d, want %d", segCount, n)
		}
	})

	t.Run("highestSegmentOnDisk reflects disk, not the manifest", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")

		// No segments yet.
		if h, err := highestSegmentOnDisk(path); err != nil || h != 0 {
			t.Fatalf("highest with no segments = %d, %v; want 0, nil", h, err)
		}

		// Plant .001, .002, a checkpoint sidecar, and an unrelated file; only the bare numbered
		// segments count, so the highest is 2.
		for _, f := range []string{
			segmentPath(path, 1),
			segmentPath(path, 2),
			checkpointPath(segmentPath(path, 2)), // .002.checkpoint must be ignored
			path + ".manifest",                   // .manifest must be ignored
		} {
			if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		h, err := highestSegmentOnDisk(path)
		if err != nil {
			t.Fatal(err)
		}
		if h != 2 {
			t.Fatalf("highestSegmentOnDisk = %d, want 2", h)
		}
	})

	t.Run("repeated rotation never disturbs older segments even with a planted file", func(t *testing.T) {
		// End-to-end: a first rotation produces .001 (manifest-tracked). An attacker then plants a
		// bogus .002 on disk. A second rotation must derive the next number from disk (highest=2 ->
		// .003) and leave BOTH .001 and the planted .002 byte-for-byte intact. This proves the
		// disk-derived numbering plus the stat guard never let os.Rename clobber an existing
		// segment, regardless of what the manifest claims (SEC-001).
		path := tempLog(t)
		c, err := NewChain(path)
		if err != nil {
			t.Fatal(err)
		}
		_, priv := newSegmentSigningKey(t)

		// First, a normal rotation creates .001 + manifest entry (highest on disk = 1).
		emitN(t, c, 3)
		seg1Head := lastHashOf(t, path)
		if _, err := c.Rotate(3, "test-log", segmentIssuedAt, priv); err != nil {
			t.Fatal(err)
		}
		seg1Bytes, err := os.ReadFile(segmentPath(path, 1))
		if err != nil {
			t.Fatal(err)
		}

		// Now plant a .002 to occupy the next disk-derived slot, then emit + rotate again. Because
		// disk-scan sees highest=2, it targets .003 and rotation succeeds without touching .002.
		const planted = "planted-002-must-survive\n"
		if err := os.WriteFile(segmentPath(path, 2), []byte(planted), 0o600); err != nil {
			t.Fatal(err)
		}
		emitN(t, c, 3)
		res, err := c.Rotate(3, "test-log", segmentIssuedAt+1, priv)
		if err != nil {
			t.Fatalf("second rotate: %v", err)
		}
		if res.Segment != filepath.Base(segmentPath(path, 3)) {
			t.Fatalf("second rotate segment = %q, want .003", res.Segment)
		}

		// Neither the manifest-tracked .001 nor the planted .002 may have been overwritten.
		got1, err := os.ReadFile(segmentPath(path, 1))
		if err != nil || string(got1) != string(seg1Bytes) {
			t.Fatalf(".001 was disturbed by second rotation")
		}
		got2, err := os.ReadFile(segmentPath(path, 2))
		if err != nil || string(got2) != planted {
			t.Fatalf("planted .002 was overwritten: got %q, want %q", string(got2), planted)
		}
		_ = seg1Head
	})
}

// TC-015-08: docs/spec/data-model.md documents the segment + manifest schemas and the
// seam-continuity invariant explicitly.
func TestDataModelDocumentsSegmentSchemas(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("docs", "spec", "data-model.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	required := []string{
		ManifestFormat,                  // manifest format tag documented
		"SegmentManifest",               // manifest type named
		"start_prev_hash",               // segment entry field documented
		"end_hash",                      // segment entry field documented
		"first_seq",                     // segment entry field documented
		"last_seq",                      // segment entry field documented
		"Seam-continuity invariant",     // invariant section present
		"first** record in segment N+1", // invariant stated explicitly
	}
	for _, want := range required {
		if !strings.Contains(doc, want) {
			t.Fatalf("data-model.md missing required text: %q", want)
		}
	}
}

// TC-015-07: the single-segment degenerate case (no rotation, no manifest) is unchanged.
func TestDegenerateNoManifestUnchanged(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	emitN(t, c, 4)

	// No manifest is created by emit alone.
	if _, err := os.Stat(manifestPath(path)); !os.IsNotExist(err) {
		t.Fatal("manifest must not exist for a never-rotated log")
	}

	// loadState resumes exactly as before: seq = 4, prevHash = last hash.
	last := lastHashOf(t, path)
	resumed, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.seq != 4 {
		t.Fatalf("degenerate resumed seq = %d, want 4", resumed.seq)
	}
	if resumed.prevHash != last {
		t.Fatalf("degenerate resumed prevHash = %v, want %v", resumed.prevHash, last)
	}

	// Verify still walks from Genesis with the identical result.
	if vr := resumed.Verify(); !vr.Valid {
		t.Fatalf("degenerate verify failed: %+v", vr)
	}

	// verifyChainStateFrom(path, Genesis, 0) is byte-identical to verifyChainState(path).
	a, ra := verifyChainState(path)
	b, rb := verifyChainStateFrom(path, Genesis, 0)
	if a != b || ra != rb {
		t.Fatalf("walker default mismatch: %+v/%+v vs %+v/%+v", a, ra, b, rb)
	}
}

// ADR-005 required: single-writer isolation — Emit racing Rotate loses no record and the
// resulting multi-segment log verifies end-to-end (manifest segment + active segment).
func TestRotateEmitSingleWriterIsolation(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := newSegmentSigningKey(t)

	const pre = 10
	emitN(t, c, pre)

	const concurrentEmits = 20
	var wg sync.WaitGroup
	wg.Add(concurrentEmits + 1)

	// One rotation racing many emits, all serialized through c.mu.
	go func() {
		defer wg.Done()
		_, _ = c.Rotate(pre, "test-log", segmentIssuedAt, priv)
	}()
	for i := 0; i < concurrentEmits; i++ {
		go func() {
			defer wg.Done()
			_, _ = c.Emit(map[string]any{"actor": "a", "action": "x", "target": "t"})
		}()
	}
	wg.Wait()

	// No record lost: total records across the rotated segment + active segment == pre + emits.
	var total int64
	if seg, err := countRecords(segmentPath(path, 1)); err == nil {
		total += seg
	}
	active, err := countRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	total += active
	if total != int64(pre+concurrentEmits) {
		t.Fatalf("record total = %d, want %d (a record was lost or duplicated)", total, pre+concurrentEmits)
	}

	// The rotated-out segment, if rotation occurred, verifies cumulatively and its checkpoint
	// verifies; the active segment resumes cleanly.
	if m, err := loadManifest(manifestPath(path)); err == nil && len(m.Segments) == 1 {
		seg := m.Segments[0]
		state, res := verifyChainStateFrom(segmentPath(path, 1), seg.StartPrevHash, seg.FirstSeq)
		if !res.Valid {
			t.Fatalf("rotated segment did not verify: %s", res.Message)
		}
		if state.rootHash != seg.EndHash || state.lastSeq != seg.LastSeq {
			t.Fatalf("manifest/content mismatch: state %+v vs entry %+v", state, seg)
		}
		// Active segment continues from the manifest head with no broken link.
		if active > 0 {
			_, ares := verifyChainStateFrom(path, seg.EndHash, seg.LastSeq+1)
			if !ares.Valid {
				t.Fatalf("active segment did not verify after rotation: %s", ares.Message)
			}
		}
	}

	// A fresh resume sees the correct global seq regardless of interleaving.
	resumed, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.seq != int64(pre+concurrentEmits) {
		t.Fatalf("resumed seq = %d, want %d", resumed.seq, pre+concurrentEmits)
	}
}
