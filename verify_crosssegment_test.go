package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildMultiSegmentChain emits recordsPerSegment events, rotates, repeats for `segments`
// rotations, then emits `activeRecords` more events into the active segment. It returns the
// loaded Chain and the signing key. The result is a chain with `segments` rotated-out segments
// (audit.log.001 .. audit.log.NNN) plus the active segment at the base path.
func buildMultiSegmentChain(t *testing.T, segments, recordsPerSegment, activeRecords int) (*Chain, ed25519.PrivateKey) {
	t.Helper()
	_, priv := newSegmentSigningKey(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	c, err := NewChain(path)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	for s := 0; s < segments; s++ {
		emitN(t, c, recordsPerSegment)
		if _, err := c.Rotate(int64(recordsPerSegment), "log-x", segmentIssuedAt, priv); err != nil {
			t.Fatalf("rotate %d: %v", s, err)
		}
	}
	emitN(t, c, activeRecords)
	return c, priv
}

// readLines returns the non-empty JSONL lines of the file at path.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return splitNonEmptyLines(data)
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func loadManifestForTest(t *testing.T, basePath string) SegmentManifest {
	t.Helper()
	m, err := loadManifest(manifestPath(basePath))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	return m
}

func writeManifestForTest(t *testing.T, basePath string, m SegmentManifest) {
	t.Helper()
	if err := writeManifestAtomic(manifestPath(basePath), m); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// TC-016-01: a multi-segment intact chain (>=2 rotated-out segments + active) verifies clean.
func TestVerifyMultiSegmentIntact(t *testing.T) {
	c, _ := buildMultiSegmentChain(t, 2, 3, 2)

	r := c.Verify()
	if !r.Valid {
		t.Fatalf("expected valid multi-segment chain, got valid=%v msg=%q at=%v", r.Valid, r.Message, r.TamperDetectedAt)
	}
	if r.TamperDetectedAt != nil {
		t.Fatalf("expected tamper_detected_at=nil, got %v", *r.TamperDetectedAt)
	}
	if r.Message != "chain intact" {
		t.Fatalf("expected message %q, got %q", "chain intact", r.Message)
	}
}

// TC-016-02: a byte-level tamper in an earlier (rotated-out) segment is detected with the
// affected record's global seq and a content-hash-mismatch message.
func TestVerifyTamperInEarlierSegment(t *testing.T) {
	c, _ := buildMultiSegmentChain(t, 2, 3, 2)

	seg0 := segmentPath(c.path, 1) // first rotated-out segment, global seqs 0..2
	lines := readLines(t, seg0)
	// Tamper the middle record (global seq 1) leaving its stored hash stale.
	lines[1] = strings.Replace(lines[1], `"actor":"vault"`, `"actor":"VAULT"`, 1)
	if !strings.Contains(lines[1], `"actor":"VAULT"`) {
		t.Fatalf("tamper substitution did not apply: %s", lines[1])
	}
	writeLines(t, seg0, lines)

	r := c.Verify()
	if r.Valid {
		t.Fatal("expected tamper in earlier segment to be detected")
	}
	if r.TamperDetectedAt == nil || *r.TamperDetectedAt != 1 {
		t.Fatalf("expected tamper at global seq 1, got %+v", r)
	}
	if !strings.Contains(r.Message, "content hash mismatch (tampered)") {
		t.Fatalf("expected content-hash-mismatch message, got %q", r.Message)
	}
}

// TC-016-03: a tampered prev_hash at the cross-segment seam (first record of segment N+1) is
// detected at the first record of N+1 with a broken-link message.
func TestVerifySeamPrevHashTamper(t *testing.T) {
	c, _ := buildMultiSegmentChain(t, 2, 3, 2)

	seg1 := segmentPath(c.path, 2) // second rotated-out segment, global seqs 3..5
	lines := readLines(t, seg1)
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	rec["prev_hash"] = strings.Repeat("a", 64) // bogus link that no longer matches seg N's end hash
	out, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	lines[0] = string(out)
	writeLines(t, seg1, lines)

	r := c.Verify()
	if r.Valid {
		t.Fatal("expected broken seam to be detected")
	}
	if r.TamperDetectedAt == nil || *r.TamperDetectedAt != 3 {
		t.Fatalf("expected broken link at global seq 3 (first record of seg N+1), got %+v", r)
	}
	if !strings.Contains(r.Message, "prev_hash link broken") {
		t.Fatalf("expected prev_hash-link-broken message, got %q", r.Message)
	}
}

// TC-016-04: a segment listed in the manifest but missing from disk is detected, and the message
// names the missing segment file.
func TestVerifyDroppedSegment(t *testing.T) {
	c, _ := buildMultiSegmentChain(t, 2, 3, 2)

	seg0 := segmentPath(c.path, 1)
	if err := os.Remove(seg0); err != nil {
		t.Fatalf("remove segment: %v", err)
	}

	r := c.Verify()
	if r.Valid {
		t.Fatal("expected dropped segment to be detected")
	}
	if !strings.Contains(r.Message, filepath.Base(seg0)) {
		t.Fatalf("expected message to name missing segment %q, got %q", filepath.Base(seg0), r.Message)
	}
}

// TC-016-05: reordered manifest entries (swap two segments) break the hash link and are detected.
func TestVerifyReorderedSegments(t *testing.T) {
	c, _ := buildMultiSegmentChain(t, 2, 3, 2)

	m := loadManifestForTest(t, c.path)
	if len(m.Segments) != 2 {
		t.Fatalf("expected 2 manifest segments, got %d", len(m.Segments))
	}
	m.Segments[0], m.Segments[1] = m.Segments[1], m.Segments[0]
	writeManifestForTest(t, c.path, m)

	r := c.Verify()
	if r.Valid {
		t.Fatal("expected reordered segments to be detected")
	}
}

// SEC-002: a tampered manifest field (forged end_hash) is caught by the manifest-vs-content
// cross-check, even though the on-disk segments are individually intact.
func TestVerifyTamperedManifestEndHash(t *testing.T) {
	c, _ := buildMultiSegmentChain(t, 2, 3, 2)

	m := loadManifestForTest(t, c.path)
	m.Segments[0].EndHash = strings.Repeat("b", 64) // forged end hash, content unchanged on disk
	writeManifestForTest(t, c.path, m)

	r := c.Verify()
	if r.Valid {
		t.Fatal("expected forged manifest end_hash to be detected")
	}
}

// SEC-002: a tampered manifest seq field (forged last_seq) is caught by the cross-check.
func TestVerifyTamperedManifestSeqRange(t *testing.T) {
	c, _ := buildMultiSegmentChain(t, 2, 3, 2)

	m := loadManifestForTest(t, c.path)
	m.Segments[0].LastSeq = m.Segments[0].LastSeq + 100 // forged seq range
	writeManifestForTest(t, c.path, m)

	r := c.Verify()
	if r.Valid {
		t.Fatal("expected forged manifest last_seq to be detected")
	}
}

// SEC-003: an on-disk segment file beyond the manifest's coverage (orphan from a crashed
// mid-rotate) must NOT be silently treated as a clean shorter log.
func TestVerifyOrphanSegmentBeyondManifest(t *testing.T) {
	c, _ := buildMultiSegmentChain(t, 2, 3, 2)

	// Drop the last manifest entry so segment .002 is on disk but unlisted.
	m := loadManifestForTest(t, c.path)
	orphan := m.Segments[len(m.Segments)-1].Segment
	m.Segments = m.Segments[:len(m.Segments)-1]
	writeManifestForTest(t, c.path, m)

	r := c.Verify()
	if r.Valid {
		t.Fatalf("expected orphan on-disk segment %q to be detected, got valid", orphan)
	}
}

// TC-016-07: Verify() reads from disk, not in-memory state. Corrupt a segment file after the
// Chain is loaded; the in-memory chain still reports the pre-corruption head, but Verify()
// (reading disk) must disagree and flag the tamper.
func TestVerifyReadsFromDiskNotMemory(t *testing.T) {
	c, _ := buildMultiSegmentChain(t, 2, 3, 2)

	// Snapshot in-memory head BEFORE corruption.
	memPrevHash := c.prevHash
	if r := c.Verify(); !r.Valid {
		t.Fatalf("precondition: expected intact chain, got %q", r.Message)
	}

	seg0 := segmentPath(c.path, 1)
	lines := readLines(t, seg0)
	lines[0] = strings.Replace(lines[0], `"action":"resolve"`, `"action":"RESOLVE"`, 1)
	if !strings.Contains(lines[0], `"action":"RESOLVE"`) {
		t.Fatalf("tamper substitution did not apply: %s", lines[0])
	}
	writeLines(t, seg0, lines)

	// In-memory state is unchanged...
	if c.prevHash != memPrevHash {
		t.Fatalf("in-memory prevHash changed unexpectedly")
	}
	// ...but Verify reads disk and disagrees.
	r := c.Verify()
	if r.Valid {
		t.Fatal("expected disk corruption to be detected without reload")
	}
	if r.TamperDetectedAt == nil || *r.TamperDetectedAt != 0 {
		t.Fatalf("expected tamper at global seq 0, got %+v", r)
	}
}

// TC-016-06: degenerate single-segment (never rotated, no manifest) is byte-for-byte identical
// to the single-file verifyChainState path, including the intact success shape.
func TestVerifyDegenerateMatchesSingleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	emitN(t, c, 4)

	// No manifest should exist for a never-rotated log.
	if _, err := os.Stat(manifestPath(path)); !os.IsNotExist(err) {
		t.Fatalf("expected no manifest for never-rotated log, stat err=%v", err)
	}

	got := c.Verify()
	_, want := verifyChainState(path)
	if got.Valid != want.Valid || got.Message != want.Message {
		t.Fatalf("degenerate Verify diverged: got %+v want %+v", got, want)
	}
	if (got.TamperDetectedAt == nil) != (want.TamperDetectedAt == nil) {
		t.Fatalf("degenerate tamper_detected_at nil-ness diverged: got %v want %v", got.TamperDetectedAt, want.TamperDetectedAt)
	}
	if got.TamperDetectedAt != nil && *got.TamperDetectedAt != *want.TamperDetectedAt {
		t.Fatalf("degenerate tamper_detected_at diverged: got %v want %v", *got.TamperDetectedAt, *want.TamperDetectedAt)
	}
	if !got.Valid || got.Message != "chain intact" || got.TamperDetectedAt != nil {
		t.Fatalf("expected intact success shape, got %+v", got)
	}
}
