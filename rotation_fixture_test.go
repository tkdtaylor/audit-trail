// SPDX-License-Identifier: Apache-2.0
package main

// TC-018-01: committed multi-segment fixtures verify intact (fitness-rotation-stability).
// TC-018-02: tamper cases each produce valid:false  (fitness-rotation-tamper-detection).
// TC-018-03: both new targets are wired into make fitness (verified by docs check + Makefile).
// TC-018-04: FF-010/FF-011 in fitness-functions.md + task 018 row in coverage-tracker.md.
//
// Fixture layout (testdata/segments/):
//   audit.log          – active segment (3 records, global seqs 6–8)
//   audit.log.001      – rotated-out segment 1 (3 records, global seqs 0–2)
//   audit.log.001.checkpoint – signed checkpoint over cumulative head after seg 1
//   audit.log.002      – rotated-out segment 2 (3 records, global seqs 3–5)
//   audit.log.002.checkpoint – signed checkpoint over cumulative head after seg 2
//   audit.log.manifest – ordered manifest index
//
// The fixtures are committed stable bytes generated once by
// testdata/segments/generate/main.go (//go:build ignore). To regenerate:
//
//   go run ./testdata/segments/generate/
//
// Do NOT regenerate during normal go test / make runs.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	segFixtureBase      = "testdata/segments/audit.log"
	segFixtureSeg001    = "testdata/segments/audit.log.001"
	segFixtureSeg002    = "testdata/segments/audit.log.002"
	segFixtureActive    = "testdata/segments/audit.log"
	segFixtureManifest  = "testdata/segments/audit.log.manifest"
	segFixturePublicKey = "testdata/checkpoints/fixture-public.pem"
)

// copySegmentFixtures copies all fixture files from testdata/segments/ to dst.
// The active segment (audit.log), both rotated segments (.001, .002), their
// checkpoints, and the manifest are all copied so tamper sub-cases can mutate
// the copies without touching the committed bytes.
func copySegmentFixtures(t *testing.T, dst string) {
	t.Helper()
	files := []string{
		"audit.log",
		"audit.log.001",
		"audit.log.001.checkpoint",
		"audit.log.002",
		"audit.log.002.checkpoint",
		"audit.log.manifest",
	}
	for _, name := range files {
		src := filepath.Join("testdata/segments", name)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("copySegmentFixtures: read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), data, 0o600); err != nil {
			t.Fatalf("copySegmentFixtures: write %s: %v", name, err)
		}
	}
}

// lastRecordHash returns the hash field of the last JSONL record in path.
func lastRecordHash(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lastRecordHash: read %s: %v", path, err)
	}
	var last string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("lastRecordHash: unmarshal: %v", err)
		}
		if h, ok := rec["hash"].(string); ok {
			last = h
		}
	}
	if last == "" {
		t.Fatalf("lastRecordHash: no hash found in %s", path)
	}
	return last
}

// firstRecordPrevHash returns the prev_hash field of the first JSONL record in path.
func firstRecordPrevHash(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("firstRecordPrevHash: read %s: %v", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("firstRecordPrevHash: unmarshal: %v", err)
		}
		ph, _ := rec["prev_hash"].(string)
		return ph
	}
	t.Fatalf("firstRecordPrevHash: no record found in %s", path)
	return ""
}

// TestRotationStabilityFixture is the fitness gate for FF-011.
// It loads the committed multi-segment fixtures and asserts:
//  1. Verify() over the full chain returns {valid:true, tamper_detected_at:null, "chain intact"}.
//  2. Every cross-segment seam holds: first record's prev_hash of seg N+1 == last hash of seg N.
func TestRotationStabilityFixture(t *testing.T) {
	// TC-018-01 — committed fixtures must verify intact.
	chain, err := NewChain(segFixtureBase)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	result := chain.Verify()
	if !result.Valid {
		t.Fatalf("expected fixtures to verify intact, got valid=%v msg=%q tamper_at=%v",
			result.Valid, result.Message, result.TamperDetectedAt)
	}
	if result.TamperDetectedAt != nil {
		t.Fatalf("expected tamper_detected_at=null, got %v", *result.TamperDetectedAt)
	}
	if result.Message != "chain intact" {
		t.Fatalf("expected message %q, got %q", "chain intact", result.Message)
	}

	// Seam check: prev_hash of first record in each N+1 segment == hash of last record in seg N.
	seams := []struct {
		name string
		prev string // file whose last hash is the expected prev_hash
		next string // file whose first record's prev_hash must match
	}{
		{"seam seg001->seg002", segFixtureSeg001, segFixtureSeg002},
		{"seam seg002->active", segFixtureSeg002, segFixtureActive},
	}
	for _, s := range seams {
		t.Run(s.name, func(t *testing.T) {
			want := lastRecordHash(t, s.prev)
			got := firstRecordPrevHash(t, s.next)
			if want != got {
				t.Fatalf("seam broken: last hash of %s=%q but first prev_hash of %s=%q",
					s.prev, want, s.next, got)
			}
		})
	}
}

// TestRotationTamperFixtureDetection is the fitness gate for FF-010.
// Each sub-case copies the committed fixtures to a t.TempDir() (committed bytes are NEVER
// mutated), applies exactly one mutation, and asserts Verify() returns valid:false.
// The test runner exits 0 because all tamper cases are expected to fail.
func TestRotationTamperFixtureDetection(t *testing.T) {
	// sub-case (a): one-byte edit in a record in a rotated-out segment.
	t.Run("one-byte-edit-in-seg001", func(t *testing.T) {
		dir := t.TempDir()
		copySegmentFixtures(t, dir)
		base := filepath.Join(dir, "audit.log")

		seg001 := filepath.Join(dir, "audit.log.001")
		lines := readLinesForFixture(t, seg001)
		// Mutate the middle record (seq 1) leaving its stored hash stale.
		lines[1] = strings.Replace(lines[1], `"actor":"fixture-agent"`, `"actor":"TAMPERED"`, 1)
		if !strings.Contains(lines[1], `"actor":"TAMPERED"`) {
			t.Fatalf("tamper substitution did not apply to line: %s", lines[1])
		}
		writeLinesForFixture(t, seg001, lines)

		c, err := NewChain(base)
		if err != nil {
			t.Fatalf("NewChain: %v", err)
		}
		r := c.Verify()
		if r.Valid {
			t.Fatalf("sub-case (a): expected tamper in seg001 to be detected, got valid=true msg=%q", r.Message)
		}
		if r.TamperDetectedAt == nil {
			t.Fatalf("sub-case (a): expected tamper_detected_at to be set, got nil (msg=%q)", r.Message)
		}
		// The tampered record is in the range of seq 0–2 (seg001 holds global seqs 0,1,2).
		if *r.TamperDetectedAt < 0 || *r.TamperDetectedAt > 2 {
			t.Fatalf("sub-case (a): expected tamper_detected_at in [0,2], got %d", *r.TamperDetectedAt)
		}
	})

	// sub-case (b): modified prev_hash of the first record in seg002 (seam tamper).
	t.Run("broken-seam-prev-hash-seg002", func(t *testing.T) {
		dir := t.TempDir()
		copySegmentFixtures(t, dir)
		base := filepath.Join(dir, "audit.log")

		seg002 := filepath.Join(dir, "audit.log.002")
		lines := readLinesForFixture(t, seg002)
		var rec map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
			t.Fatalf("unmarshal first record of seg002: %v", err)
		}
		rec["prev_hash"] = strings.Repeat("b", 64)
		out, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal tampered record: %v", err)
		}
		lines[0] = string(out)
		writeLinesForFixture(t, seg002, lines)

		c, err := NewChain(base)
		if err != nil {
			t.Fatalf("NewChain: %v", err)
		}
		r := c.Verify()
		if r.Valid {
			t.Fatalf("sub-case (b): expected broken seam to be detected, got valid=true msg=%q", r.Message)
		}
		if r.TamperDetectedAt == nil {
			t.Fatalf("sub-case (b): expected tamper_detected_at set, got nil (msg=%q)", r.Message)
		}
		// The seam break is at the first record of seg002 = global seq 3.
		if *r.TamperDetectedAt != 3 {
			t.Fatalf("sub-case (b): expected tamper_detected_at=3 (first record of seg002), got %d", *r.TamperDetectedAt)
		}
	})

	// sub-case (c): segment file removed from disk but still listed in the manifest.
	t.Run("dropped-segment-file", func(t *testing.T) {
		dir := t.TempDir()
		copySegmentFixtures(t, dir)
		base := filepath.Join(dir, "audit.log")

		if err := os.Remove(filepath.Join(dir, "audit.log.001")); err != nil {
			t.Fatalf("remove seg001: %v", err)
		}

		c, err := NewChain(base)
		if err != nil {
			t.Fatalf("NewChain: %v", err)
		}
		r := c.Verify()
		if r.Valid {
			t.Fatalf("sub-case (c): expected dropped segment to be detected, got valid=true msg=%q", r.Message)
		}
		if !strings.Contains(r.Message, "audit.log.001") {
			t.Fatalf("sub-case (c): expected message to name missing segment, got %q", r.Message)
		}
	})

	// sub-case (d): two segment entries swapped in the manifest.
	t.Run("swapped-manifest-entries", func(t *testing.T) {
		dir := t.TempDir()
		copySegmentFixtures(t, dir)
		base := filepath.Join(dir, "audit.log")

		m, err := loadManifest(filepath.Join(dir, "audit.log.manifest"))
		if err != nil {
			t.Fatalf("loadManifest: %v", err)
		}
		if len(m.Segments) < 2 {
			t.Fatalf("expected at least 2 manifest segments, got %d", len(m.Segments))
		}
		m.Segments[0], m.Segments[1] = m.Segments[1], m.Segments[0]
		if err := writeManifestAtomic(filepath.Join(dir, "audit.log.manifest"), m); err != nil {
			t.Fatalf("writeManifestAtomic: %v", err)
		}

		c, err := NewChain(base)
		if err != nil {
			t.Fatalf("NewChain: %v", err)
		}
		r := c.Verify()
		if r.Valid {
			t.Fatalf("sub-case (d): expected swapped manifest entries to be detected, got valid=true msg=%q", r.Message)
		}
	})
}

// TestRotationFitnessDocsAreUpdated verifies FF-010/FF-011 are in fitness-functions.md
// (TC-018-03: rotation targets wired into make fitness) and the coverage-tracker.md row
// for task 018 is present (TC-018-04: spec and coverage tracker updated).
func TestRotationFitnessDocsAreUpdated(t *testing.T) {
	docs := []struct {
		path  string
		terms []string
	}{
		{
			path: "docs/spec/fitness-functions.md",
			terms: []string{
				"FF-010",
				"FF-011",
				"`make fitness-rotation-tamper-detection`",
				"`make fitness-rotation-stability`",
			},
		},
		{
			path: "docs/tasks/test-specs/coverage-tracker.md",
			terms: []string{
				"018",
				"Rotation fitness and fixtures",
				"fitness-rotation-stability",
				"fitness-rotation-tamper-detection",
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

// readLinesForFixture reads the non-empty JSONL lines from a fixture file copy.
func readLinesForFixture(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readLinesForFixture: read %s: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// writeLinesForFixture writes JSONL lines to a fixture file copy.
func writeLinesForFixture(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("writeLinesForFixture: write %s: %v", path, err)
	}
}
