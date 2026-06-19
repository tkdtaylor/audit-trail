// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// ManifestFormat is the literal manifest format tag (ADR-005 Data schemas).
	ManifestFormat = "audit-trail-manifest-v1"
	// ManifestVersion is the literal manifest schema version.
	ManifestVersion = int64(1)
	// CheckpointSuffix is appended to a rotated-out segment's filename to name its checkpoint.
	CheckpointSuffix = ".checkpoint"
	// ManifestSuffix is appended to the chain base path to name the manifest file.
	ManifestSuffix = ".manifest"
)

// errBelowRotationThreshold is the sentinel returned by Rotate when the active segment holds
// fewer records than the configured threshold. Nothing on disk is touched in this case.
var errBelowRotationThreshold = errors.New("active segment is below rotation threshold")

// errSegmentExists is returned by Rotate when the computed target segment path already exists
// on disk. The manifest is an attacker-controlled index (not the root of trust), so a forged,
// truncated, or deleted manifest could otherwise drive Rotate to a low segment number and
// os.Rename would silently clobber an existing <base>.NNN segment. Rotate refuses instead
// (SEC-001).
var errSegmentExists = errors.New("rotate: refusing to overwrite existing segment")

// Segment is one ordered entry in a SegmentManifest. It records the global seq range, the
// chain head at the segment's start and end, and when the segment was rotated out. Field types
// are integers only (int64) — this project rejects floats in audited data and keeps manifest
// counters byte-stable.
type Segment struct {
	Segment       string `json:"segment"`         // segment filename, e.g. "audit.log.001"
	FirstSeq      int64  `json:"first_seq"`       // global seq of the segment's first record
	LastSeq       int64  `json:"last_seq"`        // global seq of the segment's last record
	StartPrevHash string `json:"start_prev_hash"` // prev_hash the first record must carry (Genesis for segment 0)
	EndHash       string `json:"end_hash"`        // hash of the segment's last record (chain head at this boundary)
	IssuedAt      int64  `json:"issued_at"`       // Unix seconds when the segment was rotated out
}

// SegmentManifest is the ordered index of rotated-out segments written at <base>.manifest. It
// is a convenience index for enumeration, not the root of trust — tamper-evidence stays
// cryptographic (ADR-005 Integrity risks).
type SegmentManifest struct {
	Format   string    `json:"format"`
	Version  int64     `json:"version"`
	Segments []Segment `json:"segments"`
}

// manifestPath returns the manifest path for a chain whose active segment is at logPath.
func manifestPath(logPath string) string {
	return logPath + ManifestSuffix
}

// segmentPath returns the rotated-out segment path for the n-th rotation (1-based), zero-padded
// to three digits: audit.log.001, audit.log.002, ...
func segmentPath(logPath string, n int64) string {
	return fmt.Sprintf("%s.%03d", logPath, n)
}

// checkpointPath returns the per-segment checkpoint path for a rotated-out segment file.
func checkpointPath(segPath string) string {
	return segPath + CheckpointSuffix
}

// highestSegmentOnDisk scans logPath's directory for existing rotated-out segments named
// <base>.NNN (three-or-more-digit, zero-padded suffix) and returns the highest N present, or 0
// when none exist. Unlike the manifest length, this reflects what is actually on disk, so the
// next segment number derived from it cannot be driven backwards by a forged/truncated manifest
// into clobbering a real segment (SEC-001). Checkpoint sidecars (<base>.NNN.checkpoint) and
// other suffixes are ignored.
func highestSegmentOnDisk(logPath string) (int64, error) {
	matches, err := filepath.Glob(logPath + ".[0-9]*")
	if err != nil {
		return 0, fmt.Errorf("glob segments: %w", err)
	}
	prefix := logPath + "."
	var highest int64
	for _, p := range matches {
		suffix := strings.TrimPrefix(p, prefix)
		// Reject anything that is not a pure run of digits (e.g. ".001.checkpoint").
		if suffix == "" || strings.ContainsFunc(suffix, func(r rune) bool { return r < '0' || r > '9' }) {
			continue
		}
		var n int64
		if _, err := fmt.Sscanf(suffix, "%d", &n); err != nil {
			continue
		}
		if n > highest {
			highest = n
		}
	}
	return highest, nil
}

// loadManifest reads and decodes the manifest at path. A missing manifest is reported via
// os.IsNotExist on the returned error so callers can treat it as the degenerate (never-rotated)
// case.
func loadManifest(path string) (SegmentManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SegmentManifest{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m SegmentManifest
	if err := dec.Decode(&m); err != nil {
		return SegmentManifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return SegmentManifest{}, fmt.Errorf("decode manifest: multiple JSON values")
	}
	return m, nil
}

// writeManifestAtomic writes m to path atomically: it marshals to a temp file in the same
// directory (mode 0600), fsyncs, then renames over path. A concurrent reader therefore sees
// either the old manifest or the complete new one, never a partial write (ADR-005 §5).
func writeManifestAtomic(path string, m SegmentManifest) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp manifest: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we fail before the rename succeeds.
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp manifest: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp manifest: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp manifest: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename manifest: %w", err)
	}
	tmpName = "" // rename succeeded; suppress cleanup
	return nil
}

// countRecords returns the number of non-blank records in the file at path. A missing file
// counts as zero records.
func countRecords(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	var n int64
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return n, nil
}

// manifestState returns the cumulative record count and the chain head (end hash of the last
// listed segment) recorded in the manifest at logPath. For a never-rotated log (no manifest) it
// returns (0, Genesis), i.e. the degenerate starting point.
func manifestState(logPath string) (offset int64, head string, err error) {
	m, err := loadManifest(manifestPath(logPath))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, Genesis, nil
		}
		return 0, Genesis, err
	}
	if len(m.Segments) == 0 {
		return 0, Genesis, nil
	}
	last := m.Segments[len(m.Segments)-1]
	// Cumulative record count up to and including the last rotated-out segment.
	return last.LastSeq + 1, last.EndHash, nil
}

// RotateResult describes the outcome of a Rotate call.
type RotateResult struct {
	// Rotated is false when the active segment was below threshold (no files were touched).
	Rotated bool `json:"rotated"`
	// Segment is the rotated-out segment filename (empty when Rotated is false).
	Segment string `json:"segment,omitempty"`
	// FirstSeq / LastSeq are the global seq range of the rotated-out segment.
	FirstSeq int64 `json:"first_seq,omitempty"`
	LastSeq  int64 `json:"last_seq,omitempty"`
	// Checkpoint is the per-segment checkpoint path (empty when Rotated is false).
	Checkpoint string `json:"checkpoint,omitempty"`
}

// Rotate closes the active segment when it holds at least threshold records, archiving it as a
// zero-padded sibling (<base>.NNN), writing a signed checkpoint over the cumulative chain head
// at that boundary, appending the manifest entry atomically, and opening a fresh active segment
// at the same path. Chain state (c.seq / c.prevHash) is carried over so the seam links: the
// next Emit's prev_hash equals the rotated-out segment's last hash (ADR-005 §2).
//
// Below threshold it touches no files and returns errBelowRotationThreshold with
// RotateResult{Rotated:false}. The whole operation runs under c.mu (single-writer, ADR-005 §5).
func (c *Chain) Rotate(threshold int64, logID string, issuedAt int64, privateKey ed25519.PrivateKey) (RotateResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	active, err := countRecords(c.path)
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate: count active segment: %w", err)
	}
	if active < threshold {
		return RotateResult{Rotated: false}, errBelowRotationThreshold
	}

	// Determine the cumulative starting point for the active segment from the manifest.
	startOffset, startPrev, err := manifestState(c.path)
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate: read manifest state: %w", err)
	}

	// Verify the active segment from disk, carrying the prior segment's end hash and offset so
	// the checkpoint commits to the GLOBAL chain head at this boundary (ADR-005 §4).
	state, res := verifyChainStateFrom(c.path, startPrev, startOffset)
	if !res.Valid {
		return RotateResult{}, fmt.Errorf("rotate: %w: %s", errInvalidCheckpointLog, res.Message)
	}

	payload := CheckpointPayload{
		Format:        CheckpointFormat,
		Version:       CheckpointVersion,
		Contract:      CheckpointContract,
		LogID:         logID,
		TreeSize:      state.treeSize,
		LastSeq:       state.lastSeq,
		RootHash:      state.rootHash,
		HashAlgorithm: CheckpointHashAlgorithm,
		IssuedAt:      issuedAt,
	}
	signed, err := SignCheckpointPayload(payload, privateKey)
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate: sign checkpoint: %w", err)
	}
	checkpointBytes, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate: marshal checkpoint: %w", err)
	}

	// Load the manifest so we can append to it. The manifest is an untrusted index, so its
	// length is NOT used to pick the next segment number (a forged/truncated manifest could
	// drive that backwards and clobber an existing segment, SEC-001).
	m, err := loadManifest(manifestPath(c.path))
	if err != nil && !os.IsNotExist(err) {
		return RotateResult{}, fmt.Errorf("rotate: load manifest: %w", err)
	}
	if os.IsNotExist(err) {
		m = SegmentManifest{Format: ManifestFormat, Version: ManifestVersion}
	}

	// Derive the next zero-padded segment number from the actual on-disk segment files, not the
	// manifest length, so a tampered manifest cannot make us overwrite a real segment.
	highest, err := highestSegmentOnDisk(c.path)
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate: scan segments: %w", err)
	}
	segNum := highest + 1
	segPath := segmentPath(c.path, segNum)

	// Defence in depth: even with the disk-derived number, refuse to rename over an existing
	// segment rather than let os.Rename silently clobber it. The TOCTOU window is under c.mu
	// (single-writer), so no concurrent writer can create the file between this stat and the
	// rename.
	if _, err := os.Stat(segPath); err == nil {
		return RotateResult{}, fmt.Errorf("%w: %s", errSegmentExists, segPath)
	} else if !os.IsNotExist(err) {
		return RotateResult{}, fmt.Errorf("rotate: stat target segment: %w", err)
	}

	// (b) rename the active segment to its <base>.NNN sibling.
	if err := os.Rename(c.path, segPath); err != nil {
		return RotateResult{}, fmt.Errorf("rotate: rename active segment: %w", err)
	}

	// (c) write the per-segment checkpoint file (mode 0600).
	cpPath := checkpointPath(segPath)
	if err := os.WriteFile(cpPath, checkpointBytes, 0o600); err != nil {
		return RotateResult{}, fmt.Errorf("rotate: write checkpoint: %w", err)
	}

	// (d) append the manifest entry and write it atomically.
	m.Format = ManifestFormat
	m.Version = ManifestVersion
	m.Segments = append(m.Segments, Segment{
		Segment:       filepath.Base(segPath),
		FirstSeq:      startOffset,
		LastSeq:       state.lastSeq,
		StartPrevHash: startPrev,
		EndHash:       state.rootHash,
		IssuedAt:      issuedAt,
	})
	if err := writeManifestAtomic(manifestPath(c.path), m); err != nil {
		return RotateResult{}, fmt.Errorf("rotate: write manifest: %w", err)
	}

	// (e) open a fresh active segment at c.path WITHOUT resetting c.prevHash / c.seq so the
	// seam links automatically on the next Emit.
	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate: open new active segment: %w", err)
	}
	if err := f.Close(); err != nil {
		return RotateResult{}, fmt.Errorf("rotate: close new active segment: %w", err)
	}

	return RotateResult{
		Rotated:    true,
		Segment:    filepath.Base(segPath),
		FirstSeq:   startOffset,
		LastSeq:    state.lastSeq,
		Checkpoint: filepath.Base(cpPath),
	}, nil
}
