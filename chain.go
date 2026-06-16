package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

// Genesis is the prev_hash of the first entry in a chain.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

var errInvalidAuditEvent = errors.New("invalid audit event")

// Chain is an append-only, hash-chained, RFC 8785-canonicalized event log.
//
//	hash = SHA256( prev_hash + JCS(record_without_hash) )
//
// State is derived from the on-disk JSONL file, so the chain is resumable across restarts
// and Verify() re-reads from disk (it must, in order to detect a tamper).
type Chain struct {
	mu       sync.Mutex
	path     string
	seq      int64
	prevHash string
}

// NewChain opens (creating if absent) the log at path and resumes its state.
func NewChain(path string) (*Chain, error) {
	c := &Chain{path: path, seq: 0, prevHash: Genesis}
	if err := c.loadState(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Chain) loadState() error {
	// Recover the global offset from the manifest, if any. For a never-rotated log (no manifest)
	// this returns (0, Genesis) and behavior is identical to the single-file degenerate case.
	offset, head, err := manifestState(c.path)
	if err != nil {
		return err
	}
	c.seq = offset
	c.prevHash = head

	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return err
		}
		if h, ok := rec["hash"].(string); ok {
			c.prevHash = h
		}
		c.seq++
	}
	return sc.Err()
}

func hashRecord(prevHash string, recordWithoutHash map[string]any) (string, error) {
	cb, err := canonical(recordWithoutHash)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(cb)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Emit appends one event to the log and returns {seq, hash}.
func (c *Chain) Emit(event map[string]any) (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := validateEmitEventNoFloats(event); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidAuditEvent, err)
	}

	rec := map[string]any{
		"seq":       c.seq,
		"ts":        toInt64(event["ts"]),
		"actor":     event["actor"],
		"action":    event["action"],
		"target":    event["target"],
		"decision":  event["decision"],
		"refs":      orEmptyList(event["refs"]),
		"context":   orEmptyMap(event["context"]),
		"prev_hash": c.prevHash,
	}
	hash, err := hashRecord(c.prevHash, rec)
	if err != nil {
		return nil, err
	}
	rec["hash"] = hash

	line, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	out := map[string]any{"seq": c.seq, "hash": hash}
	c.seq++
	c.prevHash = hash
	return out, nil
}

func validateEmitEventNoFloats(event map[string]any) error {
	for _, field := range []string{"ts", "actor", "action", "target", "decision", "refs", "context"} {
		if err := rejectFloats(event[field], field); err != nil {
			return err
		}
	}
	return nil
}

func rejectFloats(v any, path string) error {
	return rejectFloatsValue(reflect.ValueOf(v), path)
}

func rejectFloatsValue(v reflect.Value, path string) error {
	if !v.IsValid() {
		return nil
	}

	switch v.Kind() {
	case reflect.Interface, reflect.Ptr:
		if v.IsNil() {
			return nil
		}
		return rejectFloatsValue(v.Elem(), path)
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("audited event rejects float at %s (%s)", path, v.Kind())
	case reflect.Map:
		for _, key := range v.MapKeys() {
			if err := rejectFloatsValue(v.MapIndex(key), childPath(path, key)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).PkgPath != "" {
				continue
			}
			if err := rejectFloatsValue(v.Field(i), childPath(path, reflect.ValueOf(t.Field(i).Name))); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := rejectFloatsValue(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func childPath(path string, key reflect.Value) string {
	if key.Kind() == reflect.String {
		if path == "" {
			return key.String()
		}
		return path + "." + key.String()
	}
	return fmt.Sprintf("%s[%v]", path, key.Interface())
}

// VerifyResult is the outcome of walking the chain.
type VerifyResult struct {
	Valid            bool   `json:"valid"`
	TamperDetectedAt *int64 `json:"tamper_detected_at"`
	Message          string `json:"message"`
}

type verifiedChainState struct {
	treeSize int64
	lastSeq  int64
	rootHash string
}

// Verify walks the on-disk chain. Deterministic and offline.
//
// For a never-rotated log (no manifest on disk) it is byte-for-byte identical to the original
// single-file walk (the degenerate 1-segment case). For a rotated log it loads the manifest and
// walks every rotated-out segment in manifest order plus the active segment, threading the
// carried ending prev_hash and seq offset from each segment into the next (Genesis/0 for the
// first), applying the cross-segment seam check at every boundary and cross-checking each
// segment's walked result against the manifest's recorded values. It always reads from disk and
// never trusts in-memory c.prevHash / c.seq (ADR-005 §3).
func (c *Chain) Verify() VerifyResult {
	return verifyAcrossSegments(c.path)
}

// verifyAcrossSegments is the cross-segment walker (REQ-016-01..07). It loads the manifest for
// the chain whose active segment is at logPath; with no manifest (or an empty one) it falls back
// to the exact single-file path so the degenerate case is unchanged.
func verifyAcrossSegments(logPath string) VerifyResult {
	m, err := loadManifest(manifestPath(logPath))
	if err != nil {
		if os.IsNotExist(err) {
			// Degenerate, never-rotated log: identical to the original single-file walk.
			_, res := verifyChainState(logPath)
			return res
		}
		return VerifyResult{Valid: false, Message: "cannot read manifest: " + err.Error()}
	}
	if len(m.Segments) == 0 {
		// A manifest FILE exists but lists zero segments. This is NOT the degenerate
		// never-rotated case (that path has no manifest at all and is handled above). An
		// attacker who rewrites the manifest to {"segments":[]} while leaving <base>.NNN
		// segments on disk would otherwise fall to the single-file walk and surface a generic
		// "prev_hash link broken" message. Run the SEC-003 orphan scan first so an uncovered
		// on-disk segment is named explicitly (fails closed either way; this is diagnostic
		// hardening — SEC-L01).
		highest, err := highestSegmentOnDisk(logPath)
		if err != nil {
			return VerifyResult{Valid: false, Message: "cannot scan segments: " + err.Error()}
		}
		if highest > 0 {
			orphan := segmentPath(logPath, 1)
			return VerifyResult{Valid: false,
				Message: "on-disk segment beyond manifest coverage: " + filepath.Base(orphan)}
		}
		_, res := verifyChainState(logPath)
		return res
	}

	dir := filepath.Dir(logPath)
	prev := Genesis
	var offset int64 // global record count accounted for by earlier segments

	// Walk each rotated-out segment in manifest order, threading the carried head + offset.
	for _, seg := range m.Segments {
		// The manifest is untrusted input: reject any segment field that is not a bare base
		// filename before joining it to the log directory, so a manifest entry like
		// "../something" or an absolute path cannot reach a file outside the log dir
		// (SEC-I01). filepath.Base collapses any path; if it differs, the field carried a
		// separator or "..".
		if seg.Segment == "" || seg.Segment == "." || seg.Segment == ".." ||
			seg.Segment != filepath.Base(seg.Segment) || filepath.IsAbs(seg.Segment) {
			return VerifyResult{Valid: false,
				Message: "invalid segment filename in manifest: " + seg.Segment}
		}
		segFile := filepath.Join(dir, seg.Segment)

		// Dropped segment: listed in the manifest but missing from disk (REQ-016-04).
		if _, statErr := os.Stat(segFile); statErr != nil {
			if os.IsNotExist(statErr) {
				at := offset
				return VerifyResult{Valid: false, TamperDetectedAt: &at,
					Message: "segment missing from disk: " + seg.Segment}
			}
			return VerifyResult{Valid: false, Message: "cannot stat segment " + seg.Segment + ": " + statErr.Error()}
		}

		// Walk the segment from the ACTUAL carried head + offset (derived from on-disk hashes,
		// NOT from the manifest's recorded values — the manifest is an index, not the root of
		// trust). A broken first-record prev_hash here is the seam check (REQ-016-02/05): a
		// reordered or seam-tampered segment fails to link to the prior segment's real head.
		state, res := verifyChainStateFrom(segFile, prev, offset)
		if !res.Valid {
			return res
		}

		// Manifest-vs-content cross-check (SEC-002 / ADR-005 Integrity risks): the manifest's
		// recorded start_prev_hash / first_seq / last_seq / end_hash must match what the segment
		// actually contains on disk. A forged manifest field cannot make an intact chain pass
		// nor mask a tampered one.
		if seg.StartPrevHash != prev {
			at := offset
			return VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "manifest start_prev_hash mismatch for segment " + seg.Segment}
		}
		if seg.FirstSeq != offset {
			at := offset
			return VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "manifest first_seq mismatch for segment " + seg.Segment}
		}
		if seg.LastSeq != state.lastSeq {
			at := state.lastSeq
			return VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "manifest last_seq mismatch for segment " + seg.Segment}
		}
		if seg.EndHash != state.rootHash {
			at := state.lastSeq
			return VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "manifest end_hash mismatch for segment " + seg.Segment}
		}

		prev = state.rootHash
		offset = state.treeSize
	}

	// Orphan / truncation defense (SEC-003): refuse to silently treat the chain as a clean
	// shorter log when on-disk <base>.NNN segments exist beyond the manifest's coverage (e.g. a
	// crash mid-rotate left a rotated-out segment unlisted). highestSegmentOnDisk returns 0 when
	// there are no rotated-out files at all, so this never trips the degenerate no-segments case.
	highest, err := highestSegmentOnDisk(logPath)
	if err != nil {
		return VerifyResult{Valid: false, Message: "cannot scan segments: " + err.Error()}
	}
	if highest > int64(len(m.Segments)) {
		orphan := segmentPath(logPath, int64(len(m.Segments))+1)
		return VerifyResult{Valid: false,
			Message: "on-disk segment beyond manifest coverage: " + filepath.Base(orphan)}
	}

	// Finally walk the active segment at logPath, carrying the last rotated-out segment's head
	// and offset. The seam between the last rotated-out segment and the active segment is checked
	// here too (the active segment's first record must link to the prior head).
	_, res := verifyChainStateFrom(logPath, prev, offset)
	return res
}

// verifyChainState walks a single segment from Genesis with a zero offset. This is the
// degenerate, never-rotated case and is byte-for-byte identical to the original behavior.
func verifyChainState(path string) (verifiedChainState, VerifyResult) {
	return verifyChainStateFrom(path, Genesis, 0)
}

// verifyChainStateFrom is the parameterized segment walker (ADR-005 §3). It walks the records
// in path expecting the first record's prev_hash to equal startPrev (Genesis for segment 0,
// the previous segment's end hash otherwise) and treats startOffset as the number of records
// already accounted for by earlier segments. The returned treeSize is the cumulative global
// record count (startOffset + records walked) and lastSeq/rootHash are the global chain head
// as of this segment's last record. With (Genesis, 0) it reproduces the single-file behavior.
func verifyChainStateFrom(path, startPrev string, startOffset int64) (verifiedChainState, VerifyResult) {
	f, err := os.Open(path)
	if err != nil {
		return verifiedChainState{}, VerifyResult{Valid: false, Message: "cannot open log: " + err.Error()}
	}
	defer f.Close()

	state := verifiedChainState{treeSize: startOffset, lastSeq: startOffset - 1, rootHash: startPrev}
	prev := startPrev
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	i := startOffset
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec map[string]any
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&rec); err != nil {
			at := i
			return verifiedChainState{}, VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "entry is not valid JSON (corrupted)"}
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			at := i
			return verifiedChainState{}, VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "entry is not valid JSON (corrupted)"}
		}
		normalized, err := normalizeJSONNumbers(rec, "entry")
		if err != nil {
			at := seqOf(rec, i)
			return verifiedChainState{}, VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: err.Error()}
		}
		rec = normalized
		recPrev, _ := rec["prev_hash"].(string)
		if recPrev != prev {
			at := seqOf(rec, i)
			return verifiedChainState{}, VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "prev_hash link broken"}
		}
		stored, _ := rec["hash"].(string)
		body := make(map[string]any, len(rec))
		for k, v := range rec {
			if k != "hash" {
				body[k] = v
			}
		}
		computed, err := hashRecord(recPrev, body)
		if err != nil {
			at := seqOf(rec, i)
			return verifiedChainState{}, VerifyResult{Valid: false, TamperDetectedAt: &at, Message: err.Error()}
		}
		if computed != stored {
			at := seqOf(rec, i)
			return verifiedChainState{}, VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "content hash mismatch (tampered)"}
		}
		prev = stored
		state.lastSeq = seqOf(rec, i)
		state.rootHash = stored
		state.treeSize++
		i++
	}
	if err := sc.Err(); err != nil {
		return verifiedChainState{}, VerifyResult{Valid: false, Message: "cannot read log: " + err.Error()}
	}
	return state, VerifyResult{Valid: true, Message: "chain intact"}
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	default:
		return 0
	}
}

func seqOf(rec map[string]any, fallback int64) int64 {
	if s, ok := rec["seq"]; ok {
		return toInt64(s)
	}
	return fallback
}

func orEmptyList(v any) any {
	if v == nil {
		return []any{}
	}
	return v
}

func orEmptyMap(v any) any {
	if v == nil {
		return map[string]any{}
	}
	return v
}
