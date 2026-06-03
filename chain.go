package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

// Verify walks the on-disk chain. Deterministic and offline.
func (c *Chain) Verify() VerifyResult {
	f, err := os.Open(c.path)
	if err != nil {
		return VerifyResult{Valid: false, Message: "cannot open log: " + err.Error()}
	}
	defer f.Close()

	prev := Genesis
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	i := int64(0)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			at := i
			return VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "entry is not valid JSON (corrupted)"}
		}
		recPrev, _ := rec["prev_hash"].(string)
		if recPrev != prev {
			at := seqOf(rec, i)
			return VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "prev_hash link broken"}
		}
		stored, _ := rec["hash"].(string)
		body := make(map[string]any, len(rec))
		for k, v := range rec {
			if k != "hash" {
				body[k] = v
			}
		}
		// normalize JSON-decoded numbers back to int64 so canonicalization is stable
		body["seq"] = toInt64(body["seq"])
		body["ts"] = toInt64(body["ts"])
		computed, err := hashRecord(recPrev, body)
		if err != nil {
			at := seqOf(rec, i)
			return VerifyResult{Valid: false, TamperDetectedAt: &at, Message: err.Error()}
		}
		if computed != stored {
			at := seqOf(rec, i)
			return VerifyResult{Valid: false, TamperDetectedAt: &at,
				Message: "content hash mismatch (tampered)"}
		}
		prev = stored
		i++
	}
	return VerifyResult{Valid: true, Message: "chain intact"}
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
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
