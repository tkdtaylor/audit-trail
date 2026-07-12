// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

// defaultQueryLimit / maxQueryLimit bound the "limit" field of a query request
// (REQ-020-03): default 100 results per page, hard cap 1000.
const (
	defaultQueryLimit = int64(100)
	maxQueryLimit     = int64(1000)
)

// QueryFilter is the set of optional, AND-combined filters accepted by runQuery. A nil field
// means "no constraint on this dimension". String fields are exact matches; the four range
// fields are inclusive int64 bounds.
type QueryFilter struct {
	Actor, Action, Target, Decision *string
	SeqMin, SeqMax, TsMin, TsMax    *int64
}

// QueryResponse is the shape of both the query IPC op's success response and the query CLI
// subcommand's stdout (REQ-020-01). Results are the stored JSONL lines verbatim, never
// re-marshalled (REQ-020-04). Verified/TamperDetectedAt/Message are always populated from a
// fresh verifyAllSegments walk (REQ-020-05): a query never refuses on a failing log.
type QueryResponse struct {
	Results          []json.RawMessage `json:"results"`
	Count            int64             `json:"count"`
	NextToken        *string           `json:"next_token"`
	Verified         bool              `json:"verified"`
	TamperDetectedAt *int64            `json:"tamper_detected_at"`
	Message          string            `json:"message"`
}

// queryFilterKeys are the only recognized keys in a query request's "filter" object
// (REQ-020-08: an unrecognized key is a bad_request).
var queryFilterKeys = map[string]bool{
	"actor": true, "action": true, "target": true, "decision": true,
	"seq_min": true, "seq_max": true, "ts_min": true, "ts_max": true,
}

// parseQueryRequest validates and decodes a decoded IPC request body into a QueryFilter plus
// the effective limit and resume seq (from an optional continuation token). It never touches
// disk; all failures here are client input errors (bad_request, REQ-020-08).
func parseQueryRequest(req map[string]any) (QueryFilter, int64, int64, error) {
	var f QueryFilter

	var filterRaw map[string]any
	if v, ok := req["filter"]; ok && v != nil {
		filterRaw, ok = v.(map[string]any)
		if !ok {
			return QueryFilter{}, 0, 0, fmt.Errorf("filter must be an object")
		}
	}
	for key := range filterRaw {
		if !queryFilterKeys[key] {
			return QueryFilter{}, 0, 0, fmt.Errorf("unknown filter key %q", key)
		}
	}

	var err error
	if f.Actor, err = queryStringField(filterRaw, "actor"); err != nil {
		return QueryFilter{}, 0, 0, err
	}
	if f.Action, err = queryStringField(filterRaw, "action"); err != nil {
		return QueryFilter{}, 0, 0, err
	}
	if f.Target, err = queryStringField(filterRaw, "target"); err != nil {
		return QueryFilter{}, 0, 0, err
	}
	if f.Decision, err = queryStringField(filterRaw, "decision"); err != nil {
		return QueryFilter{}, 0, 0, err
	}
	if f.SeqMin, err = queryIntField(filterRaw, "seq_min"); err != nil {
		return QueryFilter{}, 0, 0, err
	}
	if f.SeqMax, err = queryIntField(filterRaw, "seq_max"); err != nil {
		return QueryFilter{}, 0, 0, err
	}
	if f.TsMin, err = queryIntField(filterRaw, "ts_min"); err != nil {
		return QueryFilter{}, 0, 0, err
	}
	if f.TsMax, err = queryIntField(filterRaw, "ts_max"); err != nil {
		return QueryFilter{}, 0, 0, err
	}

	limit := defaultQueryLimit
	if v, ok := req["limit"]; ok && v != nil {
		n, err := queryIntValue(v, "limit")
		if err != nil {
			return QueryFilter{}, 0, 0, err
		}
		limit = n
	}
	if limit < 1 || limit > maxQueryLimit {
		return QueryFilter{}, 0, 0, fmt.Errorf("limit must be between 1 and %d, got %d", maxQueryLimit, limit)
	}

	var resumeSeq int64
	if v, ok := req["token"]; ok && v != nil {
		s, ok := v.(string)
		if !ok {
			return QueryFilter{}, 0, 0, fmt.Errorf("token must be a numeric string")
		}
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil || n < 0 {
			return QueryFilter{}, 0, 0, fmt.Errorf("token must be a numeric string, got %q", s)
		}
		resumeSeq = n
	}

	return f, limit, resumeSeq, nil
}

func queryStringField(filter map[string]any, key string) (*string, error) {
	v, ok := filter[key]
	if !ok || v == nil {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("filter.%s must be a string", key)
	}
	return &s, nil
}

func queryIntField(filter map[string]any, key string) (*int64, error) {
	v, ok := filter[key]
	if !ok || v == nil {
		return nil, nil
	}
	n, err := queryIntValue(v, "filter."+key)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// queryIntValue accepts a json.Number (the shape IPC requests decode to, via
// decodeIPCRequest's dec.UseNumber()) or a plain int64 (the shape a Go caller, e.g. a future
// in-process caller, might pass directly). Any fractional JSON number is rejected.
func queryIntValue(v any, path string) (int64, error) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer JSON number (%q)", path, x.String())
		}
		return n, nil
	case int64:
		return x, nil
	case int:
		return int64(x), nil
	default:
		return 0, fmt.Errorf("%s must be an integer", path)
	}
}

// matchesFilter reports whether the decoded record rec satisfies every non-nil constraint in f
// (AND semantics, REQ-020-02). rec is expected to have been decoded with a number-preserving
// decoder (json.Decoder.UseNumber) so seq/ts survive as json.Number for toInt64.
func matchesFilter(rec map[string]any, f QueryFilter) bool {
	if f.Actor != nil {
		v, _ := rec["actor"].(string)
		if v != *f.Actor {
			return false
		}
	}
	if f.Action != nil {
		v, _ := rec["action"].(string)
		if v != *f.Action {
			return false
		}
	}
	if f.Target != nil {
		v, _ := rec["target"].(string)
		if v != *f.Target {
			return false
		}
	}
	if f.Decision != nil {
		v, _ := rec["decision"].(string)
		if v != *f.Decision {
			return false
		}
	}
	if f.SeqMin != nil && toInt64(rec["seq"]) < *f.SeqMin {
		return false
	}
	if f.SeqMax != nil && toInt64(rec["seq"]) > *f.SeqMax {
		return false
	}
	if f.TsMin != nil && toInt64(rec["ts"]) < *f.TsMin {
		return false
	}
	if f.TsMax != nil && toInt64(rec["ts"]) > *f.TsMax {
		return false
	}
	return true
}

// queryableSegmentPaths returns, in the order runQuery must read them, the absolute paths of
// every segment a query walks: each manifest-listed rotated-out segment (oldest first) followed
// by the active segment at logPath (REQ-020-07). A never-rotated log (no manifest) returns just
// the active segment.
//
// The manifest is untrusted input (ADR-005 / ADR-006 §3): a segment filename is rejected before
// it is ever joined to the log directory unless it is a bare base filename, using the exact
// validation verifyAllSegments applies, so a forged manifest entry (e.g. "../evil") cannot make
// a query read outside the log directory.
func queryableSegmentPaths(logPath string) ([]string, error) {
	m, err := loadManifest(manifestPath(logPath))
	if err != nil {
		if os.IsNotExist(err) {
			return []string{logPath}, nil
		}
		return nil, fmt.Errorf("query: cannot read manifest: %w", err)
	}

	dir := filepath.Dir(logPath)
	paths := make([]string, 0, len(m.Segments)+1)
	for _, seg := range m.Segments {
		if seg.Segment == "" || seg.Segment == "." || seg.Segment == ".." ||
			seg.Segment != filepath.Base(seg.Segment) || filepath.IsAbs(seg.Segment) {
			return nil, fmt.Errorf("query: invalid segment filename in manifest: %s", seg.Segment)
		}
		paths = append(paths, filepath.Join(dir, seg.Segment))
	}
	paths = append(paths, logPath)
	return paths, nil
}

// runQuery is the core, read-only query walk (REQ-020-01..07). It streams every segment
// returned by queryableSegmentPaths in order, decoding each line only to test it against f and
// to read its seq. The returned Results are the untouched on-disk line bytes, never
// re-marshalled, re-hashed, or re-canonicalized (REQ-020-04). It opens every file O_RDONLY,
// takes no Chain.mu lock, and writes nothing (REQ-020-06); there is no persisted index (ADR-006
// section 1): every call re-walks the log from scratch.
//
// Pagination (REQ-020-03): resumeSeq is the inclusive lower bound on seq (from a prior
// next_token); at most limit records are returned. next_token, when non-nil, is the decimal
// string of one past the last *returned* record's seq, set only when at least one further
// matching record exists beyond the page, so a page that exactly exhausts the matches reports
// next_token:null rather than a phantom next page.
//
// Every response carries the outcome of a fresh verifyAllSegments(logPath) walk (REQ-020-05): a
// log that fails verification still returns its matching results, flagged verified:false
// (ADR-006 section 2): runQuery never refuses on a failing log.
func runQuery(logPath string, f QueryFilter, limit, resumeSeq int64) (QueryResponse, error) {
	segments, err := queryableSegmentPaths(logPath)
	if err != nil {
		return QueryResponse{}, err
	}

	results := []json.RawMessage{}
	var lastSeq int64
	haveLast := false
	var nextToken *string

scan:
	for _, segPath := range segments {
		file, ferr := os.OpenFile(segPath, os.O_RDONLY, 0)
		if ferr != nil {
			return QueryResponse{}, fmt.Errorf("query: open segment %s: %w", segPath, ferr)
		}

		sc := bufio.NewScanner(file)
		sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var rec map[string]any
			dec := json.NewDecoder(bytes.NewReader(line))
			dec.UseNumber()
			if derr := dec.Decode(&rec); derr != nil {
				// A corrupted line cannot be matched against the filter. It is not silently
				// hidden: the attached verifyAllSegments verdict on the response reports the
				// log as unverified/tampered whenever such a line exists.
				continue
			}
			seq := toInt64(rec["seq"])
			if seq < resumeSeq {
				continue
			}
			if !matchesFilter(rec, f) {
				continue
			}
			if int64(len(results)) < limit {
				raw := make([]byte, len(line))
				copy(raw, line)
				results = append(results, json.RawMessage(raw))
				lastSeq = seq
				haveLast = true
				continue
			}
			// The page is already full; this match proves at least one more result exists
			// beyond it. The resume cursor is one past the last record actually returned,
			// not this record's own seq, so resuming re-scans (and re-matches) from there.
			if haveLast {
				t := strconv.FormatInt(lastSeq+1, 10)
				nextToken = &t
			}
			_ = file.Close()
			break scan
		}
		if serr := sc.Err(); serr != nil {
			_ = file.Close()
			return QueryResponse{}, fmt.Errorf("query: read segment %s: %w", segPath, serr)
		}
		_ = file.Close()
	}

	_, verifyRes := verifyAllSegments(logPath)

	return QueryResponse{
		Results:          results,
		Count:            int64(len(results)),
		NextToken:        nextToken,
		Verified:         verifyRes.Valid,
		TamperDetectedAt: verifyRes.TamperDetectedAt,
		Message:          verifyRes.Message,
	}, nil
}

// errBadQueryRequest wraps every parseQueryRequest failure so queryIPCErrorCode can map it to
// the shared bad_request error code (REQ-020-08) without string-matching the message.
var errBadQueryRequest = fmt.Errorf("invalid query request")

// queryForIPC parses req (the decoded IPC request body) and runs the query against chain's
// logfile. Parse failures are wrapped in errBadQueryRequest; runQuery failures (e.g. an invalid
// manifest segment name, REQ-020-07) are returned unwrapped and surface as an internal error:
// they are a server-side data-integrity condition, not a malformed client request.
func queryForIPC(req map[string]any, chain *Chain) (QueryResponse, error) {
	f, limit, resumeSeq, err := parseQueryRequest(req)
	if err != nil {
		return QueryResponse{}, fmt.Errorf("%w: %s", errBadQueryRequest, err.Error())
	}
	return runQuery(chain.path, f, limit, resumeSeq)
}

// queryIPCErrorCode maps a queryForIPC error to the shared IPC error code.
func queryIPCErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errBadQueryRequest) {
		return "bad_request"
	}
	return "internal"
}

// marshalQueryResponseCompact and marshalQueryResponseIndent render a QueryResponse without Go's
// default HTML-escaping (which would otherwise rewrite '<', '>', and '&' inside a raw stored
// record's string fields, e.g. a target URL, when it is embedded via json.RawMessage). This
// keeps REQ-020-04's verbatim guarantee byte-exact end to end, not just at the json.RawMessage
// boundary: what went into the record at Emit time is exactly what comes out of query.
func marshalQueryResponseCompact(resp QueryResponse) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func marshalQueryResponseIndent(resp QueryResponse) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// writeQueryJSON writes resp to conn as a single newline-terminated JSON line, mirroring
// writeJSON's wire shape (ipc.go) but without HTML-escaping raw record bytes (see
// marshalQueryResponseCompact).
func writeQueryJSON(conn net.Conn, resp QueryResponse) {
	b, err := marshalQueryResponseCompact(resp)
	if err != nil {
		// Encoding a QueryResponse cannot fail in practice (no channels/funcs/cyclic data);
		// fall back to the shared error shape rather than writing nothing.
		writeJSON(conn, errShape("internal", err.Error()))
		return
	}
	_, _ = conn.Write(append(b, '\n'))
}
