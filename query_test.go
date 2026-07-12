// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// emitQueryFixture appends the exact 5-record fixture from the test spec
// (docs/tasks/test-specs/020-indexed-query-api-test-spec.md, "Fixture") to c, in order.
func emitQueryFixture(t *testing.T, c *Chain) {
	t.Helper()
	events := []map[string]any{
		{"ts": int64(1700000000), "actor": "vault", "action": "resolve", "target": "vault://db-creds", "decision": "allow"},
		{"ts": int64(1700000010), "actor": "policy-engine", "action": "evaluate", "target": "exec:rm", "decision": "deny"},
		{"ts": int64(1700000020), "actor": "vault", "action": "resolve", "target": "vault://api-key", "decision": "allow"},
		{"ts": int64(1700000030), "actor": "armor", "action": "scan", "target": "https://example.com", "decision": "flag"},
		{"ts": int64(1700000040), "actor": "vault", "action": "rotate", "target": "vault://db-creds", "decision": "allow"},
	}
	for i, ev := range events {
		if _, err := c.Emit(ev); err != nil {
			t.Fatalf("emit fixture record %d: %v", i, err)
		}
	}
}

// resultSeqs decodes each result's "seq" field, in order, for comparison against an expected
// seq set.
func resultSeqs(t *testing.T, results []json.RawMessage) []int64 {
	t.Helper()
	seqs := make([]int64, 0, len(results))
	for _, raw := range results {
		var rec map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		seqs = append(seqs, toInt64(rec["seq"]))
	}
	return seqs
}

func assertSeqs(t *testing.T, got []int64, want []int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("seqs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("seqs = %v, want %v", got, want)
		}
	}
}

// assertResultsAreStoredLinesVerbatim checks that every result element is byte-equal to the
// corresponding stored line read back from the logfile (REQ-020-04), not merely
// JSON-semantically equal after a re-marshal.
func assertResultsAreStoredLinesVerbatim(t *testing.T, logPath string, results []json.RawMessage) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	stored := map[int64]string{}
	for _, line := range splitNonEmptyLines(data) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		stored[toInt64(rec["seq"])] = line
	}
	for _, raw := range results {
		var rec map[string]any
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		seq := toInt64(rec["seq"])
		want, ok := stored[seq]
		if !ok {
			t.Fatalf("result seq %d has no corresponding stored line", seq)
		}
		if string(raw) != want {
			t.Fatalf("result for seq %d is not byte-equal to the stored line:\n got:  %s\n want: %s", seq, raw, want)
		}
	}
}

// TC-020-01: single-field filters return exact seq sets.
func TestQuerySingleFieldFilters(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	emitQueryFixture(t, c)

	str := func(s string) *string { return &s }

	cases := []struct {
		name string
		f    QueryFilter
		want []int64
	}{
		{"actor=vault", QueryFilter{Actor: str("vault")}, []int64{0, 2, 4}},
		{"action=resolve", QueryFilter{Action: str("resolve")}, []int64{0, 2}},
		{"target=vault://db-creds", QueryFilter{Target: str("vault://db-creds")}, []int64{0, 4}},
		{"decision=deny", QueryFilter{Decision: str("deny")}, []int64{1}},
		{"actor=nobody", QueryFilter{Actor: str("nobody")}, []int64{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := runQuery(logPath, tc.f, defaultQueryLimit, 0)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Count != int64(len(tc.want)) {
				t.Fatalf("count = %d, want %d", resp.Count, len(tc.want))
			}
			assertSeqs(t, resultSeqs(t, resp.Results), tc.want)
			if len(tc.want) > 0 {
				if !resp.Verified {
					t.Fatalf("expected verified:true, got false (%s)", resp.Message)
				}
				if resp.TamperDetectedAt != nil {
					t.Fatalf("expected tamper_detected_at:nil, got %v", *resp.TamperDetectedAt)
				}
				if resp.Message != "chain intact" {
					t.Fatalf("expected message %q, got %q", "chain intact", resp.Message)
				}
				assertResultsAreStoredLinesVerbatim(t, logPath, resp.Results)
			} else {
				if resp.NextToken != nil {
					t.Fatalf("expected next_token:nil for empty result set, got %q", *resp.NextToken)
				}
			}
		})
	}
}

// TC-020-02: combined filters and ranges, AND semantics, inclusive bounds.
func TestQueryCombinedFiltersAndRanges(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	emitQueryFixture(t, c)

	str := func(s string) *string { return &s }
	i64 := func(n int64) *int64 { return &n }

	cases := []struct {
		name string
		f    QueryFilter
		want []int64
	}{
		{"actor=vault AND action=resolve", QueryFilter{Actor: str("vault"), Action: str("resolve")}, []int64{0, 2}},
		{"seq_min=1 seq_max=3", QueryFilter{SeqMin: i64(1), SeqMax: i64(3)}, []int64{1, 2, 3}},
		{"ts_min=1700000010 ts_max=1700000030", QueryFilter{TsMin: i64(1700000010), TsMax: i64(1700000030)}, []int64{1, 2, 3}},
		{"actor=vault seq_min=2", QueryFilter{Actor: str("vault"), SeqMin: i64(2)}, []int64{2, 4}},
		{"actor=vault AND decision=deny (no match)", QueryFilter{Actor: str("vault"), Decision: str("deny")}, []int64{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := runQuery(logPath, tc.f, defaultQueryLimit, 0)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Count != int64(len(tc.want)) {
				t.Fatalf("count = %d, want %d (results=%v)", resp.Count, len(tc.want), resp.Results)
			}
			assertSeqs(t, resultSeqs(t, resp.Results), tc.want)
		})
	}
}

// TC-020-03: pagination, limit, continuation token, terminal page.
func TestQueryPagination(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	emitQueryFixture(t, c)

	actorVault := "vault"
	f := QueryFilter{Actor: &actorVault}

	// Page 1: limit 2 -> seq [0,2], count:2, next_token:"3".
	page1, err := runQuery(logPath, f, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertSeqs(t, resultSeqs(t, page1.Results), []int64{0, 2})
	if page1.Count != 2 {
		t.Fatalf("page1 count = %d, want 2", page1.Count)
	}
	if page1.NextToken == nil || *page1.NextToken != "3" {
		t.Fatalf("page1 next_token = %v, want \"3\"", page1.NextToken)
	}

	// Page 2: resubmit with the token -> seq [4], count:1, next_token:null (terminal page).
	resumeSeq, perr := strconv.ParseInt(*page1.NextToken, 10, 64)
	if perr != nil {
		t.Fatal(perr)
	}
	page2, err := runQuery(logPath, f, 2, resumeSeq)
	if err != nil {
		t.Fatal(err)
	}
	assertSeqs(t, resultSeqs(t, page2.Results), []int64{4})
	if page2.Count != 1 {
		t.Fatalf("page2 count = %d, want 1", page2.Count)
	}
	if page2.NextToken != nil {
		t.Fatalf("page2 next_token = %v, want nil", *page2.NextToken)
	}

	// limit:3 exactly exhausts the 3 matches -> next_token:null, no phantom next page.
	exact, err := runQuery(logPath, f, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertSeqs(t, resultSeqs(t, exact.Results), []int64{0, 2, 4})
	if exact.NextToken != nil {
		t.Fatalf("exact-limit next_token = %v, want nil", *exact.NextToken)
	}

	// Default limit (100, via defaultQueryLimit) returns all 3 matches, next_token:null.
	def, err := runQuery(logPath, f, defaultQueryLimit, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertSeqs(t, resultSeqs(t, def.Results), []int64{0, 2, 4})
	if def.NextToken != nil {
		t.Fatalf("default-limit next_token = %v, want nil", *def.NextToken)
	}
}

// TC-020-06: query spans segments after rotation.
func TestQuerySpansSegmentsAfterRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	emitQueryFixture(t, c) // seq 0..4, rotated out below

	_, priv := newSegmentSigningKey(t)
	if _, err := c.Rotate(5, "test-log", segmentIssuedAt, priv); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// One more vault event lands in the fresh active segment at seq 5.
	if _, err := c.Emit(map[string]any{
		"ts": int64(1700000050), "actor": "vault", "action": "resolve", "target": "vault://third-key",
	}); err != nil {
		t.Fatalf("emit post-rotation: %v", err)
	}

	actorVault := "vault"
	resp, err := runQuery(logPath, QueryFilter{Actor: &actorVault}, defaultQueryLimit, 0)
	if err != nil {
		t.Fatal(err)
	}
	// vault matches: seq 0, 2, 4 (rotated-out segment) and seq 5 (active segment).
	assertSeqs(t, resultSeqs(t, resp.Results), []int64{0, 2, 4, 5})
	if !resp.Verified {
		t.Fatalf("expected verified:true after rotation, got false (%s)", resp.Message)
	}

	// Manifest safety: a manifest whose segment field contains a path separator must not let
	// the query read outside the log directory. It returns an error result instead.
	m, err := loadManifest(manifestPath(logPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Segments) == 0 {
		t.Fatal("expected at least one manifest segment after rotation")
	}
	tampered := m
	tampered.Segments = append([]Segment{}, m.Segments...)
	tampered.Segments[0].Segment = "../evil"
	if err := writeManifestAtomic(manifestPath(logPath), tampered); err != nil {
		t.Fatal(err)
	}

	if _, err := runQuery(logPath, QueryFilter{Actor: &actorVault}, defaultQueryLimit, 0); err == nil {
		t.Fatal("expected runQuery to return an error for a manifest with a path-traversal segment name, got nil")
	}
}

// TC-020-09: docs/spec/interfaces.md, docs/spec/behaviors.md, and ADR-006 document the query
// surface, present tense, in the same commit as the code.
func TestQueryDocsAndADRAreUpdated(t *testing.T) {
	docs := []struct {
		path  string
		terms []string
	}{
		{
			path: "docs/spec/interfaces.md",
			terms: []string{
				"`query`",
				"--seq-min",
				"bad_request",
				`"op":"query"`,
			},
		},
		{
			path: "docs/spec/behaviors.md",
			terms: []string{
				"B-015",
				"verified:false",
			},
		},
		{
			path: "docs/architecture/decisions/006-indexed-query-api.md",
			terms: []string{
				"Status:** Accepted",
				"persisted index",
				"next_token",
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
