package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempLog(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit.log")
}

func TestEmitVerifyAndTamperDetection(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := c.Emit(map[string]any{
			"actor": "vault", "action": "resolve", "target": "vault://test/k",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if r := c.Verify(); !r.Valid {
		t.Fatalf("expected valid chain, got %q", r.Message)
	}

	// one-character flip on a middle entry's content, hash left stale
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	lines[2] = strings.Replace(lines[2], `"actor":"vault"`, `"actor":"Vault"`, 1)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	r := c.Verify()
	if r.Valid {
		t.Fatal("expected tamper to be detected")
	}
	if r.TamperDetectedAt == nil || *r.TamperDetectedAt != 2 {
		t.Fatalf("expected tamper at seq 2, got %+v", r)
	}
}

func TestCanonicalIsOrderIndependent(t *testing.T) {
	a, _ := canonical(map[string]any{"target": "x", "actor": "a", "action": "net"})
	b, _ := canonical(map[string]any{"action": "net", "actor": "a", "target": "x"})
	if string(a) != string(b) {
		t.Fatalf("canonical not order-independent: %s vs %s", a, b)
	}
	if string(a) != `{"action":"net","actor":"a","target":"x"}` {
		t.Fatalf("unexpected canonical form: %s", a)
	}
}

func TestChainResumesFromDisk(t *testing.T) {
	path := tempLog(t)
	c1, _ := NewChain(path)
	c1.Emit(map[string]any{"actor": "a", "action": "x", "target": "t"})
	c1.Emit(map[string]any{"actor": "b", "action": "y", "target": "t"})

	c2, _ := NewChain(path) // reopen: must resume seq + prev_hash
	out, _ := c2.Emit(map[string]any{"actor": "c", "action": "z", "target": "t"})
	if out["seq"].(int64) != 2 {
		t.Fatalf("expected resumed seq 2, got %v", out["seq"])
	}
	if r := c2.Verify(); !r.Valid {
		t.Fatalf("chain invalid after resume: %q", r.Message)
	}
}

func TestEmitRejectsFloats(t *testing.T) {
	tests := []struct {
		name      string
		event     map[string]any
		wantParts []string
	}{
		{
			name: "context float",
			event: map[string]any{
				"actor": "a", "action": "x", "target": "t",
				"context": map[string]any{"score": 1.5},
			},
			wantParts: []string{"float", "context.score"},
		},
		{
			name: "nested context float",
			event: map[string]any{
				"actor": "a", "action": "x", "target": "t",
				"context": map[string]any{
					"items": []any{map[string]any{"score": float32(1.5)}},
				},
			},
			wantParts: []string{"float", "context.items[0].score"},
		},
		{
			name: "refs float",
			event: map[string]any{
				"actor": "a", "action": "x", "target": "t",
				"refs": []any{map[string]any{"type": "finding", "score": 1.5}},
			},
			wantParts: []string{"float", "refs[0].score"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tempLog(t)
			c, err := NewChain(path)
			if err != nil {
				t.Fatal(err)
			}

			_, err = c.Emit(tt.event)
			if err == nil {
				t.Fatal("expected float rejection error")
			}
			for _, part := range tt.wantParts {
				if !strings.Contains(err.Error(), part) {
					t.Fatalf("expected error %q to contain %q", err.Error(), part)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) != 0 {
				t.Fatalf("expected no appended records, got %q", data)
			}
		})
	}
}

func TestEmitAllowsNonFloatAuditedValues(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Emit(map[string]any{
		"ts":       int64(42),
		"actor":    "a",
		"action":   "x",
		"target":   "t",
		"decision": nil,
		"refs": []any{
			map[string]any{"type": "finding", "id": "F-1", "confirmed": true},
		},
		"context": map[string]any{
			"int":    int(1),
			"int64":  int64(2),
			"string": "ok",
			"bool":   true,
			"nil":    nil,
			"array":  []any{int64(3), "v", false, nil},
			"object": map[string]any{"nested": int64(4)},
		},
	})
	if err != nil {
		t.Fatalf("expected emit to allow non-float values: %v", err)
	}
	if r := c.Verify(); !r.Valid {
		t.Fatalf("expected valid chain, got %q", r.Message)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	delete(rec, "hash")
	rec["seq"] = toInt64(rec["seq"])
	rec["ts"] = toInt64(rec["ts"])
	if _, err := canonical(rec); err != nil {
		t.Fatalf("expected emitted record to remain canonicalizable: %v", err)
	}
}

func TestIPCNormalizesIntegerJSONNumbers(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}

	resp := ipcRoundTrip(t, c, `{"op":"emit","event":{"actor":"a","action":"x","target":"t","context":{"n":1}}}`)
	if resp["error"] != nil {
		t.Fatalf("expected successful emit, got %+v", resp)
	}
	if _, ok := resp["hash"].(string); !ok {
		t.Fatalf("expected hash in response, got %+v", resp)
	}
	seq, err := resp["seq"].(json.Number).Int64()
	if err != nil || seq != 0 {
		t.Fatalf("expected seq 0, got %v (err=%v)", resp["seq"], err)
	}

	verify := ipcRoundTrip(t, c, `{"op":"verify"}`)
	if verify["valid"] != true {
		t.Fatalf("expected valid verify response, got %+v", verify)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&rec); err != nil {
		t.Fatal(err)
	}
	context := rec["context"].(map[string]any)
	if got := context["n"].(json.Number).String(); got != "1" {
		t.Fatalf("expected stored integer JSON number 1, got %q", got)
	}
}

func TestIPCRejectsFractionalJSONNumbers(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}

	resp := ipcRoundTrip(t, c, `{"op":"emit","event":{"actor":"a","action":"x","target":"t","context":{"n":1.25}}}`)
	assertIPCError(t, resp, "bad_request", "non-integer JSON number", "event.context.n")
	if retryable := resp["error"].(map[string]any)["retryable"]; retryable != false {
		t.Fatalf("expected retryable false, got %+v", retryable)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("expected no appended records, got %q", data)
	}
}

func TestIPCMapsEmitValidationFailuresToBadRequest(t *testing.T) {
	err := fmt.Errorf("%w: audited event rejects float at context.score (float64)", errInvalidAuditEvent)
	if got := emitErrorCode(err); got != "bad_request" {
		t.Fatalf("expected validation failure to map to bad_request, got %q", got)
	}
	if got := emitErrorCode(os.ErrPermission); got != "internal" {
		t.Fatalf("expected non-validation failure to map to internal, got %q", got)
	}
}

func TestIPCPreservesExistingOpsAndErrors(t *testing.T) {
	path := tempLog(t)
	c, err := NewChain(path)
	if err != nil {
		t.Fatal(err)
	}

	ping := ipcRoundTrip(t, c, `{"op":"ping"}`)
	if ping["ok"] != true {
		t.Fatalf("expected ping ok, got %+v", ping)
	}

	verify := ipcRoundTrip(t, c, `{"op":"verify"}`)
	if verify["valid"] != true {
		t.Fatalf("expected verify valid, got %+v", verify)
	}

	malformed := ipcRoundTrip(t, c, `{"op":`)
	assertIPCError(t, malformed, "bad_request")

	unknown := ipcRoundTrip(t, c, `{"op":"unknown"}`)
	assertIPCError(t, unknown, "unknown_op", "unsupported op")

	trailing := ipcRoundTrip(t, c, `{"op":"ping"} {"op":"ping"}`)
	assertIPCError(t, trailing, "bad_request", "multiple JSON values")
}

func ipcRoundTrip(t *testing.T, c *Chain, req string) map[string]any {
	t.Helper()

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleConn(server, c)
		close(done)
	}()

	if _, err := client.Write([]byte(req + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	<-done

	var resp map[string]any
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func assertIPCError(t *testing.T, resp map[string]any, code string, messageParts ...string) {
	t.Helper()

	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error response, got %+v", resp)
	}
	if got := errObj["code"]; got != code {
		t.Fatalf("expected code %q, got %+v", code, got)
	}
	message, _ := errObj["message"].(string)
	for _, part := range messageParts {
		if !strings.Contains(message, part) {
			t.Fatalf("expected message %q to contain %q", message, part)
		}
	}
}
