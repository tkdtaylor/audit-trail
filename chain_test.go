package main

import (
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
