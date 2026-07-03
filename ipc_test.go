// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The IPC socket must be owner-only from the moment it exists — a group- or
// world-accessible socket would let any local user emit into the forensic log.
func TestListenUnixSocketPermsOwnerOnly(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "audit-trail.sock")
	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket permissions = %04o, want 0600", got)
	}
}

// Rebinding over a stale socket file must succeed (the old path is removed first).
func TestListenUnixRebindsOverStaleSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "audit-trail.sock")
	ln1, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("first listenUnix: %v", err)
	}
	_ = ln1.Close()

	ln2, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("rebind listenUnix: %v", err)
	}
	defer func() { _ = ln2.Close() }()
}
