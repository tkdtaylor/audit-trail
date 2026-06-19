// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRekorRuntimeIntegration(t *testing.T) {
	// Compile the audit-trail binary for CLI tests
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "audit-trail")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile audit-trail binary: %v", err)
	}

	// 1. Setup operator keys
	opEdPriv, opEdPub := deterministicCheckpointKey(2)
	opEdPubDer, err := x509.MarshalPKIXPublicKey(opEdPub)
	if err != nil {
		t.Fatal(err)
	}
	opEdPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: opEdPubDer})
	opEdPrivDer, err := x509.MarshalPKCS8PrivateKey(opEdPriv)
	if err != nil {
		t.Fatal(err)
	}
	opEdPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: opEdPrivDer})

	opPubPath := filepath.Join(tmpDir, "operator-pub.pem")
	os.WriteFile(opPubPath, opEdPubPEM, 0o600)
	opPrivPath := filepath.Join(tmpDir, "operator-priv.pem")
	os.WriteFile(opPrivPath, opEdPrivPEM, 0o600)

	// Setup Rekor keys
	rekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rekorPubDer, err := x509.MarshalPKIXPublicKey(&rekorKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rekorPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rekorPubDer})
	rekorPubPath := filepath.Join(tmpDir, "rekor-pub.pem")
	os.WriteFile(rekorPubPath, rekorPubPEM, 0o600)

	// Create a logfile and emit an event to have something to checkpoint
	logPath := filepath.Join(tmpDir, "audit.log")
	chain, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = chain.Emit(map[string]any{"actor": "test", "action": "create", "target": "resource"})
	if err != nil {
		t.Fatal(err)
	}

	// Generate a signed checkpoint
	checkpoint, err := chain.CreateSignedCheckpoint("test-log", time.Now().Unix(), opEdPriv)
	if err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(tmpDir, "checkpoint.json")
	checkpointBytes, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(checkpointPath, checkpointBytes, 0o600)

	// Setup mock Rekor server
	expectedEntryID := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	expectedLogID := "c0ee4787a2da8cb5f41fa6e0a8b9f0ee"
	expectedLogIndex := int64(42)
	expectedIntegratedTime := int64(1700000000)

	hr, err := CheckpointHashedRekord(checkpoint, opEdPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBytes, err := CanonicalHashedRekordBytes(hr)
	if err != nil {
		t.Fatal(err)
	}
	bodyStr := base64.StdEncoding.EncodeToString(canonicalBytes)
	setSig := signMockSET(t, rekorKey, bodyStr, expectedIntegratedTime, expectedLogID, expectedLogIndex)

	rekorMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" && r.URL.Path == "/api/v1/log/entries" {
			w.WriteHeader(http.StatusCreated)
			respJSON := fmt.Sprintf(`{
				%q: {
					"body": %q,
					"integratedTime": %d,
					"logID": %q,
					"logIndex": %d,
					"verification": {
						"signedEntryTimestamp": %q
					}
				}
			}`, expectedEntryID, bodyStr, expectedIntegratedTime, expectedLogID, expectedLogIndex, setSig)
			w.Write([]byte(respJSON))
			return
		}
		if r.Method == "GET" && r.URL.Path == "/api/v1/log/entries/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
			w.WriteHeader(http.StatusOK)
			respJSON := fmt.Sprintf(`{
				"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890": {
					"body": %q,
					"integratedTime": %d,
					"logID": %q,
					"logIndex": %d,
					"verification": {
						"signedEntryTimestamp": %q
					}
				}
			}`, bodyStr, expectedIntegratedTime, expectedLogID, expectedLogIndex, setSig)
			w.Write([]byte(respJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rekorMock.Close()

	// 2. Test CLI `checkpoint anchor`
	receiptPath := filepath.Join(tmpDir, "receipt.json")
	anchorCmd := exec.Command(binaryPath, "checkpoint", "anchor",
		"--checkpoint", checkpointPath,
		"--rekor-url", rekorMock.URL,
		"--public-key", opPubPath,
		"--out", receiptPath,
	)
	var stderr bytes.Buffer
	anchorCmd.Stderr = &stderr
	if err := anchorCmd.Run(); err != nil {
		t.Fatalf("checkpoint anchor CLI command failed: %v, stderr: %s", err, stderr.String())
	}

	// Verify receipt file exists and parses
	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt RekorReceipt
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatalf("failed to parse generated receipt: %v", err)
	}
	if receipt.EntryID != expectedEntryID || receipt.LogIndex != expectedLogIndex {
		t.Errorf("receipt properties mismatch: %+v", receipt)
	}

	// 3. Test CLI `checkpoint verify-anchor` (offline)
	verifyOfflineCmd := exec.Command(binaryPath, "checkpoint", "verify-anchor",
		"--checkpoint", checkpointPath,
		"--receipt", receiptPath,
		"--rekor-public-key", rekorPubPath,
		"--public-key", opPubPath,
	)
	var offlineStdout, offlineStderr bytes.Buffer
	verifyOfflineCmd.Stdout = &offlineStdout
	verifyOfflineCmd.Stderr = &offlineStderr
	if err := verifyOfflineCmd.Run(); err != nil {
		t.Fatalf("checkpoint verify-anchor offline CLI command failed: %v, stdout: %s, stderr: %s", err, offlineStdout.String(), offlineStderr.String())
	}
	var offlineRes RekorCheckpointVerificationResult
	if err := json.Unmarshal(offlineStdout.Bytes(), &offlineRes); err != nil {
		t.Fatal(err)
	}
	if !offlineRes.Valid || !offlineRes.SignatureValid || !offlineRes.RekorValid || offlineRes.RekorOnlineMatch != nil {
		t.Errorf("unexpected offline verification result: %+v", offlineRes)
	}

	// 4. Test CLI `checkpoint verify-anchor` (online)
	verifyOnlineCmd := exec.Command(binaryPath, "checkpoint", "verify-anchor",
		"--checkpoint", checkpointPath,
		"--receipt", receiptPath,
		"--rekor-public-key", rekorPubPath,
		"--rekor-url", rekorMock.URL,
	)
	var onlineStdout, onlineStderr bytes.Buffer
	verifyOnlineCmd.Stdout = &onlineStdout
	verifyOnlineCmd.Stderr = &onlineStderr
	if err := verifyOnlineCmd.Run(); err != nil {
		t.Fatalf("checkpoint verify-anchor online CLI command failed: %v, stderr: %s", err, onlineStderr.String())
	}
	var onlineRes RekorCheckpointVerificationResult
	if err := json.Unmarshal(onlineStdout.Bytes(), &onlineRes); err != nil {
		t.Fatal(err)
	}
	if !onlineRes.Valid || !onlineRes.SignatureValid || !onlineRes.RekorValid || onlineRes.RekorOnlineMatch == nil || !*onlineRes.RekorOnlineMatch {
		t.Errorf("unexpected online verification result: %+v", onlineRes)
	}

	// 5. Test Daemon Startup Flags and IPC Operations
	socketPath := filepath.Join(tmpDir, "audit.sock")
	daemonCmd := exec.Command(binaryPath, "serve",
		"--socket", socketPath,
		"--logfile", logPath,
		"--checkpoint-log-id", "test-log",
		"--checkpoint-signing-key", opPrivPath,
		"--checkpoint-public-key", opPubPath,
		"--rekor-url", rekorMock.URL,
		"--rekor-public-key", rekorPubPath,
	)
	if err := daemonCmd.Start(); err != nil {
		t.Fatalf("failed to start daemon: %v", err)
	}
	defer func() {
		_ = daemonCmd.Process.Kill()
	}()

	// Wait for socket to become available
	var conn net.Conn
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		conn, err = net.Dial("unix", socketPath)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("failed to connect to daemon socket: %v", err)
	}
	conn.Close()

	// Helper to send IPC requests
	sendIPC := func(req map[string]any) (map[string]any, error) {
		c, err := net.Dial("unix", socketPath)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		reqBytes, _ := json.Marshal(req)
		c.Write(append(reqBytes, '\n'))
		respBytes, err := io.ReadAll(c)
		if err != nil {
			return nil, err
		}
		var resp map[string]any
		if err := json.Unmarshal(respBytes, &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	// Test IPC ping
	pingResp, err := sendIPC(map[string]any{"op": "ping"})
	if err != nil {
		t.Fatal(err)
	}
	if pingResp["ok"] != true {
		t.Errorf("ping failed: %+v", pingResp)
	}

	// Test IPC checkpoint_anchor
	anchorResp, err := sendIPC(map[string]any{"op": "checkpoint_anchor"})
	if err != nil {
		t.Fatal(err)
	}
	if anchorResp["error"] != nil {
		t.Fatalf("checkpoint_anchor IPC returned error: %+v", anchorResp["error"])
	}
	if anchorResp["entry_id"] != expectedEntryID {
		t.Errorf("unexpected entry_id in IPC anchor response: %v", anchorResp["entry_id"])
	}

	// Test IPC checkpoint_verify (offline)
	verifyIPCResp, err := sendIPC(map[string]any{
		"op":         "checkpoint_verify",
		"checkpoint": checkpoint,
		"receipt":    receipt,
		"online":     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verifyIPCResp["error"] != nil {
		t.Fatalf("checkpoint_verify IPC returned error: %+v", verifyIPCResp["error"])
	}
	if verifyIPCResp["valid"] != true || verifyIPCResp["signature_valid"] != true || verifyIPCResp["rekor_valid"] != true {
		t.Errorf("unexpected IPC verify response: %+v", verifyIPCResp)
	}

	// Test IPC checkpoint_verify (online)
	verifyIPCOnlineResp, err := sendIPC(map[string]any{
		"op":         "checkpoint_verify",
		"checkpoint": checkpoint,
		"receipt":    receipt,
		"online":     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verifyIPCOnlineResp["error"] != nil {
		t.Fatalf("checkpoint_verify online IPC returned error: %+v", verifyIPCOnlineResp["error"])
	}
	if verifyIPCOnlineResp["valid"] != true || verifyIPCOnlineResp["rekor_online_match"] != true {
		t.Errorf("unexpected IPC online verify response: %+v", verifyIPCOnlineResp)
	}

	// 6. Test Security Mitigations: Reject client-submitted URLs or paths
	badPayloads := []map[string]any{
		{"op": "checkpoint_verify", "checkpoint": checkpoint, "receipt": receipt, "rekor_url": "http://evil.com"},
		{"op": "checkpoint_verify", "checkpoint": checkpoint, "receipt": receipt, "public_key_path": "/etc/passwd"},
		{"op": "checkpoint_verify", "checkpoint": checkpoint, "receipt": receipt, "signing_key": "some-key"},
	}
	for _, badPayload := range badPayloads {
		badResp, err := sendIPC(badPayload)
		if err != nil {
			t.Fatal(err)
		}
		errObj, ok := badResp["error"].(map[string]any)
		if !ok || errObj["code"] != "bad_request" || !strings.Contains(errObj["message"].(string), "rejected") {
			t.Errorf("expected bad_request rejection for payload %+v, got %+v", badPayload, badResp)
		}
	}

	// Kill current daemon
	_ = daemonCmd.Process.Kill()
	daemonCmd.Wait()

	// 7. Test Daemon started without Rekor URL returning checkpoint_not_configured
	daemonNoRekorCmd := exec.Command(binaryPath, "serve",
		"--socket", socketPath,
		"--logfile", logPath,
		"--checkpoint-log-id", "test-log",
		"--checkpoint-signing-key", opPrivPath,
		"--checkpoint-public-key", opPubPath,
	)
	if err := daemonNoRekorCmd.Start(); err != nil {
		t.Fatalf("failed to start daemon without Rekor: %v", err)
	}
	defer func() {
		_ = daemonNoRekorCmd.Process.Kill()
	}()

	// Wait for socket
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		conn, err = net.Dial("unix", socketPath)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("failed to connect to daemon socket: %v", err)
	}
	conn.Close()

	// Send checkpoint_anchor
	noRekorResp, err := sendIPC(map[string]any{"op": "checkpoint_anchor"})
	if err != nil {
		t.Fatal(err)
	}
	errObj, ok := noRekorResp["error"].(map[string]any)
	if !ok || errObj["code"] != "checkpoint_not_configured" {
		t.Errorf("expected checkpoint_not_configured, got %+v", noRekorResp)
	}
}
