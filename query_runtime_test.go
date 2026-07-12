// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startQueryTestDaemon builds nothing (the binary is built once by the caller). It starts a
// real `audit-trail serve` subprocess against socketPath/logfilePath and waits for the socket to
// accept connections. No checkpoint/rotation configuration is passed: this exercises the same
// "rotation not configured" daemon posture as TC-020-07's existing-ops check.
func startQueryTestDaemon(t *testing.T, binaryPath, socketPath, logfilePath string) {
	t.Helper()
	cmd := exec.Command(binaryPath, "serve", "--socket", socketPath, "--logfile", logfilePath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	var lastErr error
	for i := 0; i < 50; i++ {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			_ = conn.Close()
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("daemon socket never became available: %v", lastErr)
}

// sendQueryIPCRaw sends req to the live daemon at socketPath and returns the raw response
// bytes, unparsed: needed wherever a test must check byte-exact content (REQ-020-04), since
// decoding into map[string]any loses the raw formatting of nested elements.
func sendQueryIPCRaw(t *testing.T, socketPath, req string) []byte {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial socket: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(req + "\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return respBytes
}

// sendQueryIPC sends req and decodes the response with number preservation.
func sendQueryIPC(t *testing.T, socketPath, req string) map[string]any {
	t.Helper()
	raw := sendQueryIPCRaw(t, socketPath, req)
	var resp map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	return resp
}

// emitQueryFixtureViaIPC appends the test spec fixture (see emitQueryFixture in query_test.go)
// through the live daemon's "emit" op, in order.
func emitQueryFixtureViaIPC(t *testing.T, socketPath string) {
	t.Helper()
	events := []string{
		`{"op":"emit","event":{"ts":1700000000,"actor":"vault","action":"resolve","target":"vault://db-creds","decision":"allow"}}`,
		`{"op":"emit","event":{"ts":1700000010,"actor":"policy-engine","action":"evaluate","target":"exec:rm","decision":"deny"}}`,
		`{"op":"emit","event":{"ts":1700000020,"actor":"vault","action":"resolve","target":"vault://api-key","decision":"allow"}}`,
		`{"op":"emit","event":{"ts":1700000030,"actor":"armor","action":"scan","target":"https://example.com","decision":"flag"}}`,
		`{"op":"emit","event":{"ts":1700000040,"actor":"vault","action":"rotate","target":"vault://db-creds","decision":"allow"}}`,
	}
	for i, req := range events {
		resp := sendQueryIPC(t, socketPath, req)
		if resp["error"] != nil {
			t.Fatalf("emit fixture record %d failed: %+v", i, resp["error"])
		}
	}
}

func flipHexChar(hash string) string {
	if hash == "" {
		return hash
	}
	b := []byte(hash)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

func buildAuditTrailBinary(t *testing.T) string {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "audit-trail")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile audit-trail binary: %v\n%s", err, stderr.String())
	}
	return binaryPath
}

// TestQueryRuntimeSurface covers the runtime-observable slice of task 020: TC-020-04 (raw
// tampered bytes over live IPC), TC-020-05 (failed verification is surfaced, not refused, read
// fresh from disk), TC-020-07 (malformed requests + existing ops unchanged), and TC-020-08 (the
// CLI query subcommand's live exit codes). It builds the real audit-trail binary once and drives
// it as a real `serve` subprocess / real CLI invocations, mirroring the pattern in
// rekor_runtime_test.go.
func TestQueryRuntimeSurface(t *testing.T) {
	binaryPath := buildAuditTrailBinary(t)

	// TC-020-04: results are stored bytes, never recomputed. A tamper travels with the
	// evidence instead of being hidden by a re-marshal.
	t.Run("TC-020-04_tamper_returns_raw_bytes_over_ipc", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "audit.log")
		socketPath := filepath.Join(dir, "audit.sock")
		startQueryTestDaemon(t, binaryPath, socketPath, logPath)
		emitQueryFixtureViaIPC(t, socketPath)

		// Tamper record seq 1 on disk: "evaluate" -> "evaluatX" (same length, same byte
		// count, so no other record's on-disk position shifts).
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		tampered := bytes.Replace(data, []byte(`"action":"evaluate"`), []byte(`"action":"evaluatX"`), 1)
		if bytes.Equal(tampered, data) {
			t.Fatal("tamper replacement matched no bytes in the logfile")
		}
		if err := os.WriteFile(logPath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}

		var storedLine []byte
		for _, line := range splitNonEmptyLines(tampered) {
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			if toInt64(rec["seq"]) == 1 {
				storedLine = []byte(line)
				break
			}
		}
		if storedLine == nil {
			t.Fatal("could not locate the tampered seq-1 line on disk")
		}

		raw := sendQueryIPCRaw(t, socketPath, `{"op":"query","filter":{"actor":"policy-engine"}}`)
		if !bytes.Contains(raw, storedLine) {
			t.Fatalf("response does not contain the tampered stored line verbatim:\nresponse: %s\nstored:   %s", raw, storedLine)
		}

		resp := sendQueryIPC(t, socketPath, `{"op":"query","filter":{"actor":"policy-engine"}}`)
		if resp["verified"] != false {
			t.Fatalf("expected verified:false, got %+v", resp["verified"])
		}
		tamperAt, ok := resp["tamper_detected_at"].(json.Number)
		if !ok {
			t.Fatalf("expected tamper_detected_at to be a number, got %+v", resp["tamper_detected_at"])
		}
		if tamperAt.String() != "1" {
			t.Fatalf("expected tamper_detected_at:1, got %s", tamperAt.String())
		}
		if msg, _ := resp["message"].(string); msg != "content hash mismatch (tampered)" {
			t.Fatalf("expected message %q, got %q", "content hash mismatch (tampered)", msg)
		}
	})

	// TC-020-05: a failing log is not refused; results are still returned, verified comes
	// from a fresh disk walk, not the daemon's in-memory chain state.
	t.Run("TC-020-05_failed_verification_surfaced_not_refused", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "audit.log")
		socketPath := filepath.Join(dir, "audit.sock")
		startQueryTestDaemon(t, binaryPath, socketPath, logPath)
		emitQueryFixtureViaIPC(t, socketPath)

		// Tamper record seq 3's stored hash field externally, behind the running daemon's back.
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := splitNonEmptyLines(data)
		found := false
		for i, line := range lines {
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatal(err)
			}
			if toInt64(rec["seq"]) != 3 {
				continue
			}
			hash, _ := rec["hash"].(string)
			if hash == "" {
				t.Fatal("seq 3 record missing hash")
			}
			flipped := flipHexChar(hash)
			lines[i] = strings.Replace(line, `"hash":"`+hash+`"`, `"hash":"`+flipped+`"`, 1)
			found = true
			break
		}
		if !found {
			t.Fatal("could not locate seq-3 record to tamper")
		}
		out := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(logPath, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}

		resp := sendQueryIPC(t, socketPath, `{"op":"query","filter":{"actor":"vault"}}`)
		if _, isErr := resp["error"]; isErr {
			t.Fatalf("query on a failing log must not return an error envelope, got %+v", resp)
		}
		if resp["verified"] != false {
			t.Fatalf("expected verified:false, got %+v", resp["verified"])
		}
		if resp["tamper_detected_at"] == nil {
			t.Fatalf("expected non-null tamper_detected_at, got %+v", resp)
		}

		results, ok := resp["results"].([]any)
		if !ok {
			t.Fatalf("expected a results array, got %+v", resp["results"])
		}
		var gotSeqs []int64
		for _, r := range results {
			rm, ok := r.(map[string]any)
			if !ok {
				t.Fatalf("result element is not an object: %+v", r)
			}
			gotSeqs = append(gotSeqs, toInt64(rm["seq"]))
		}
		want := []int64{0, 2, 4}
		if len(gotSeqs) != len(want) {
			t.Fatalf("result seqs = %v, want %v", gotSeqs, want)
		}
		for i := range want {
			if gotSeqs[i] != want[i] {
				t.Fatalf("result seqs = %v, want %v", gotSeqs, want)
			}
		}
	})

	// TC-020-07: malformed requests return the shared bad_request shape; existing ops are
	// byte-shape-identical now that "query" exists alongside them.
	t.Run("TC-020-07_malformed_requests_and_unchanged_ops", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "audit.log")
		socketPath := filepath.Join(dir, "audit.sock")
		startQueryTestDaemon(t, binaryPath, socketPath, logPath)
		emitQueryFixtureViaIPC(t, socketPath)

		malformed := []string{
			`{"op":"query","filter":{"bogus":"x"}}`,
			`{"op":"query","filter":{"ts_min":1.5}}`,
			`{"op":"query","filter":{"actor":7}}`,
			`{"op":"query","limit":0}`,
			`{"op":"query","limit":5000}`,
			`{"op":"query","token":"abc"}`,
			`{"op":"query","filter":"vault"}`,
		}
		for _, req := range malformed {
			resp := sendQueryIPC(t, socketPath, req)
			assertIPCError(t, resp, "bad_request")
			if _, hasResults := resp["results"]; hasResults {
				t.Fatalf("bad_request response for %s must not carry a results field, got %+v", req, resp)
			}
		}

		emitResp := sendQueryIPC(t, socketPath, `{"op":"emit","event":{"actor":"a","action":"x","target":"t"}}`)
		if emitResp["seq"] == nil || emitResp["hash"] == nil {
			t.Fatalf("emit response shape changed: %+v", emitResp)
		}
		verifyResp := sendQueryIPC(t, socketPath, `{"op":"verify"}`)
		if verifyResp["valid"] != true {
			t.Fatalf("verify response changed: %+v", verifyResp)
		}
		if _, ok := verifyResp["tamper_detected_at"]; !ok {
			t.Fatalf("verify response missing tamper_detected_at: %+v", verifyResp)
		}
		pingResp := sendQueryIPC(t, socketPath, `{"op":"ping"}`)
		if pingResp["ok"] != true {
			t.Fatalf("ping response changed: %+v", pingResp)
		}
		rotateResp := sendQueryIPC(t, socketPath, `{"op":"rotate"}`)
		assertIPCError(t, rotateResp, "rotation_not_configured")
	})

	// TC-020-08: the CLI query subcommand's live exit codes and stdout/stderr shape.
	t.Run("TC-020-08_cli_query_subcommand", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "audit.log")

		c, err := NewChain(logPath)
		if err != nil {
			t.Fatal(err)
		}
		emitQueryFixture(t, c)

		runCLI := func(args ...string) (stdout, stderr string, exitCode int) {
			cmd := exec.Command(binaryPath, args...)
			var out, errBuf bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &errBuf
			runErr := cmd.Run()
			code := 0
			if runErr != nil {
				exitErr, ok := runErr.(*exec.ExitError)
				if !ok {
					t.Fatalf("failed to run CLI %v: %v", args, runErr)
				}
				code = exitErr.ExitCode()
			}
			return out.String(), errBuf.String(), code
		}

		decodeStdout := func(stdout string) map[string]any {
			var resp map[string]any
			dec := json.NewDecoder(strings.NewReader(stdout))
			dec.UseNumber()
			if err := dec.Decode(&resp); err != nil {
				t.Fatalf("decode stdout %q: %v", stdout, err)
			}
			return resp
		}

		// audit-trail query --logfile <log> --actor vault --limit 2
		stdout, stderr, code := runCLI("query", "--logfile", logPath, "--actor", "vault", "--limit", "2")
		if code != 0 {
			t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr)
		}
		resp := decodeStdout(stdout)
		if resp["count"].(json.Number).String() != "2" {
			t.Fatalf("count = %v, want 2", resp["count"])
		}
		if resp["next_token"] != "3" {
			t.Fatalf(`next_token = %v, want "3"`, resp["next_token"])
		}
		if resp["verified"] != true {
			t.Fatalf("verified = %v, want true", resp["verified"])
		}
		results, _ := resp["results"].([]any)
		if len(results) != 2 {
			t.Fatalf("results len = %d, want 2", len(results))
		}
		for _, r := range results {
			rm := r.(map[string]any)
			if rm["actor"] != "vault" {
				t.Fatalf("result actor = %v, want vault", rm["actor"])
			}
		}

		// audit-trail query --logfile <log> --actor vault --token 3
		stdout2, stderr2, code2 := runCLI("query", "--logfile", logPath, "--actor", "vault", "--token", "3")
		if code2 != 0 {
			t.Fatalf("exit code = %d, want 0; stderr=%s", code2, stderr2)
		}
		resp2 := decodeStdout(stdout2)
		if resp2["next_token"] != nil {
			t.Fatalf("next_token = %v, want nil", resp2["next_token"])
		}
		results2, _ := resp2["results"].([]any)
		if len(results2) != 1 {
			t.Fatalf("results len = %d, want 1", len(results2))
		}

		// Tamper the log, rerun: exit stays 0, verified:false with a non-null tamper_detected_at.
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		tampered := bytes.Replace(data, []byte(`"target":"exec:rm"`), []byte(`"target":"exec:XX"`), 1)
		if bytes.Equal(tampered, data) {
			t.Fatal("tamper replacement matched no bytes in the logfile")
		}
		if err := os.WriteFile(logPath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		stdout3, stderr3, code3 := runCLI("query", "--logfile", logPath, "--actor", "vault")
		if code3 != 0 {
			t.Fatalf("exit code = %d, want 0 (verified:false must not change the exit code); stderr=%s", code3, stderr3)
		}
		resp3 := decodeStdout(stdout3)
		if resp3["verified"] != false {
			t.Fatalf("verified = %v, want false", resp3["verified"])
		}
		if resp3["tamper_detected_at"] == nil {
			t.Fatal("tamper_detected_at = nil, want non-null")
		}

		// audit-trail query --logfile <log> --limit 0 -> exit 2, usage message on stderr.
		_, stderr4, code4 := runCLI("query", "--logfile", logPath, "--limit", "0")
		if code4 != 2 {
			t.Fatalf("exit code = %d, want 2", code4)
		}
		if stderr4 == "" {
			t.Fatal("expected a usage message on stderr for --limit 0")
		}

		// Missing logfile path -> exit 1 with "error:" on stderr.
		missingPath := filepath.Join(dir, "does-not-exist.log")
		_, stderr5, code5 := runCLI("query", "--logfile", missingPath)
		if code5 != 1 {
			t.Fatalf("exit code = %d, want 1", code5)
		}
		if !strings.Contains(stderr5, "error:") {
			t.Fatalf("expected stderr to contain %q, got %q", "error:", stderr5)
		}
	})
}
