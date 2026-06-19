// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestKeyPair writes an Ed25519 key pair to temp files and returns their paths.
func writeTestKeyPair(t *testing.T, dir string) (privatePath, publicPath string, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Write private key (PKCS8).
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privatePath = filepath.Join(dir, "private.pem")
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDer})
	if err := os.WriteFile(privatePath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// Write public key (SPKI).
	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	publicPath = filepath.Join(dir, "public.pem")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	if err := os.WriteFile(publicPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	return privatePath, publicPath, priv, pub
}

// rotateViaChain exercises Chain.Rotate and returns the RotateResult as a map[string]any.
// It is the same code path as cmdRotate (which calls Rotate and prints JSON).
func rotateViaChain(t *testing.T, c *Chain, threshold int64, logID, signingKeyPath string) (map[string]any, error) {
	t.Helper()
	privateKey, err := LoadCheckpointSigningKey(signingKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	res, rotErr := c.Rotate(threshold, logID, 1700000000, privateKey)
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out, rotErr
}

// TC-017-01: CLI rotate command triggers rotation and reports the result as JSON.
func TestCLIRotateCommandTriggersRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	privatePath, _, _, _ := writeTestKeyPair(t, dir)

	// Populate the log with enough records to exceed the threshold.
	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	const n = 5
	emitN(t, c, n)

	// Exercise the same logic as cmdRotate (threshold 5, at threshold → should rotate).
	result, rotErr := rotateViaChain(t, c, n, "test-log", privatePath)
	if rotErr != nil {
		t.Fatalf("rotate returned error: %v", rotErr)
	}

	// Rotation must report rotated:true.
	if result["rotated"] != true {
		t.Fatalf("expected rotated:true, got %+v", result)
	}

	// Segment and checkpoint fields must be non-empty strings.
	seg, _ := result["segment"].(string)
	if seg == "" {
		t.Fatalf("expected non-empty segment field, got %+v", result)
	}
	cpField, _ := result["checkpoint"].(string)
	if cpField == "" {
		t.Fatalf("expected non-empty checkpoint field, got %+v", result)
	}

	// Rotated-out segment file exists at the ADR-005-specified path (<base>.001).
	segOnDisk := filepath.Join(dir, seg)
	if _, err := os.Stat(segOnDisk); err != nil {
		t.Fatalf("rotated segment file missing on disk: %v", err)
	}

	// Signed checkpoint sidecar exists (<base>.001.checkpoint).
	cpOnDisk := filepath.Join(dir, cpField)
	if _, err := os.Stat(cpOnDisk); err != nil {
		t.Fatalf("checkpoint file missing on disk: %v", err)
	}

	// New active segment must exist (empty) at logPath.
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("new active segment missing: %v", err)
	}
	activeCount, err := countRecords(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if activeCount != 0 {
		t.Fatalf("new active segment must be empty after rotation, got %d records", activeCount)
	}
}

// TC-017-01 (below threshold): CLI rotate returns rotated:false when count < threshold.
func TestCLIRotateBelowThreshold(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	privatePath, _, _, _ := writeTestKeyPair(t, dir)

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	emitN(t, c, 3)

	// Threshold is 10, which is above the 3 records — decline expected.
	result, rotErr := rotateViaChain(t, c, 10, "test-log", privatePath)
	if rotErr != errBelowRotationThreshold {
		t.Fatalf("expected errBelowRotationThreshold, got %v", rotErr)
	}

	if result["rotated"] != false {
		t.Fatalf("expected rotated:false below threshold, got %+v", result)
	}
	// No segment file should exist.
	if _, err := os.Stat(filepath.Join(dir, "audit.log.001")); !os.IsNotExist(err) {
		t.Fatalf("expected no segment file after declined rotation")
	}
}

// TC-017-02: after a rotation, CLI verify (via Chain.Verify) walks all segments and returns valid.
func TestCLIVerifyAfterRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	_, _, priv, _ := writeTestKeyPair(t, dir)

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	const n = 5
	emitN(t, c, n)

	if _, err := c.Rotate(n, "test-log", 1700000000, priv); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Emit more records into the new active segment.
	emitN(t, c, 3)

	// Verify via Chain.Verify — the same path cmdVerify uses.
	c2, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	res := c2.Verify()
	if !res.Valid {
		t.Fatalf("verify after rotation returned invalid: %s", res.Message)
	}
	if res.TamperDetectedAt != nil {
		t.Fatalf("expected tamper_detected_at:null, got %v", *res.TamperDetectedAt)
	}
	if res.Message != "chain intact" {
		t.Fatalf("expected message 'chain intact', got %q", res.Message)
	}
}

// TC-017-03: IPC rotate operation succeeds when rotation is configured and threshold is met.
func TestIPCRotateSucceeds(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	privatePath, _, _, _ := writeTestKeyPair(t, dir)

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	const n = 5
	emitN(t, c, n)

	config := CheckpointServerConfig{
		LogID:          "ipc-log",
		SigningKeyPath: privatePath,
		RotateAfter:    int64(n),
	}

	resp := ipcRoundTripWithConfig(t, c, config, `{"op":"rotate"}`)
	if resp["error"] != nil {
		t.Fatalf("expected rotate success, got error: %+v", resp)
	}
	if resp["rotated"] != true {
		t.Fatalf("expected rotated:true, got %+v", resp)
	}
	seg, _ := resp["segment"].(string)
	if seg == "" {
		t.Fatalf("expected non-empty segment in response, got %+v", resp)
	}

	// Rotated-out segment exists on disk.
	segOnDisk := filepath.Join(dir, seg)
	if _, err := os.Stat(segOnDisk); err != nil {
		t.Fatalf("rotated segment missing on disk: %v", err)
	}

	// Signed checkpoint sidecar exists. A successful rotation MUST always emit a checkpoint, so
	// assert the field is present and the file is on disk unconditionally.
	cpField, _ := resp["checkpoint"].(string)
	if cpField == "" {
		t.Fatalf("expected non-empty checkpoint in response, got %+v", resp)
	}
	cpOnDisk := filepath.Join(dir, cpField)
	if _, err := os.Stat(cpOnDisk); err != nil {
		t.Fatalf("checkpoint file missing on disk: %v", err)
	}
}

// TC-017-03 (below threshold over IPC): IPC rotate returns rotated:false (not an error) when
// the active segment is below the configured threshold.
func TestIPCRotateBelowThresholdReturnsResult(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	privatePath, _, _, _ := writeTestKeyPair(t, dir)

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	emitN(t, c, 3)

	config := CheckpointServerConfig{
		LogID:          "ipc-log",
		SigningKeyPath: privatePath,
		RotateAfter:    int64(10), // above 3 records → decline
	}

	resp := ipcRoundTripWithConfig(t, c, config, `{"op":"rotate"}`)
	// Below-threshold is NOT an error — it returns a result with rotated:false.
	if resp["error"] != nil {
		t.Fatalf("expected rotated:false result (not error), got: %+v", resp)
	}
	if resp["rotated"] != false {
		t.Fatalf("expected rotated:false below threshold, got %+v", resp)
	}
}

// TC-017-04: IPC rotate without any rotation configuration returns the shared error shape.
func TestIPCRotateNotConfigured(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	emitN(t, c, 3)

	// No rotation config at all (empty CheckpointServerConfig, RotateAfter == 0).
	resp := ipcRoundTrip(t, c, `{"op":"rotate"}`)
	assertIPCError(t, resp, "rotation_not_configured", "rotation not configured")

	// TC-017-04: the shared error shape must carry an explicit retryable:false (a missing
	// configuration is not transient — retrying without reconfiguring will fail identically).
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %+v", resp)
	}
	if _, present := errObj["retryable"]; !present {
		t.Fatalf("error shape missing retryable field: %+v", errObj)
	}
	if errObj["retryable"] != false {
		t.Fatalf("expected retryable:false, got %+v", errObj["retryable"])
	}
}

// TC-017-04: missing signing key returns rotation_not_configured.
func TestIPCRotateMissingSigningKeyNotConfigured(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	emitN(t, c, 3)

	// RotateAfter is set but SigningKeyPath is missing.
	configMissingKey := CheckpointServerConfig{
		LogID:       "test-log",
		RotateAfter: 2,
		// SigningKeyPath intentionally empty.
	}
	resp := ipcRoundTripWithConfig(t, c, configMissingKey, `{"op":"rotate"}`)
	assertIPCError(t, resp, "rotation_not_configured", "rotation not configured")
}

// TC-017-04: daemon does not crash or partially rotate on the not-configured error path.
func TestIPCRotateNotConfiguredNoCrashOrPartialRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	emitN(t, c, 5)

	// Trigger not-configured error.
	resp := ipcRoundTrip(t, c, `{"op":"rotate"}`)
	assertIPCError(t, resp, "rotation_not_configured", "")

	// Daemon must still be usable after the error: emit and verify work.
	emitResp := ipcRoundTrip(t, c, `{"op":"emit","event":{"actor":"a","action":"x","target":"t"}}`)
	if emitResp["error"] != nil {
		t.Fatalf("emit after rotate-not-configured error failed: %+v", emitResp)
	}
	if emitResp["seq"] == nil {
		t.Fatalf("expected emit response with seq, got %+v", emitResp)
	}

	verifyResp := ipcRoundTrip(t, c, `{"op":"verify"}`)
	if verifyResp["valid"] != true {
		t.Fatalf("verify after rotate-not-configured returned invalid: %+v", verifyResp)
	}

	// No partial rotation: no segment file, no manifest.
	if _, err := os.Stat(filepath.Join(dir, "audit.log.001")); !os.IsNotExist(err) {
		t.Fatal("expected no segment file after not-configured error")
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.manifest")); !os.IsNotExist(err) {
		t.Fatal("expected no manifest after not-configured error")
	}
}

// TC-017-04: IPC rejects client-submitted key fields even on the rotate op.
func TestIPCRotateRejectsClientSubmittedKeyFields(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}

	// Client tries to submit a signing_key — must be rejected with bad_request.
	resp := ipcRoundTrip(t, c, `{"op":"rotate","signing_key":"/etc/private.pem"}`)
	assertIPCError(t, resp, "bad_request", "signing_key")
}

// TC-017-05: existing IPC ops produce unchanged response shapes after a rotation.
func TestIPCExistingOpsUnchangedAfterRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	privatePath, publicPath, _, _ := writeTestKeyPair(t, dir)

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	const n = 5
	emitN(t, c, n)

	// Rotate via IPC.
	config := CheckpointServerConfig{
		LogID:          "test-log",
		SigningKeyPath: privatePath,
		PublicKeyPath:  publicPath,
		RotateAfter:    int64(n),
	}
	rotResp := ipcRoundTripWithConfig(t, c, config, `{"op":"rotate"}`)
	if rotResp["rotated"] != true {
		t.Fatalf("rotation failed: %+v", rotResp)
	}

	// emit: appends to the new active segment, returns {seq, hash}.
	emitResp := ipcRoundTripWithConfig(t, c, config, `{"op":"emit","event":{"actor":"a","action":"x","target":"t"}}`)
	if emitResp["error"] != nil {
		t.Fatalf("emit after rotation returned error: %+v", emitResp)
	}
	if emitResp["seq"] == nil || emitResp["hash"] == nil {
		t.Fatalf("emit response missing seq or hash: %+v", emitResp)
	}
	seqNum, err := emitResp["seq"].(json.Number).Int64()
	if err != nil {
		t.Fatalf("seq not a number: %+v", emitResp)
	}
	if seqNum != int64(n) {
		t.Fatalf("expected seq=%d after rotation, got %d", n, seqNum)
	}

	// verify: walks all segments and returns {valid, tamper_detected_at, message}.
	verifyResp := ipcRoundTripWithConfig(t, c, config, `{"op":"verify"}`)
	if verifyResp["valid"] != true {
		t.Fatalf("verify after rotation returned invalid: %+v", verifyResp)
	}
	if _, ok := verifyResp["tamper_detected_at"]; !ok {
		t.Fatalf("verify response missing tamper_detected_at field: %+v", verifyResp)
	}
	if _, ok := verifyResp["message"]; !ok {
		t.Fatalf("verify response missing message field: %+v", verifyResp)
	}

	// ping: returns {ok:true}.
	pingResp := ipcRoundTripWithConfig(t, c, config, `{"op":"ping"}`)
	if pingResp["ok"] != true {
		t.Fatalf("ping after rotation returned unexpected: %+v", pingResp)
	}

	// checkpoint_create: returns a signed checkpoint envelope (not an error).
	cpResp := ipcRoundTripWithConfig(t, c, config, `{"op":"checkpoint_create"}`)
	if cpResp["error"] != nil {
		t.Fatalf("checkpoint_create after rotation returned error: %+v", cpResp)
	}
	if cpResp["payload"] == nil || cpResp["signature"] == nil {
		t.Fatalf("checkpoint_create response missing payload or signature: %+v", cpResp)
	}
}

// TC-017-05: CLI verify shape ({valid, tamper_detected_at, message}) is unchanged post-rotation.
func TestCLIVerifyShapeUnchangedAfterRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	_, _, priv, _ := writeTestKeyPair(t, dir)

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	const n = 4
	emitN(t, c, n)

	if _, err := c.Rotate(n, "test-log", 1700000000, priv); err != nil {
		t.Fatal(err)
	}
	emitN(t, c, 2)

	res := c.Verify()
	if !res.Valid {
		t.Fatalf("verify returned invalid: %s", res.Message)
	}
	if res.TamperDetectedAt != nil {
		t.Fatalf("expected tamper_detected_at nil, got %v", *res.TamperDetectedAt)
	}
	if res.Message != "chain intact" {
		t.Fatalf("expected message 'chain intact', got %q", res.Message)
	}
}

// TC-017-03 (REQ-017-03): emit never blocks on a concurrent rotation — both emit and rotate
// complete and the multi-segment log verifies end-to-end (ADR-005 §5).
func TestEmitNeverBlockedByRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	_, priv := newSegmentSigningKey(t)

	c, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	const pre = 10
	emitN(t, c, pre)

	// Concurrent: one rotation, many emits. All must complete without deadlock.
	const concurrentEmits = 15
	rotDone := make(chan struct{})
	go func() {
		defer close(rotDone)
		_, _ = c.Rotate(pre, "test-log", 1700000000, priv)
	}()
	emitDone := make(chan struct{}, concurrentEmits)
	for i := 0; i < concurrentEmits; i++ {
		go func() {
			_, _ = c.Emit(map[string]any{"actor": "a", "action": "x", "target": "t"})
			emitDone <- struct{}{}
		}()
	}
	<-rotDone
	for i := 0; i < concurrentEmits; i++ {
		<-emitDone
	}

	// Count records across all segments (rotated + active).
	var total int64
	if cnt, err := countRecords(segmentPath(logPath, 1)); err == nil {
		total += cnt
	}
	active, err := countRecords(logPath)
	if err != nil {
		t.Fatal(err)
	}
	total += active
	if total != int64(pre+concurrentEmits) {
		t.Fatalf("record total = %d, want %d: a record was lost", total, pre+concurrentEmits)
	}

	// The full multi-segment chain must verify end-to-end.
	c2, err := NewChain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if vr := c2.Verify(); !vr.Valid {
		t.Fatalf("chain invalid after concurrent emit+rotate: %s", vr.Message)
	}
}

// TC-017-06: docs/spec/interfaces.md, behaviors.md and configuration.md document the new
// rotation runtime surface.
func TestRotationRuntimeSpecsAreUpdated(t *testing.T) {
	docs := []struct {
		path  string
		terms []string
	}{
		{
			path: "docs/spec/interfaces.md",
			terms: []string{
				"`rotate`",
				"--rotate-after",
				"rotation_not_configured",
				`"op":"rotate"`,
			},
		},
		{
			path: "docs/spec/behaviors.md",
			terms: []string{
				"B-014",
				"rotate",
			},
		},
		{
			path: "docs/spec/configuration.md",
			terms: []string{
				"--rotate-after",
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
