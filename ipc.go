package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type CheckpointServerConfig struct {
	LogID          string
	SigningKeyPath string
	PublicKeyPath  string
}

// serve runs the JSON-over-Unix-socket IPC form of the contract (interface-contracts §1):
// one newline-terminated JSON request {op: emit|verify|ping} -> one JSON response.
func serve(socketPath string, chain *Chain, checkpointConfig CheckpointServerConfig) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	_ = os.Chmod(socketPath, 0o600)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn, chain, checkpointConfig)
	}
}

func handleConn(conn net.Conn, chain *Chain, checkpointConfig CheckpointServerConfig) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	req, err := decodeIPCRequest(line)
	if err != nil {
		writeJSON(conn, errShape("bad_request", err.Error()))
		return
	}
	switch req["op"] {
	case "emit":
		event, _ := req["event"].(map[string]any)
		if event == nil {
			writeJSON(conn, errShape("bad_request", "missing event"))
			return
		}
		event, err = normalizeJSONNumbers(event, "event")
		if err != nil {
			writeJSON(conn, errShape("bad_request", err.Error()))
			return
		}
		out, err := chain.Emit(event)
		if err != nil {
			writeJSON(conn, errShape(emitErrorCode(err), err.Error()))
			return
		}
		writeJSON(conn, out)
	case "verify":
		writeJSON(conn, chain.Verify())
	case "ping":
		writeJSON(conn, map[string]any{"ok": true})
	case "checkpoint_create":
		checkpoint, err := createCheckpointForIPC(chain, checkpointConfig)
		if err != nil {
			writeJSON(conn, errShape(checkpointIPCErrorCode(err), err.Error()))
			return
		}
		writeJSON(conn, checkpoint)
	case "checkpoint_verify":
		result, err := verifyCheckpointForIPC(req, chain, checkpointConfig)
		if err != nil {
			writeJSON(conn, errShape(checkpointIPCErrorCode(err), err.Error()))
			return
		}
		writeJSON(conn, result)
	default:
		writeJSON(conn, errShape("unknown_op", "unsupported op"))
	}
}

func emitErrorCode(err error) string {
	if errors.Is(err, errInvalidAuditEvent) {
		return "bad_request"
	}
	return "internal"
}

func createCheckpointForIPC(chain *Chain, config CheckpointServerConfig) (SignedCheckpoint, error) {
	if config.LogID == "" || config.SigningKeyPath == "" {
		return SignedCheckpoint{}, errCheckpointNotConfigured
	}
	privateKey, err := LoadCheckpointSigningKey(config.SigningKeyPath)
	if err != nil {
		return SignedCheckpoint{}, err
	}
	return chain.CreateSignedCheckpoint(config.LogID, time.Now().Unix(), privateKey)
}

func verifyCheckpointForIPC(req map[string]any, chain *Chain, config CheckpointServerConfig) (CheckpointVerificationResult, error) {
	if config.PublicKeyPath == "" {
		return CheckpointVerificationResult{}, errCheckpointNotConfigured
	}
	checkpointValue := req["checkpoint"]
	if checkpointValue == nil {
		return CheckpointVerificationResult{}, fmt.Errorf("%w: missing checkpoint", errInvalidCheckpointSignature)
	}
	checkpointBytes, err := json.Marshal(checkpointValue)
	if err != nil {
		return CheckpointVerificationResult{}, fmt.Errorf("%w: encode checkpoint: %w", errInvalidCheckpointSignature, err)
	}
	checkpoint, err := DecodeSignedCheckpoint(checkpointBytes)
	if err != nil {
		return CheckpointVerificationResult{}, err
	}
	publicKey, err := LoadCheckpointVerificationKey(config.PublicKeyPath)
	if err != nil {
		return CheckpointVerificationResult{}, err
	}
	compareLog, ok := req["compare_log"].(bool)
	if ok && compareLog {
		return VerifySignedCheckpointForLog(checkpoint, publicKey, chain.path), nil
	}
	return VerifySignedCheckpoint(checkpoint, publicKey), nil
}

var errCheckpointNotConfigured = errors.New("checkpoint not configured")

func checkpointIPCErrorCode(err error) string {
	if errors.Is(err, errCheckpointNotConfigured) {
		return "checkpoint_not_configured"
	}
	if errors.Is(err, errInvalidCheckpointKey) {
		return "bad_request"
	}
	if errors.Is(err, errInvalidCheckpointPayload) || errors.Is(err, errInvalidCheckpointSignature) {
		return "bad_request"
	}
	if errors.Is(err, errInvalidCheckpointLog) {
		return "invalid_log"
	}
	return "internal"
}

func decodeIPCRequest(line []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()

	var req map[string]any
	if err := dec.Decode(&req); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("multiple JSON values in request")
	}
	return req, nil
}

func normalizeJSONNumbers(event map[string]any, path string) (map[string]any, error) {
	out := make(map[string]any, len(event))
	for k, v := range event {
		normalized, err := normalizeJSONNumberValue(v, path+"."+k)
		if err != nil {
			return nil, err
		}
		out[k] = normalized
	}
	return out, nil
}

func normalizeJSONNumberValue(v any, path string) (any, error) {
	switch x := v.(type) {
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			return nil, fmt.Errorf("audited event rejects non-integer JSON number at %s (%q)", path, x.String())
		}
		return i, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, child := range x {
			normalized, err := normalizeJSONNumberValue(child, path+"."+k)
			if err != nil {
				return nil, err
			}
			out[k] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, child := range x {
			normalized, err := normalizeJSONNumberValue(child, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			out[i] = normalized
		}
		return out, nil
	default:
		return v, nil
	}
}

func writeJSON(conn net.Conn, v any) {
	b, _ := json.Marshal(v)
	conn.Write(append(b, '\n'))
}

func errShape(code, msg string) map[string]any {
	return map[string]any{"error": map[string]any{
		"code": code, "message": msg, "retryable": false}}
}
