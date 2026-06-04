package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type CheckpointServerConfig struct {
	LogID              string
	SigningKeyPath     string
	PublicKeyPath      string
	RekorURL           string
	RekorPublicKeyPath string
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

	// Reject client-submitted URLs or public key/private key file paths to mitigate SSRF and key-injection
	for _, key := range []string{"rekor_url", "rekor-url", "rekor_public_key", "rekor-public-key", "rekor_public_key_path", "rekor-public-key-path", "public_key", "public-key", "public_key_path", "public-key-path", "signing_key", "signing-key", "signing_key_path", "signing-key-path", "key_path", "key-path"} {
		if _, ok := req[key]; ok {
			writeJSON(conn, errShape("bad_request", fmt.Sprintf("client-submitted %s is rejected", key)))
			return
		}
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
	case "checkpoint_anchor":
		receipt, err := anchorCheckpointForIPC(chain, checkpointConfig)
		if err != nil {
			writeJSON(conn, errShape(checkpointIPCErrorCode(err), err.Error()))
			return
		}
		writeJSON(conn, receipt)
	case "checkpoint_verify":
		if req["receipt"] != nil {
			result, err := verifyCheckpointAnchorForIPC(req, chain, checkpointConfig)
			if err != nil {
				writeJSON(conn, errShape(checkpointIPCErrorCode(err), err.Error()))
				return
			}
			writeJSON(conn, result)
			return
		}
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

func anchorCheckpointForIPC(chain *Chain, config CheckpointServerConfig) (RekorReceipt, error) {
	if config.LogID == "" || config.SigningKeyPath == "" || config.RekorURL == "" || config.RekorPublicKeyPath == "" {
		return RekorReceipt{}, errCheckpointNotConfigured
	}
	privateKey, err := LoadCheckpointSigningKey(config.SigningKeyPath)
	if err != nil {
		return RekorReceipt{}, err
	}
	// Generate signed checkpoint for current head
	checkpoint, err := chain.CreateSignedCheckpoint(config.LogID, time.Now().Unix(), privateKey)
	if err != nil {
		return RekorReceipt{}, err
	}

	// We also need the operator public key PEM
	var pubKeyPEM []byte
	if config.PublicKeyPath != "" {
		pubKeyPEM, err = os.ReadFile(config.PublicKeyPath)
		if err != nil {
			return RekorReceipt{}, err
		}
	} else {
		// Derive from private key
		publicKey, ok := privateKey.Public().(ed25519.PublicKey)
		if !ok {
			return RekorReceipt{}, fmt.Errorf("signing key has no Ed25519 public key")
		}
		pubDer, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return RekorReceipt{}, err
		}
		pubKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	}

	client := NewRekorClient(config.RekorURL)
	return client.SubmitCheckpoint(context.Background(), checkpoint, pubKeyPEM)
}

func verifyCheckpointAnchorForIPC(req map[string]any, chain *Chain, config CheckpointServerConfig) (RekorCheckpointVerificationResult, error) {
	if config.PublicKeyPath == "" || config.RekorPublicKeyPath == "" {
		return RekorCheckpointVerificationResult{}, errCheckpointNotConfigured
	}

	checkpointValue := req["checkpoint"]
	if checkpointValue == nil {
		return RekorCheckpointVerificationResult{}, fmt.Errorf("%w: missing checkpoint", errInvalidCheckpointSignature)
	}
	checkpointBytes, err := json.Marshal(checkpointValue)
	if err != nil {
		return RekorCheckpointVerificationResult{}, fmt.Errorf("%w: encode checkpoint: %w", errInvalidCheckpointSignature, err)
	}
	checkpoint, err := DecodeSignedCheckpoint(checkpointBytes)
	if err != nil {
		return RekorCheckpointVerificationResult{}, err
	}

	receiptValue := req["receipt"]
	if receiptValue == nil {
		return RekorCheckpointVerificationResult{}, fmt.Errorf("%w: missing receipt", errInvalidCheckpointSignature)
	}
	receiptBytes, err := json.Marshal(receiptValue)
	if err != nil {
		return RekorCheckpointVerificationResult{}, fmt.Errorf("%w: encode receipt: %w", errInvalidCheckpointSignature, err)
	}
	var receipt RekorReceipt
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		return RekorCheckpointVerificationResult{}, fmt.Errorf("%w: decode receipt: %w", errInvalidCheckpointSignature, err)
	}

	// Load keys
	operatorPubKey, err := LoadCheckpointVerificationKey(config.PublicKeyPath)
	if err != nil {
		return RekorCheckpointVerificationResult{}, err
	}
	operatorPubKeyPEM, err := os.ReadFile(config.PublicKeyPath)
	if err != nil {
		return RekorCheckpointVerificationResult{}, err
	}
	rekorPubKey, err := LoadRekorPublicKey(config.RekorPublicKeyPath)
	if err != nil {
		return RekorCheckpointVerificationResult{}, err
	}

	var res RekorCheckpointVerificationResult
	res.Valid = true
	res.SignatureValid = true
	res.RekorValid = true

	// 1. Verify checkpoint signature locally
	sigVer := VerifySignedCheckpoint(checkpoint, operatorPubKey)
	if !sigVer.Valid {
		res.Valid = false
		res.SignatureValid = false
		res.Message = "checkpoint signature verification failed: " + sigVer.Message
		return res, nil
	}

	// 2. Check online parameter
	online, _ := req["online"].(bool)

	if online {
		if config.RekorURL == "" {
			return RekorCheckpointVerificationResult{}, errCheckpointNotConfigured
		}
		client := NewRekorClient(config.RekorURL)
		err = client.VerifyRekorReceiptOnline(context.Background(), receipt, checkpoint, operatorPubKeyPEM, rekorPubKey)
		var onlineMatch bool
		if err != nil {
			onlineMatch = false
			res.Valid = false
			res.RekorValid = false
			res.RekorOnlineMatch = &onlineMatch
			res.Message = "online verification failed: " + err.Error()
		} else {
			onlineMatch = true
			res.RekorOnlineMatch = &onlineMatch
			res.Message = "verification succeeded"
		}
	} else {
		// Offline verification
		err = VerifyRekorReceiptOffline(receipt, checkpoint, operatorPubKeyPEM, rekorPubKey)
		if err != nil {
			res.Valid = false
			res.RekorValid = false
			res.Message = "offline verification failed: " + err.Error()
		} else {
			res.Message = "verification succeeded"
		}
	}

	return res, nil
}
