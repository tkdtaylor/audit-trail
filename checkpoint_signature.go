package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	CheckpointSignatureAlgorithm = "ed25519"
	CheckpointKeyIDPrefix        = "ed25519-sha256:"
)

var (
	errInvalidCheckpointPayload   = errors.New("invalid checkpoint payload")
	errInvalidCheckpointSignature = errors.New("invalid checkpoint signature")
	errInvalidCheckpointKey       = errors.New("invalid checkpoint key")
)

// CheckpointSignature carries Ed25519 metadata and base64url signature bytes.
type CheckpointSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Sig       string `json:"sig"`
}

// SignedCheckpoint is the portable checkpoint envelope.
type SignedCheckpoint struct {
	Payload   CheckpointPayload   `json:"payload"`
	Signature CheckpointSignature `json:"signature"`
}

// CheckpointVerificationResult describes checkpoint signature verification.
type CheckpointVerificationResult struct {
	Valid          bool   `json:"valid"`
	SignatureValid bool   `json:"signature_valid"`
	LogMatch       *bool  `json:"log_match"`
	Message        string `json:"message"`
}

// LoadCheckpointSigningKey reads a PKCS #8 Ed25519 private key from a PEM file.
func LoadCheckpointSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: signing key is not PEM", errInvalidCheckpointKey)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("%w: signing key has trailing data", errInvalidCheckpointKey)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%w: signing key PEM type %q, want PRIVATE KEY", errInvalidCheckpointKey, block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse signing key: %w", errInvalidCheckpointKey, err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signing key is not Ed25519", errInvalidCheckpointKey)
	}
	return privateKey, nil
}

// LoadCheckpointVerificationKey reads a SubjectPublicKeyInfo Ed25519 public key from PEM.
func LoadCheckpointVerificationKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read verification key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: verification key is not PEM", errInvalidCheckpointKey)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("%w: verification key has trailing data", errInvalidCheckpointKey)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: verification key PEM type %q, want PUBLIC KEY", errInvalidCheckpointKey, block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse verification key: %w", errInvalidCheckpointKey, err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: verification key is not Ed25519", errInvalidCheckpointKey)
	}
	return publicKey, nil
}

func checkpointKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: invalid Ed25519 public key length", errInvalidCheckpointKey)
	}
	sum := sha256.Sum256(publicKey)
	return CheckpointKeyIDPrefix + hex.EncodeToString(sum[:]), nil
}

// SignCheckpointPayload signs exactly CheckpointPayloadBytes(payload).
func SignCheckpointPayload(payload CheckpointPayload, privateKey ed25519.PrivateKey) (SignedCheckpoint, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedCheckpoint{}, fmt.Errorf("%w: invalid Ed25519 private key length", errInvalidCheckpointKey)
	}
	if err := validateCheckpointPayload(payload); err != nil {
		return SignedCheckpoint{}, err
	}
	payloadBytes, err := CheckpointPayloadBytes(payload)
	if err != nil {
		return SignedCheckpoint{}, fmt.Errorf("%w: canonical payload: %w", errInvalidCheckpointPayload, err)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return SignedCheckpoint{}, fmt.Errorf("%w: private key has no Ed25519 public key", errInvalidCheckpointKey)
	}
	keyID, err := checkpointKeyID(publicKey)
	if err != nil {
		return SignedCheckpoint{}, err
	}
	sig := ed25519.Sign(privateKey, payloadBytes)
	return SignedCheckpoint{
		Payload: payload,
		Signature: CheckpointSignature{
			Algorithm: CheckpointSignatureAlgorithm,
			KeyID:     keyID,
			Sig:       base64.RawURLEncoding.EncodeToString(sig),
		},
	}, nil
}

// DecodeSignedCheckpoint parses a checkpoint envelope and rejects malformed or unknown fields.
func DecodeSignedCheckpoint(data []byte) (SignedCheckpoint, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var checkpoint SignedCheckpoint
	if err := dec.Decode(&checkpoint); err != nil {
		return SignedCheckpoint{}, fmt.Errorf("%w: decode checkpoint: %w", errInvalidCheckpointSignature, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return SignedCheckpoint{}, fmt.Errorf("%w: decode checkpoint: %w", errInvalidCheckpointSignature, err)
		}
		return SignedCheckpoint{}, fmt.Errorf("%w: multiple JSON values in checkpoint", errInvalidCheckpointSignature)
	}
	return checkpoint, nil
}

// VerifySignedCheckpoint fails closed for malformed envelopes and invalid signatures.
func VerifySignedCheckpoint(checkpoint SignedCheckpoint, publicKey ed25519.PublicKey) CheckpointVerificationResult {
	if len(publicKey) != ed25519.PublicKeySize {
		return invalidCheckpointResult("invalid verification key")
	}
	if err := validateCheckpointPayload(checkpoint.Payload); err != nil {
		return invalidCheckpointResult(err.Error())
	}
	if checkpoint.Signature.Algorithm != CheckpointSignatureAlgorithm {
		return invalidCheckpointResult("unsupported checkpoint signature algorithm")
	}
	keyID, err := checkpointKeyID(publicKey)
	if err != nil {
		return invalidCheckpointResult(err.Error())
	}
	if checkpoint.Signature.KeyID != keyID {
		return invalidCheckpointResult("checkpoint signature key_id does not match verification key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature.Sig)
	if err != nil {
		return invalidCheckpointResult("malformed checkpoint signature encoding")
	}
	if len(sig) != ed25519.SignatureSize {
		return invalidCheckpointResult("malformed checkpoint signature length")
	}
	payloadBytes, err := CheckpointPayloadBytes(checkpoint.Payload)
	if err != nil {
		return invalidCheckpointResult(err.Error())
	}
	if !ed25519.Verify(publicKey, payloadBytes, sig) {
		return invalidCheckpointResult("invalid checkpoint signature")
	}
	return CheckpointVerificationResult{
		Valid:          true,
		SignatureValid: true,
		LogMatch:       nil,
		Message:        "checkpoint signature valid",
	}
}

// VerifySignedCheckpointForLog verifies the signature and compares it to a verified logfile.
func VerifySignedCheckpointForLog(checkpoint SignedCheckpoint, publicKey ed25519.PublicKey, logPath string) CheckpointVerificationResult {
	result := VerifySignedCheckpoint(checkpoint, publicKey)
	if !result.Valid {
		return result
	}

	state, verifyResult := verifyChainState(logPath)
	if !verifyResult.Valid {
		match := false
		return CheckpointVerificationResult{
			Valid:          false,
			SignatureValid: true,
			LogMatch:       &match,
			Message:        "checkpoint signature valid, but logfile verification failed: " + verifyResult.Message,
		}
	}
	if checkpoint.Payload.TreeSize != state.treeSize ||
		checkpoint.Payload.LastSeq != state.lastSeq ||
		checkpoint.Payload.RootHash != state.rootHash {
		match := false
		return CheckpointVerificationResult{
			Valid:          false,
			SignatureValid: true,
			LogMatch:       &match,
			Message:        "checkpoint signature valid, but logfile does not match checkpoint",
		}
	}

	match := true
	result.LogMatch = &match
	result.Message = "checkpoint signature valid and logfile matches"
	return result
}

func invalidCheckpointResult(message string) CheckpointVerificationResult {
	return CheckpointVerificationResult{
		Valid:          false,
		SignatureValid: false,
		LogMatch:       nil,
		Message:        message,
	}
}

func validateCheckpointPayload(payload CheckpointPayload) error {
	if payload.Format != CheckpointFormat {
		return fmt.Errorf("%w: format must be %q", errInvalidCheckpointPayload, CheckpointFormat)
	}
	if payload.Version != CheckpointVersion {
		return fmt.Errorf("%w: version must be %d", errInvalidCheckpointPayload, CheckpointVersion)
	}
	if payload.Contract != CheckpointContract {
		return fmt.Errorf("%w: contract must be %q", errInvalidCheckpointPayload, CheckpointContract)
	}
	if payload.LogID == "" {
		return fmt.Errorf("%w: log_id is required", errInvalidCheckpointPayload)
	}
	if payload.TreeSize < 0 {
		return fmt.Errorf("%w: tree_size must be non-negative", errInvalidCheckpointPayload)
	}
	if payload.TreeSize == 0 && payload.LastSeq != -1 {
		return fmt.Errorf("%w: last_seq must be -1 for an empty log", errInvalidCheckpointPayload)
	}
	if payload.TreeSize > 0 && payload.LastSeq != payload.TreeSize-1 {
		return fmt.Errorf("%w: last_seq must equal tree_size - 1", errInvalidCheckpointPayload)
	}
	if !isLowerHexSHA256(payload.RootHash) {
		return fmt.Errorf("%w: root_hash must be 64 lowercase hex characters", errInvalidCheckpointPayload)
	}
	if payload.HashAlgorithm != CheckpointHashAlgorithm {
		return fmt.Errorf("%w: hash_algorithm must be %q", errInvalidCheckpointPayload, CheckpointHashAlgorithm)
	}
	if payload.IssuedAt < 0 {
		return fmt.Errorf("%w: issued_at must be non-negative", errInvalidCheckpointPayload)
	}
	return nil
}

func isLowerHexSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}
