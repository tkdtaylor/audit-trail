// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedCheckpointVerifiesWithMatchingKey(t *testing.T) {
	privateKey, publicKey := deterministicCheckpointKey(1)
	payload := validCheckpointPayload()

	checkpoint, err := SignCheckpointPayload(payload, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Payload != payload {
		t.Fatalf("signed checkpoint payload changed: %+v", checkpoint.Payload)
	}
	if checkpoint.Signature.Algorithm != CheckpointSignatureAlgorithm {
		t.Fatalf("expected signature algorithm %q, got %q", CheckpointSignatureAlgorithm, checkpoint.Signature.Algorithm)
	}
	keyID, err := checkpointKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Signature.KeyID != keyID {
		t.Fatalf("expected key_id %q, got %q", keyID, checkpoint.Signature.KeyID)
	}
	if _, err := base64.RawURLEncoding.DecodeString(checkpoint.Signature.Sig); err != nil {
		t.Fatalf("signature is not base64url without padding: %v", err)
	}

	result := VerifySignedCheckpoint(checkpoint, publicKey)
	if !result.Valid || !result.SignatureValid {
		t.Fatalf("expected valid checkpoint signature, got %+v", result)
	}
	if result.LogMatch != nil {
		t.Fatalf("expected nil log_match for signature-only verification, got %v", *result.LogMatch)
	}
}

func TestSignedCheckpointAlteredPayloadFailsVerification(t *testing.T) {
	privateKey, publicKey := deterministicCheckpointKey(1)
	checkpoint, err := SignCheckpointPayload(validCheckpointPayload(), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	checkpoint.Payload.LogID = "other-log"
	result := VerifySignedCheckpoint(checkpoint, publicKey)
	if result.Valid || result.SignatureValid {
		t.Fatalf("expected altered payload to fail, got %+v", result)
	}
	if !strings.Contains(result.Message, "invalid checkpoint signature") {
		t.Fatalf("expected invalid signature message, got %q", result.Message)
	}
}

func TestSignedCheckpointAlteredSignatureAndWrongKeyFail(t *testing.T) {
	privateKey, publicKey := deterministicCheckpointKey(1)
	_, wrongPublicKey := deterministicCheckpointKey(2)
	checkpoint, err := SignCheckpointPayload(validCheckpointPayload(), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("altered signature bytes", func(t *testing.T) {
		tampered := checkpoint
		sig, err := base64.RawURLEncoding.DecodeString(tampered.Signature.Sig)
		if err != nil {
			t.Fatal(err)
		}
		sig[0] ^= 0xff
		tampered.Signature.Sig = base64.RawURLEncoding.EncodeToString(sig)

		result := VerifySignedCheckpoint(tampered, publicKey)
		if result.Valid || result.SignatureValid {
			t.Fatalf("expected altered signature to fail, got %+v", result)
		}
	})

	t.Run("malformed signature bytes", func(t *testing.T) {
		tampered := checkpoint
		tampered.Signature.Sig = "@@@"

		result := VerifySignedCheckpoint(tampered, publicKey)
		if result.Valid || result.SignatureValid {
			t.Fatalf("expected malformed signature to fail, got %+v", result)
		}
		if !strings.Contains(result.Message, "malformed checkpoint signature") {
			t.Fatalf("expected malformed signature message, got %q", result.Message)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		result := VerifySignedCheckpoint(checkpoint, wrongPublicKey)
		if result.Valid || result.SignatureValid {
			t.Fatalf("expected wrong key to fail, got %+v", result)
		}
		if !strings.Contains(result.Message, "key_id") {
			t.Fatalf("expected key_id mismatch message, got %q", result.Message)
		}
	})

	t.Run("key id mismatch", func(t *testing.T) {
		tampered := checkpoint
		tampered.Signature.KeyID = CheckpointKeyIDPrefix + strings.Repeat("0", 64)

		result := VerifySignedCheckpoint(tampered, publicKey)
		if result.Valid || result.SignatureValid {
			t.Fatalf("expected key id mismatch to fail, got %+v", result)
		}
	})
}

func TestCheckpointKeyLoadingFailsClosed(t *testing.T) {
	dir := t.TempDir()
	privateKey, publicKey := deterministicCheckpointKey(1)
	privatePath := filepath.Join(dir, "ed25519-private.pem")
	publicPath := filepath.Join(dir, "ed25519-public.pem")
	writeCheckpointPrivateKeyPEM(t, privatePath, privateKey)
	writeCheckpointPublicKeyPEM(t, publicPath, publicKey)

	loadedPrivate, err := LoadCheckpointSigningKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !loadedPrivate.Equal(privateKey) {
		t.Fatal("loaded private key does not match fixture key")
	}
	loadedPublic, err := LoadCheckpointVerificationKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !loadedPublic.Equal(publicKey) {
		t.Fatal("loaded public key does not match fixture key")
	}

	cases := []struct {
		name      string
		path      string
		writeFile func(string)
		load      func(string) error
	}{
		{
			name: "missing signing key",
			path: filepath.Join(dir, "missing-private.pem"),
			load: func(path string) error {
				_, err := LoadCheckpointSigningKey(path)
				return err
			},
		},
		{
			name: "malformed signing key",
			path: filepath.Join(dir, "bad-private.pem"),
			writeFile: func(path string) {
				if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			load: func(path string) error {
				_, err := LoadCheckpointSigningKey(path)
				return err
			},
		},
		{
			name: "wrong signing key type",
			path: filepath.Join(dir, "rsa-private.pem"),
			writeFile: func(path string) {
				writeRSAPrivateKeyPEM(t, path)
			},
			load: func(path string) error {
				_, err := LoadCheckpointSigningKey(path)
				return err
			},
		},
		{
			name: "malformed verification key",
			path: filepath.Join(dir, "bad-public.pem"),
			writeFile: func(path string) {
				if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			load: func(path string) error {
				_, err := LoadCheckpointVerificationKey(path)
				return err
			},
		},
		{
			name: "wrong verification key type",
			path: filepath.Join(dir, "rsa-public.pem"),
			writeFile: func(path string) {
				writeRSAPublicKeyPEM(t, path)
			},
			load: func(path string) error {
				_, err := LoadCheckpointVerificationKey(path)
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.writeFile != nil {
				tc.writeFile(tc.path)
			}
			err := tc.load(tc.path)
			if err == nil {
				t.Fatal("expected malformed key material to fail closed")
			}
			if tc.name != "missing signing key" && !errors.Is(err, errInvalidCheckpointKey) {
				t.Fatalf("expected invalid checkpoint key error, got %v", err)
			}
		})
	}
}

func TestCheckpointSigningRejectsMalformedInputs(t *testing.T) {
	privateKey, publicKey := deterministicCheckpointKey(1)

	if _, err := SignCheckpointPayload(validCheckpointPayload(), nil); err == nil {
		t.Fatal("expected empty signing key to fail")
	}
	if result := VerifySignedCheckpoint(SignedCheckpoint{}, publicKey); result.Valid {
		t.Fatalf("expected empty checkpoint to fail, got %+v", result)
	}
	if result := VerifySignedCheckpoint(mustSignCheckpoint(t, validCheckpointPayload(), privateKey), nil); result.Valid {
		t.Fatalf("expected empty verification key to fail, got %+v", result)
	}

	payload := validCheckpointPayload()
	payload.RootHash = strings.Repeat("A", 64)
	if _, err := SignCheckpointPayload(payload, privateKey); err == nil {
		t.Fatal("expected malformed payload to fail before signing")
	}
}

func TestCheckpointSignatureSpecsAreUpdated(t *testing.T) {
	docs := []struct {
		path  string
		terms []string
	}{
		{
			path: "docs/spec/configuration.md",
			terms: []string{
				"`--signing-key`",
				"`--public-key`",
				"PKCS #8 Ed25519 private key",
				"SubjectPublicKeyInfo Ed25519 public key",
			},
		},
		{
			path: "docs/spec/data-model.md",
			terms: []string{
				"Signed checkpoint envelope",
				"`signature`",
				"`algorithm`",
				"`key_id`",
				"`sig`",
			},
		},
		{
			path: "docs/spec/behaviors.md",
			terms: []string{
				"B-009",
				"Sign and verify checkpoint signatures",
				"Ed25519",
				"fail closed",
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

func deterministicCheckpointKey(seedByte byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey, privateKey.Public().(ed25519.PublicKey)
}

func validCheckpointPayload() CheckpointPayload {
	return CheckpointPayload{
		Format:        CheckpointFormat,
		Version:       CheckpointVersion,
		Contract:      CheckpointContract,
		LogID:         "test-log",
		TreeSize:      2,
		LastSeq:       1,
		RootHash:      "1111111111111111111111111111111111111111111111111111111111111111",
		HashAlgorithm: CheckpointHashAlgorithm,
		IssuedAt:      checkpointIssuedAt,
	}
}

func mustSignCheckpoint(t *testing.T, payload CheckpointPayload, privateKey ed25519.PrivateKey) SignedCheckpoint {
	t.Helper()
	checkpoint, err := SignCheckpointPayload(payload, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func writeCheckpointPrivateKeyPEM(t *testing.T, path string, privateKey ed25519.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "PRIVATE KEY", der)
}

func writeCheckpointPublicKeyPEM(t *testing.T, path string, publicKey ed25519.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "PUBLIC KEY", der)
}

func writeRSAPrivateKeyPEM(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "PRIVATE KEY", der)
}

func writeRSAPublicKeyPEM(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "PUBLIC KEY", der)
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
