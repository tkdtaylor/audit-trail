// SPDX-License-Identifier: Apache-2.0
// Command audit-trail is the hash-chained, append-only forensic spine of the secure-agent
// ecosystem. Every block emits to it; verify() walks the chain and detects any tamper.
//
// Contract (docs/CONTRACT.md, v1):
//
//	emit(event) -> { seq, hash }
//	verify()    -> { valid, tamper_detected_at, message }
//	hash = SHA256( prev_hash + JCS(event) )
//
// Usage:
//
//	audit-trail serve      --socket /run/audit.sock --logfile audit.log
//	audit-trail emit       --logfile audit.log --actor vault --action resolve --target vault://x
//	audit-trail verify     --logfile audit.log
//	audit-trail checkpoint create --logfile audit.log --log-id prod --signing-key key.pem
//	audit-trail rotate     --logfile audit.log --rotate-after N --log-id prod --signing-key key.pem
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "emit":
		cmdEmit(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "checkpoint":
		cmdCheckpoint(os.Args[2:])
	case "rotate":
		cmdRotate(os.Args[2:])
	case "query":
		cmdQuery(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: audit-trail <serve|emit|verify|checkpoint|rotate|query> [flags]")
	os.Exit(2)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (required)")
	logfile := fs.String("logfile", "audit.log", "JSONL log path")
	checkpointLogID := fs.String("checkpoint-log-id", "", "checkpoint log identifier (also used for rotation)")
	checkpointSigningKey := fs.String("checkpoint-signing-key", "", "checkpoint signing key PEM path (also used for rotation)")
	checkpointPublicKey := fs.String("checkpoint-public-key", "", "checkpoint verification public key PEM path")
	rekorURL := fs.String("rekor-url", "", "Rekor transparency log server URL")
	rekorPublicKey := fs.String("rekor-public-key", "", "Rekor server public key PEM path")
	rotateAfter := fs.Int64("rotate-after", 0, "rotate the active segment after this many records (0 = disabled); requires --checkpoint-log-id and --checkpoint-signing-key")
	fs.Parse(args)
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "serve: --socket is required")
		os.Exit(2)
	}
	chain, err := NewChain(*logfile)
	check(err)
	fmt.Fprintf(os.Stderr, "audit-trail serving on %s (log=%s)\n", *socket, *logfile)
	check(serve(*socket, chain, CheckpointServerConfig{
		LogID:              *checkpointLogID,
		SigningKeyPath:     *checkpointSigningKey,
		PublicKeyPath:      *checkpointPublicKey,
		RekorURL:           *rekorURL,
		RekorPublicKeyPath: *rekorPublicKey,
		RotateAfter:        *rotateAfter,
	}))
}

func cmdEmit(args []string) {
	fs := flag.NewFlagSet("emit", flag.ExitOnError)
	logfile := fs.String("logfile", "audit.log", "JSONL log path")
	actor := fs.String("actor", "", "actor identity")
	action := fs.String("action", "", "action verb")
	target := fs.String("target", "", "target resource")
	decision := fs.String("decision", "", "decision (optional)")
	fs.Parse(args)
	chain, err := NewChain(*logfile)
	check(err)
	event := map[string]any{
		"ts": time.Now().Unix(), "actor": *actor, "action": *action,
		"target": *target,
	}
	if *decision != "" {
		event["decision"] = *decision
	}
	out, err := chain.Emit(event)
	check(err)
	printJSON(out)
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	logfile := fs.String("logfile", "audit.log", "JSONL log path")
	fs.Parse(args)
	chain, err := NewChain(*logfile)
	check(err)
	res := chain.Verify()
	printJSON(res)
	if !res.Valid {
		os.Exit(1)
	}
}

func cmdCheckpoint(args []string) {
	if len(args) < 1 {
		checkpointUsage()
	}
	switch args[0] {
	case "create":
		cmdCheckpointCreate(args[1:])
	case "verify":
		cmdCheckpointVerify(args[1:])
	case "anchor":
		cmdCheckpointAnchor(args[1:])
	case "verify-anchor":
		cmdCheckpointVerifyAnchor(args[1:])
	default:
		checkpointUsage()
	}
}

func checkpointUsage() {
	fmt.Fprintln(os.Stderr, "usage: audit-trail checkpoint <create|verify|anchor|verify-anchor> [flags]")
	os.Exit(2)
}

func cmdCheckpointCreate(args []string) {
	fs := flag.NewFlagSet("checkpoint create", flag.ExitOnError)
	logfile := fs.String("logfile", "audit.log", "JSONL log path")
	logID := fs.String("log-id", "", "stable checkpoint log identifier (required)")
	signingKeyPath := fs.String("signing-key", "", "PEM Ed25519 private key path (required)")
	outPath := fs.String("out", "", "write checkpoint JSON to path instead of stdout")
	fs.Parse(args)
	if *logID == "" {
		fmt.Fprintln(os.Stderr, "checkpoint create: --log-id is required")
		os.Exit(2)
	}
	if *signingKeyPath == "" {
		fmt.Fprintln(os.Stderr, "checkpoint create: --signing-key is required")
		os.Exit(2)
	}

	privateKey, err := LoadCheckpointSigningKey(*signingKeyPath)
	check(err)
	chain, err := NewChain(*logfile)
	check(err)
	checkpoint, err := chain.CreateSignedCheckpoint(*logID, time.Now().Unix(), privateKey)
	check(err)
	if *outPath != "" {
		check(writeJSONFile(*outPath, checkpoint))
		return
	}
	printJSON(checkpoint)
}

func cmdCheckpointVerify(args []string) {
	fs := flag.NewFlagSet("checkpoint verify", flag.ExitOnError)
	checkpointPath := fs.String("checkpoint", "", "checkpoint JSON path (required)")
	publicKeyPath := fs.String("public-key", "", "PEM Ed25519 public key path (required)")
	logfile := fs.String("logfile", "", "optional JSONL log path to compare against")
	fs.Parse(args)
	if *checkpointPath == "" {
		fmt.Fprintln(os.Stderr, "checkpoint verify: --checkpoint is required")
		os.Exit(2)
	}
	if *publicKeyPath == "" {
		fmt.Fprintln(os.Stderr, "checkpoint verify: --public-key is required")
		os.Exit(2)
	}

	data, err := os.ReadFile(*checkpointPath)
	check(err)
	checkpoint, err := DecodeSignedCheckpoint(data)
	check(err)
	publicKey, err := LoadCheckpointVerificationKey(*publicKeyPath)
	check(err)

	var result CheckpointVerificationResult
	if *logfile != "" {
		result = VerifySignedCheckpointForLog(checkpoint, publicKey, *logfile)
	} else {
		result = VerifySignedCheckpoint(checkpoint, publicKey)
	}
	printJSON(result)
	if !result.Valid {
		os.Exit(1)
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdRotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	logfile := fs.String("logfile", "audit.log", "JSONL log path")
	rotateAfter := fs.Int64("rotate-after", 0, "rotate when the active segment holds at least this many records (required, > 0)")
	logID := fs.String("log-id", "", "stable log identifier for the boundary checkpoint (required)")
	signingKey := fs.String("signing-key", "", "PEM Ed25519 private key path for the boundary checkpoint (required)")
	fs.Parse(args)

	if *rotateAfter <= 0 {
		fmt.Fprintln(os.Stderr, "rotate: --rotate-after must be > 0")
		os.Exit(2)
	}
	if *logID == "" {
		fmt.Fprintln(os.Stderr, "rotate: --log-id is required")
		os.Exit(2)
	}
	if *signingKey == "" {
		fmt.Fprintln(os.Stderr, "rotate: --signing-key is required")
		os.Exit(2)
	}

	privateKey, err := LoadCheckpointSigningKey(*signingKey)
	check(err)
	chain, err := NewChain(*logfile)
	check(err)

	res, err := chain.Rotate(*rotateAfter, *logID, time.Now().Unix(), privateKey)
	if err != nil && err != errBelowRotationThreshold {
		check(err)
	}
	// errBelowRotationThreshold is a non-error outcome: print {rotated:false} and exit 0.
	printJSON(res)
}

// cmdQuery implements the "query" CLI subcommand (REQ-020-10). Flags mirror QueryFilter's
// fields; range flags are strings so an unset flag (empty string) is distinguishable from an
// explicit "0", which is a legitimate seq/ts bound. Exit codes: 0 on any served query, including
// verified:false (the flag is the signal, unlike cmdVerify whose job is the verdict); 1 on an
// operational error such as an unreadable logfile (via check()); 2 on a usage error (an
// out-of-range --limit or a non-numeric --token/range flag).
func cmdQuery(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	logfile := fs.String("logfile", "audit.log", "JSONL log path")
	actor := fs.String("actor", "", "filter: exact actor match (optional)")
	action := fs.String("action", "", "filter: exact action match (optional)")
	target := fs.String("target", "", "filter: exact target match (optional)")
	decision := fs.String("decision", "", "filter: exact decision match (optional)")
	seqMin := fs.String("seq-min", "", "filter: minimum seq, inclusive (optional)")
	seqMax := fs.String("seq-max", "", "filter: maximum seq, inclusive (optional)")
	tsMin := fs.String("ts-min", "", "filter: minimum ts, inclusive (optional)")
	tsMax := fs.String("ts-max", "", "filter: maximum ts, inclusive (optional)")
	limit := fs.Int64("limit", defaultQueryLimit, "max results per page (1..1000)")
	token := fs.String("token", "", "continuation token from a previous page (optional)")
	fs.Parse(args)

	var f QueryFilter
	if *actor != "" {
		f.Actor = actor
	}
	if *action != "" {
		f.Action = action
	}
	if *target != "" {
		f.Target = target
	}
	if *decision != "" {
		f.Decision = decision
	}
	f.SeqMin = cmdQueryOptionalInt("seq-min", *seqMin)
	f.SeqMax = cmdQueryOptionalInt("seq-max", *seqMax)
	f.TsMin = cmdQueryOptionalInt("ts-min", *tsMin)
	f.TsMax = cmdQueryOptionalInt("ts-max", *tsMax)

	if *limit < 1 || *limit > maxQueryLimit {
		fmt.Fprintf(os.Stderr, "query: --limit must be between 1 and %d\n", maxQueryLimit)
		os.Exit(2)
	}

	var resumeSeq int64
	if *token != "" {
		n, err := strconv.ParseInt(*token, 10, 64)
		if err != nil || n < 0 {
			fmt.Fprintln(os.Stderr, "query: --token must be a non-negative integer string")
			os.Exit(2)
		}
		resumeSeq = n
	}

	resp, err := runQuery(*logfile, f, *limit, resumeSeq)
	check(err)

	b, err := marshalQueryResponseIndent(resp)
	check(err)
	fmt.Println(string(b))
}

// cmdQueryOptionalInt parses an optional --seq-min/--seq-max/--ts-min/--ts-max flag value. An
// empty string means "not provided"; anything else must be a valid int64 or the command exits 2
// (usage error).
func cmdQueryOptionalInt(flagName, val string) *int64 {
	if val == "" {
		return nil
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query: --%s must be an integer\n", flagName)
		os.Exit(2)
	}
	return &n
}

func cmdCheckpointAnchor(args []string) {
	fs := flag.NewFlagSet("checkpoint anchor", flag.ExitOnError)
	checkpointPath := fs.String("checkpoint", "", "checkpoint JSON path (required)")
	rekorURL := fs.String("rekor-url", "", "Rekor transparency log server URL (required)")
	publicKeyPath := fs.String("public-key", "", "PEM Ed25519 public key path (required)")
	outPath := fs.String("out", "", "write receipt JSON to path instead of stdout")
	fs.Parse(args)
	if *checkpointPath == "" {
		fmt.Fprintln(os.Stderr, "checkpoint anchor: --checkpoint is required")
		os.Exit(2)
	}
	if *rekorURL == "" {
		fmt.Fprintln(os.Stderr, "checkpoint anchor: --rekor-url is required")
		os.Exit(2)
	}
	if *publicKeyPath == "" {
		fmt.Fprintln(os.Stderr, "checkpoint anchor: --public-key is required")
		os.Exit(2)
	}

	checkpointData, err := os.ReadFile(*checkpointPath)
	check(err)
	checkpoint, err := DecodeSignedCheckpoint(checkpointData)
	check(err)

	pubKeyPEM, err := os.ReadFile(*publicKeyPath)
	check(err)

	client := NewRekorClient(*rekorURL)
	receipt, err := client.SubmitCheckpoint(context.Background(), checkpoint, pubKeyPEM)
	check(err)

	if *outPath != "" {
		check(writeJSONFile(*outPath, receipt))
		return
	}
	printJSON(receipt)
}

func cmdCheckpointVerifyAnchor(args []string) {
	fs := flag.NewFlagSet("checkpoint verify-anchor", flag.ExitOnError)
	checkpointPath := fs.String("checkpoint", "", "checkpoint JSON path (required)")
	receiptPath := fs.String("receipt", "", "Rekor receipt JSON path (required)")
	rekorPublicKeyPath := fs.String("rekor-public-key", "", "Rekor public key PEM path (required)")
	rekorURL := fs.String("rekor-url", "", "optional Rekor transparency log server URL for online verification")
	publicKeyPath := fs.String("public-key", "", "PEM Ed25519 public key path (optional, required for offline verification)")
	fs.Parse(args)

	if *checkpointPath == "" {
		fmt.Fprintln(os.Stderr, "checkpoint verify-anchor: --checkpoint is required")
		os.Exit(2)
	}
	if *receiptPath == "" {
		fmt.Fprintln(os.Stderr, "checkpoint verify-anchor: --receipt is required")
		os.Exit(2)
	}
	if *rekorPublicKeyPath == "" {
		fmt.Fprintln(os.Stderr, "checkpoint verify-anchor: --rekor-public-key is required")
		os.Exit(2)
	}

	checkpointData, err := os.ReadFile(*checkpointPath)
	check(err)
	checkpoint, err := DecodeSignedCheckpoint(checkpointData)
	check(err)

	receiptData, err := os.ReadFile(*receiptPath)
	check(err)
	var receipt RekorReceipt
	err = json.Unmarshal(receiptData, &receipt)
	check(err)

	rekorPubKey, err := LoadRekorPublicKey(*rekorPublicKeyPath)
	check(err)

	var operatorPubKeyPEM []byte
	var operatorPubKey ed25519.PublicKey

	if *publicKeyPath != "" {
		operatorPubKeyPEM, err = os.ReadFile(*publicKeyPath)
		check(err)
		operatorPubKey, err = LoadCheckpointVerificationKey(*publicKeyPath)
		check(err)
	}

	var res RekorCheckpointVerificationResult
	res.Valid = true
	res.SignatureValid = true
	res.RekorValid = true

	// Check if operator public key was supplied
	if len(operatorPubKeyPEM) > 0 {
		// Verify checkpoint signature locally
		sigVer := VerifySignedCheckpoint(checkpoint, operatorPubKey)
		if !sigVer.Valid {
			res.Valid = false
			res.SignatureValid = false
			res.Message = "checkpoint signature verification failed: " + sigVer.Message
			printJSON(res)
			os.Exit(1)
		}
	} else if *rekorURL == "" {
		// Offline and no operator public key
		fmt.Fprintln(os.Stderr, "checkpoint verify-anchor: --public-key is required for offline verification")
		os.Exit(2)
	}

	if *rekorURL != "" {
		client := NewRekorClient(*rekorURL)
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
			// If operatorPubKey was not supplied, we can now verify checkpoint signature using extracted key
			if len(operatorPubKeyPEM) == 0 {
				var fetchedBodyStr string
				if receipt.EntryID != "" {
					_, fetchedBodyStr, err = client.GetEntryByID(context.Background(), receipt.EntryID)
				} else {
					_, fetchedBodyStr, err = client.GetEntryByIndex(context.Background(), receipt.LogIndex)
				}
				if err != nil {
					res.Valid = false
					res.Message = "failed to fetch entry for signature verification: " + err.Error()
					printJSON(res)
					os.Exit(1)
				}
				extractedPEM, err := ExtractOperatorPublicKeyPEM(fetchedBodyStr)
				if err != nil {
					res.Valid = false
					res.Message = "failed to extract operator public key: " + err.Error()
					printJSON(res)
					os.Exit(1)
				}
				block, _ := pem.Decode(extractedPEM)
				if block == nil {
					res.Valid = false
					res.Message = "extracted operator public key is not PEM"
					printJSON(res)
					os.Exit(1)
				}
				key, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					res.Valid = false
					res.Message = "failed to parse extracted operator public key: " + err.Error()
					printJSON(res)
					os.Exit(1)
				}
				extractedPubKey, ok := key.(ed25519.PublicKey)
				if !ok {
					res.Valid = false
					res.Message = "extracted operator public key is not Ed25519"
					printJSON(res)
					os.Exit(1)
				}
				sigVer := VerifySignedCheckpoint(checkpoint, extractedPubKey)
				if !sigVer.Valid {
					res.Valid = false
					res.SignatureValid = false
					res.Message = "checkpoint signature verification failed with extracted key: " + sigVer.Message
				}
			}
		}
	} else {
		// Offline verification
		err = VerifyRekorReceiptOffline(receipt, checkpoint, operatorPubKeyPEM, rekorPubKey)
		if err != nil {
			res.Valid = false
			res.RekorValid = false
			res.Message = "offline verification failed: " + err.Error()
		}
	}

	if res.Valid {
		res.Message = "verification succeeded"
	}
	printJSON(res)
	if !res.Valid {
		os.Exit(1)
	}
}

type RekorCheckpointVerificationResult struct {
	Valid            bool   `json:"valid"`
	SignatureValid   bool   `json:"signature_valid"`
	RekorValid       bool   `json:"rekor_valid"`
	RekorOnlineMatch *bool  `json:"rekor_online_match"`
	Message          string `json:"message"`
}
