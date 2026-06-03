// Command audit-trail is the hash-chained, append-only forensic spine of the secure-agent
// ecosystem. Every block emits to it; verify() walks the chain and detects any tamper.
//
// Contract (interface-contracts.md §2, v1):
//
//	emit(event) -> { seq, hash }
//	verify()    -> { valid, tamper_detected_at, message }
//	hash = SHA256( prev_hash + JCS(event) )
//
// Usage:
//
//	audit-trail serve  --socket /run/audit.sock --logfile audit.log
//	audit-trail emit   --logfile audit.log --actor vault --action resolve --target vault://x
//	audit-trail verify --logfile audit.log
//	audit-trail checkpoint create --logfile audit.log --log-id prod --signing-key key.pem
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: audit-trail <serve|emit|verify|checkpoint> [flags]")
	os.Exit(2)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (required)")
	logfile := fs.String("logfile", "audit.log", "JSONL log path")
	checkpointLogID := fs.String("checkpoint-log-id", "", "checkpoint log identifier")
	checkpointSigningKey := fs.String("checkpoint-signing-key", "", "checkpoint signing key PEM path")
	checkpointPublicKey := fs.String("checkpoint-public-key", "", "checkpoint verification public key PEM path")
	fs.Parse(args)
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "serve: --socket is required")
		os.Exit(2)
	}
	chain, err := NewChain(*logfile)
	check(err)
	fmt.Fprintf(os.Stderr, "audit-trail serving on %s (log=%s)\n", *socket, *logfile)
	check(serve(*socket, chain, CheckpointServerConfig{
		LogID:          *checkpointLogID,
		SigningKeyPath: *checkpointSigningKey,
		PublicKeyPath:  *checkpointPublicKey,
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
	default:
		checkpointUsage()
	}
}

func checkpointUsage() {
	fmt.Fprintln(os.Stderr, "usage: audit-trail checkpoint <create|verify> [flags]")
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
