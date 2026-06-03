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
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: audit-trail <serve|emit|verify> [flags]")
	os.Exit(2)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket path (required)")
	logfile := fs.String("logfile", "audit.log", "JSONL log path")
	fs.Parse(args)
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "serve: --socket is required")
		os.Exit(2)
	}
	chain, err := NewChain(*logfile)
	check(err)
	fmt.Fprintf(os.Stderr, "audit-trail serving on %s (log=%s)\n", *socket, *logfile)
	check(serve(*socket, chain))
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

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
