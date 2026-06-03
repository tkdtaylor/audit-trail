package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
)

// serve runs the JSON-over-Unix-socket IPC form of the contract (interface-contracts §1):
// one newline-terminated JSON request {op: emit|verify|ping} -> one JSON response.
func serve(socketPath string, chain *Chain) error {
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
		go handleConn(conn, chain)
	}
}

func handleConn(conn net.Conn, chain *Chain) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req map[string]any
	if err := json.Unmarshal(line, &req); err != nil {
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
		out, err := chain.Emit(event)
		if err != nil {
			writeJSON(conn, errShape("internal", err.Error()))
			return
		}
		writeJSON(conn, out)
	case "verify":
		writeJSON(conn, chain.Verify())
	case "ping":
		writeJSON(conn, map[string]any{"ok": true})
	default:
		writeJSON(conn, errShape("unknown_op", "unsupported op"))
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
