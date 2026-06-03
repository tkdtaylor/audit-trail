package main

import (
	"bytes"
	"encoding/json"
)

// canonical returns the RFC 8785 (JSON Canonicalization Scheme) encoding of v.
//
// audit events use only ASCII object keys and integer/string/bool/null/array/object
// values (no floats, no non-BMP characters). Within that domain Go's encoding/json with
// HTML-escaping disabled is byte-identical to a full JCS implementation: it sorts object
// keys, emits no insignificant whitespace, and renders int64 as its shortest decimal form.
// Floats are deliberately kept out of audited events (the one place a naive serializer
// would diverge from JCS — see decisions.md D2 in the tracer).
func canonical(v map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
