package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// Canonical JSON, byte for byte as docs/EVIDENCE_FORMAT.md defines it:
// UTF-8, no whitespace, keys sorted by their UTF-8 bytes, strings/integers/objects/arrays only,
// null members omitted, only " and \ backslash-escaped, control characters as \u00xx (lowercase hex).

const (
	genesisHash = "DPDPA-AGENT-GENESIS-2026"
	chainDomain = "veritas-chain-v1"
	cpDomain    = "veritas-checkpoint-v1"
)

func decodeJSON(raw []byte) (interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func writeCanonical(b *strings.Builder, v interface{}) error {
	switch t := v.(type) {
	case nil:
		return errors.New("null is only allowed as an omitted object member")
	case bool:
		return errors.New("booleans are not allowed in a canonical record")
	case string:
		writeString(b, t)
	case json.Number:
		s := t.String()
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return fmt.Errorf("%q is not a whole number", s)
		}
		b.WriteString(n.String())
	case []interface{}:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k, e := range t {
			if e != nil {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys) // Go compares strings as bytes, which for UTF-8 is the required order
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported value of type %T", v)
	}
	return nil
}

func canonicalJSON(v interface{}) (string, error) {
	var b strings.Builder
	if err := writeCanonical(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hashV0(payloadJSON, prev string) string { return sha256hex(payloadJSON + prev) }

func hashV1(prev string, body map[string]interface{}) (string, error) {
	c, err := canonicalJSON(body)
	if err != nil {
		return "", err
	}
	return sha256hex(chainDomain + "\n" + prev + "\n" + c), nil
}

// checkpointBytes is what a checkpoint's signature covers: the domain, a newline, and the canonical body
// (the checkpoint without its signature).
func checkpointBytes(cp map[string]interface{}) (string, error) {
	body := make(map[string]interface{}, len(cp))
	for k, v := range cp {
		if k != "signature" {
			body[k] = v
		}
	}
	c, err := canonicalJSON(body)
	if err != nil {
		return "", err
	}
	return cpDomain + "\n" + c, nil
}
