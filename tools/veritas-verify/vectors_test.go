package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The golden vectors in tests/vectors/ are shared with the Python implementation: both must reproduce them.
func loadVectors(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]interface{})
}

func TestV0Chain(t *testing.T) {
	v := loadVectors(t, "chain_v0.json")
	prev := v["genesis"].(string)
	if prev != genesisHash {
		t.Fatalf("genesis %q != %q", prev, genesisHash)
	}
	for _, e := range v["chain"].([]interface{}) {
		r := e.(map[string]interface{})
		if r["previous_hash"] != prev {
			t.Fatalf("vector does not link")
		}
		got := hashV0(r["payload_json"].(string), prev)
		if got != r["expected_hash"] {
			t.Fatalf("v0 hash %s, want %s", got, r["expected_hash"])
		}
		prev = got
	}
}

func TestCanonicalCases(t *testing.T) {
	v := loadVectors(t, "chain_v1.json")
	for _, e := range v["canonical_cases"].([]interface{}) {
		c := e.(map[string]interface{})
		got, err := canonicalJSON(c["input"])
		if err != nil {
			t.Fatalf("%s: %v", c["name"], err)
		}
		if got != c["canonical"] {
			t.Errorf("%s:\n got  %s\n want %s", c["name"], got, c["canonical"])
		}
	}
}

func TestRejects(t *testing.T) {
	v := loadVectors(t, "chain_v1.json")
	for _, e := range v["rejects"].([]interface{}) {
		c := e.(map[string]interface{})
		in, err := decodeJSON([]byte(c["input_json"].(string)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := canonicalJSON(in); err == nil {
			t.Errorf("%s was accepted", c["name"])
		}
	}
}

func TestV1Chain(t *testing.T) {
	v0 := loadVectors(t, "chain_v0.json")
	chain := v0["chain"].([]interface{})
	prev := chain[len(chain)-1].(map[string]interface{})["expected_hash"].(string)
	v1 := loadVectors(t, "chain_v1.json")
	for _, e := range v1["chain"].([]interface{}) {
		r := e.(map[string]interface{})
		if r["previous_hash"] != prev {
			t.Fatalf("v1 vector does not continue the v0 chain")
		}
		c, err := canonicalJSON(r["body"])
		if err != nil || c != r["canonical"] {
			t.Fatalf("canonical body differs: %v\n got  %s\n want %s", err, c, r["canonical"])
		}
		got, err := hashV1(prev, r["body"].(map[string]interface{}))
		if err != nil || got != r["expected_hash"] {
			t.Fatalf("v1 hash %s, want %s (%v)", got, r["expected_hash"], err)
		}
		prev = got
	}
}

func TestJSONNumbersStayExact(t *testing.T) {
	in, _ := decodeJSON([]byte(`{"big":9007199254740993}`))
	got, _ := canonicalJSON(in)
	if got != `{"big":9007199254740993}` {
		t.Fatalf("lost precision: %s", got)
	}
}
