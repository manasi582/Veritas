// veritas-verify checks an evidence export against its signed checkpoints, without the Veritas server and without a network.
//
//	veritas-verify --evidence export.jsonl --checkpoints cps.jsonl --pubkey veritas.pub [--witness-dir DIR] [--json]
//
// Exit codes: 0 pass, 1 integrity failure, 2 usage or input error.
// The formats are documented in docs/EVIDENCE_FORMAT.md and docs/ANCHORING.md. Build it yourself from this source.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr interface{ Write([]byte) (int, error) }) int {
	fs := flag.NewFlagSet("veritas-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	var asJSON, showVersion bool
	fs.StringVar(&o.EvidencePath, "evidence", "", "evidence export (JSON lines) from GET /v1/{org}/evidence/export")
	fs.StringVar(&o.CheckpointsPath, "checkpoints", "", "checkpoints file (JSON lines) from GET /v1/{org}/anchors/export")
	fs.StringVar(&o.PubKeyPath, "pubkey", "", "the server's public key file from GET /v1/{org}/anchors/pubkey")
	fs.StringVar(&o.WitnessDir, "witness-dir", "", "a folder of witness copies (the file witness's folder); optional")
	fs.BoolVar(&asJSON, "json", false, "print the result as JSON")
	fs.BoolVar(&showVersion, "version", false, "print the version")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if showVersion {
		fmt.Fprintln(stdout, "veritas-verify", version)
		return 0
	}
	if o.EvidencePath == "" || o.CheckpointsPath == "" || o.PubKeyPath == "" {
		fmt.Fprintln(stderr, "usage: veritas-verify --evidence export.jsonl --checkpoints cps.jsonl --pubkey veritas.pub [--witness-dir DIR] [--json]")
		return 2
	}
	rep, err := verify(o)
	if err != nil {
		var ie *InputError
		if errors.As(err, &ie) {
			fmt.Fprintln(stderr, "input error:", ie.msg)
		} else {
			fmt.Fprintln(stderr, "error:", err)
		}
		return 2
	}
	if asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Fprintln(stdout, string(b))
	} else {
		fmt.Fprintf(stdout, "%s  organization %s: %d records, %d checkpoints\n", rep.Result, rep.Org, rep.Records, rep.Checkpoints)
		for _, f := range rep.Findings {
			fmt.Fprintf(stdout, "  %s: %s\n", f.Code, f.Message)
		}
		if rep.Result == "PASS" {
			fmt.Fprintln(stdout, "  The evidence matches every checkpoint. Records after the last checkpoint (if any) are not covered.")
		}
	}
	if rep.Result == "PASS" {
		return 0
	}
	return 1
}
