package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Result codes.
const (
	CodeHashMismatch   = "HASH_MISMATCH"
	CodeChainBreak     = "CHAIN_BREAK"
	CodeHeadMismatch   = "CHECKPOINT_HEAD_MISMATCH"
	CodeTailTruncated  = "TAIL_TRUNCATED"
	CodeSignature      = "SIGNATURE_INVALID"
	CodeGap            = "CHECKPOINT_GAP"
	CodeWitness        = "WITNESS_DIVERGENCE"
	CodeUnanchoredTail = "UNANCHORED_TAIL"  // information only
	CodeRestored       = "RESTORED_HISTORY" // information only: a restore recorded in the chain explains checkpoints that do not match
)

type Finding struct {
	Code    string `json:"code"`
	Seq     int64  `json:"seq,omitempty"`
	Message string `json:"message"`
}

type Report struct {
	Result            string    `json:"result"` // PASS or FAIL
	Org               string    `json:"org"`
	Records           int       `json:"records"`
	Checkpoints       int       `json:"checkpoints"`
	UnanchoredRecords int64     `json:"unanchored_records"`
	Findings          []Finding `json:"findings"`
}

// InputError is a problem with what was given (exit code 2), not with the evidence.
type InputError struct{ msg string }

func (e *InputError) Error() string { return e.msg }
func inputErr(format string, a ...interface{}) error {
	return &InputError{fmt.Sprintf(format, a...)}
}

type record struct {
	Seq         int64
	Type        string
	HashVersion int
	Prev, Hash  string
	PayloadJSON string                 // version 0: the exact stored text
	Body        map[string]interface{} // version 1
}

type evidence struct {
	Org     string
	Records []record
}

func num(v interface{}) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func str(m map[string]interface{}, k string) string {
	s, _ := m[k].(string)
	return s
}

func readLines(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, inputErr("cannot open %s: %v", path, err)
	}
	defer f.Close()
	var lines [][]byte
	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if t := strings.TrimSpace(string(line)); t != "" {
			lines = append(lines, []byte(t))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, inputErr("cannot read %s: %v", path, err)
		}
	}
	return lines, nil
}

func loadEvidence(path string) (*evidence, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, inputErr("%s is empty", path)
	}
	hv, err := decodeJSON(lines[0])
	header, ok := hv.(map[string]interface{})
	if err != nil || !ok || str(header, "format") != "veritas-evidence-export" {
		return nil, inputErr("%s does not start with a veritas-evidence-export header", path)
	}
	if v, _ := num(header["version"]); v != 1 {
		return nil, inputErr("export format version %v is not supported", header["version"])
	}
	ev := &evidence{Org: str(header, "org")}
	if ev.Org == "" {
		return nil, inputErr("the export header names no organization")
	}
	for n, line := range lines[1:] {
		rv, err := decodeJSON(line)
		m, ok := rv.(map[string]interface{})
		if err != nil || !ok {
			return nil, inputErr("record line %d is not a JSON object", n+2)
		}
		seq, _ := num(m["seq"])
		ver, _ := num(m["hash_version"])
		r := record{Seq: seq, Type: str(m, "record_type"), HashVersion: int(ver), Prev: str(m, "prev"), Hash: str(m, "hash")}
		switch ver {
		case 0:
			r.PayloadJSON = str(m, "payload_json")
		case 1:
			r.Body, _ = m["body"].(map[string]interface{})
			if r.Body == nil {
				return nil, inputErr("record %d has no body", seq)
			}
		default:
			return nil, inputErr("record %d uses hash_version %d, which this verifier does not support", seq, ver)
		}
		ev.Records = append(ev.Records, r)
	}
	if want, ok := num(header["record_count"]); ok && want != int64(len(ev.Records)) {
		return nil, inputErr("the header says %d records but the file holds %d (an incomplete export?)", want, len(ev.Records))
	}
	return ev, nil
}

func loadPublicKey(path string) (ed25519.PublicKey, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", inputErr("cannot read the public key %s: %v", path, err)
	}
	var b64, id string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "public_key:") {
			b64 = strings.TrimSpace(strings.TrimPrefix(line, "public_key:"))
		}
		if strings.HasPrefix(line, "key_id:") {
			id = strings.TrimSpace(strings.TrimPrefix(line, "key_id:"))
		}
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, "", inputErr("%s holds no valid public_key", path)
	}
	sum := sha256.Sum256(key)
	if want := hex.EncodeToString(sum[:])[:16]; id != "" && id != want {
		return nil, "", inputErr("the key_id in %s does not match its public key", path)
	}
	return ed25519.PublicKey(key), hex.EncodeToString(sum[:])[:16], nil
}

func loadCheckpointsFile(path string) ([]map[string]interface{}, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	var out []map[string]interface{}
	for n, line := range lines {
		v, err := decodeJSON(line)
		m, ok := v.(map[string]interface{})
		if err != nil || !ok {
			return nil, inputErr("checkpoint line %d is not a JSON object", n+1)
		}
		out = append(out, m)
	}
	return out, nil
}

func loadWitnessDir(dir string) ([]map[string]interface{}, error) {
	var out []map[string]interface{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		v, err := decodeJSON(raw)
		if m, ok := v.(map[string]interface{}); err == nil && ok {
			out = append(out, m)
		}
		return nil
	})
	if err != nil {
		return nil, inputErr("cannot read the witness folder %s: %v", dir, err)
	}
	return out, nil
}

type options struct {
	EvidencePath, CheckpointsPath, PubKeyPath, WitnessDir string
}

func verify(o options) (*Report, error) {
	ev, err := loadEvidence(o.EvidencePath)
	if err != nil {
		return nil, err
	}
	pub, keyID, err := loadPublicKey(o.PubKeyPath)
	if err != nil {
		return nil, err
	}
	exported, err := loadCheckpointsFile(o.CheckpointsPath)
	if err != nil {
		return nil, err
	}
	rep := &Report{Result: "PASS", Org: ev.Org, Records: len(ev.Records), Findings: []Finding{}}
	fail := func(code string, seq int64, format string, a ...interface{}) {
		rep.Findings = append(rep.Findings, Finding{Code: code, Seq: seq, Message: fmt.Sprintf(format, a...)})
	}

	// 1-2: every record's hash and its link to the one before
	prev := genesisHash
	hashAt := map[int64]string{0: genesisHash}
	chainOK := true
	// A RESTORE_EVENT in the verified chain names the checkpoints that described history a recorded restore set aside.
	// Only events before any break are believed.
	away := map[int64]bool{}
	var restoreNote string
	for i, r := range ev.Records {
		if r.Seq != int64(i+1) {
			fail(CodeChainBreak, r.Seq, "record %d is at position %d: a record is missing or out of order", r.Seq, i+1)
			chainOK = false
			break
		}
		if r.Prev != prev {
			fail(CodeChainBreak, r.Seq, "record %d does not link to the record before it", r.Seq)
			chainOK = false
			break
		}
		var want string
		if r.HashVersion == 0 {
			want = hashV0(r.PayloadJSON, prev)
		} else {
			if org := str(r.Body, "org"); org != ev.Org {
				fail(CodeChainBreak, r.Seq, "record %d belongs to organization %q, not %q", r.Seq, org, ev.Org)
				chainOK = false
				break
			}
			if s, _ := num(r.Body["seq"]); s != r.Seq {
				fail(CodeChainBreak, r.Seq, "record %d states position %d inside its body", r.Seq, s)
				chainOK = false
				break
			}
			w, err := hashV1(prev, r.Body)
			if err != nil {
				fail(CodeHashMismatch, r.Seq, "record %d cannot be canonicalized: %v", r.Seq, err)
				chainOK = false
				break
			}
			want = w
		}
		if want != r.Hash {
			fail(CodeHashMismatch, r.Seq, "record %d does not match its hash: its content was changed", r.Seq)
			chainOK = false
			break
		}
		prev = r.Hash
		hashAt[r.Seq] = r.Hash
		if r.Type == "RESTORE_EVENT" && r.Body != nil {
			if list, ok := r.Body["restored_away"].([]interface{}); ok {
				for _, v := range list {
					if n, ok := num(v); ok {
						away[n] = true
					}
				}
			}
			restoreNote = fmt.Sprintf("a restore from %q at %s is recorded in the chain (record %d): the live chain held %d record(s), it had held %d",
				str(r.Body, "backup"), str(r.Body, "restored_at"), r.Seq, restoreRecords(r.Body["records_after"]), restoreRecords(r.Body["records_before"]))
		}
	}

	// checkpoints: the exported ones, then the witnesses' copies
	bySeq := map[int64]map[string]interface{}{}
	for _, cp := range exported {
		if str(cp, "org") != ev.Org {
			continue
		}
		s, _ := num(cp["cp_seq"])
		bySeq[s] = cp
	}
	if o.WitnessDir != "" {
		wit, err := loadWitnessDir(o.WitnessDir)
		if err != nil {
			return nil, err
		}
		for _, w := range wit {
			if str(w, "org") != ev.Org {
				continue
			}
			s, _ := num(w["cp_seq"])
			if away[s] {
				if have, ok := bySeq[s]; !ok || func() bool { a, _ := canonicalJSON(have); b, _ := canonicalJSON(w); return a != b }() {
					continue // the witness holds the set-aside history: explained by the recorded restore
				}
			}
			if have, ok := bySeq[s]; ok {
				a, _ := canonicalJSON(have)
				b, _ := canonicalJSON(w)
				if a != b {
					fail(CodeWitness, 0, "checkpoint %d differs between the server's copy and a witness copy", s)
				}
			} else {
				bySeq[s] = w // a checkpoint only a witness holds still counts
			}
		}
	}
	seqs := make([]int64, 0, len(bySeq))
	for s := range bySeq {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	rep.Checkpoints = len(seqs)

	// 3: signatures and the checkpoint-to-checkpoint links
	prevHash := ""
	for i, s := range seqs {
		cp := bySeq[s]
		msg, err := checkpointBytes(cp)
		sigOK := false
		if err == nil {
			if sig, e := hex.DecodeString(str(cp, "signature")); e == nil {
				sigOK = str(cp, "key_id") == keyID && ed25519.Verify(pub, []byte(msg), sig)
			}
		}
		if !sigOK {
			fail(CodeSignature, 0, "checkpoint %d has an invalid signature (forged, edited, or made with another key)", s)
		}
		if i == 0 && s != 1 {
			fail(CodeGap, 0, "the first checkpoint available is %d: checkpoint(s) before it are missing", s)
		}
		if i > 0 && s != seqs[i-1]+1 {
			all := true
			for n := seqs[i-1] + 1; n < s; n++ {
				if !away[n] {
					all = false
				}
			}
			if !all {
				fail(CodeGap, 0, "checkpoints %d to %d are missing", seqs[i-1]+1, s-1)
			}
		}
		if i > 0 && s == seqs[i-1]+1 && str(cp, "prev_checkpoint_hash") != prevHash {
			fail(CodeGap, 0, "checkpoint %d does not link to checkpoint %d", s, s-1)
		}
		if err == nil {
			prevHash = sha256hex(msg)
		}
	}

	// 4-5: each checkpoint against the recomputed chain, and the evidence must reach the last one
	var lastSeq int64
	for _, s := range seqs {
		cp := bySeq[s]
		ls, _ := num(cp["last_seq"])
		cnt, _ := num(cp["record_count"])
		if ls > lastSeq {
			lastSeq = ls
		}
		if ls > int64(len(ev.Records)) {
			fail(CodeTailTruncated, ls, "checkpoint %d anchors record %d but the evidence ends at record %d: the newest records were removed", s, ls, len(ev.Records))
			continue
		}
		if !chainOK && ls >= firstBroken(rep) {
			continue // the chain itself is already reported broken from here on
		}
		if hashAt[ls] != str(cp, "head_hash") || cnt != ls {
			fail(CodeHeadMismatch, ls, "the evidence at record %d does not match checkpoint %d: records up to there were altered or replaced", ls, s)
		}
	}

	// 7: records after the last checkpoint are exposed until the next one (information only)
	if n := int64(len(ev.Records)) - lastSeq; n > 0 && !hasCode(rep, CodeTailTruncated) {
		rep.UnanchoredRecords = n
		rep.Findings = append(rep.Findings, Finding{Code: CodeUnanchoredTail, Message: fmt.Sprintf("%d record(s) after the last checkpoint are not anchored yet", n)})
	}

	if len(away) > 0 {
		nums := make([]int64, 0, len(away))
		for n := range away {
			nums = append(nums, n)
		}
		sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
		list := make([]string, len(nums))
		for i, n := range nums {
			list[i] = fmt.Sprintf("%d", n)
		}
		rep.Findings = append(rep.Findings, Finding{Code: CodeRestored, Message: fmt.Sprintf(
			"checkpoint(s) %s described history that was set aside: %s. This is information, not a failure; compare the restore with your change records",
			strings.Join(list, ", "), restoreNote)})
	}

	for _, f := range rep.Findings {
		if f.Code != CodeUnanchoredTail && f.Code != CodeRestored {
			rep.Result = "FAIL"
		}
	}
	return rep, nil
}

func restoreRecords(v interface{}) int64 {
	n, _ := num(v)
	return n
}

func firstBroken(r *Report) int64 {
	for _, f := range r.Findings {
		if f.Code == CodeHashMismatch || f.Code == CodeChainBreak {
			return f.Seq
		}
	}
	return 1 << 62
}

func hasCode(r *Report, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
