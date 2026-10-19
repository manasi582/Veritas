"""
The stand-alone verifier, run as a real program against evidence made by the real code, and then against
evidence someone has tampered with. Needs Go (or VERITAS_VERIFY_BIN pointing at a built veritas-verify).
"""
import json
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from anchoring import export as anchor_export
from anchoring.checkpoints import AnchorManager
from anchoring.config import AnchorConfig
from anchoring.sinks import FileSink
from db_encryption import decrypt_field, encrypt_field
from evidence_store import canonical as cn
from evidence_store.store import GENESIS_HASH, EvidenceStore
from evidence_store.test_evidence_store import _make_explained_verdict

ORG = "verify_org"
TOOL_DIR = Path(__file__).resolve().parents[2] / "tools" / "veritas-verify"
LEGACY_DB = Path(__file__).resolve().parents[1] / "evidence_store" / "evidence.db"


@pytest.fixture(scope="session")
def verifier(tmp_path_factory):
    env = os.environ.get("VERITAS_VERIFY_BIN")
    if env and Path(env).exists():
        return env
    go = shutil.which("go")
    if not go:
        pytest.skip("Go is not installed and VERITAS_VERIFY_BIN is not set")
    out = tmp_path_factory.mktemp("bin") / ("veritas-verify.exe" if os.name == "nt" else "veritas-verify")
    subprocess.run([go, "build", "-o", str(out), "."], cwd=TOOL_DIR, check=True, capture_output=True)
    return str(out)


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))


class World:
    """An organization with evidence, anchored twice, and the files an auditor would take away."""

    def __init__(self, tmp_path, org=ORG):
        self.tmp, self.org = tmp_path, org
        self.store = EvidenceStore(tmp_path / "e.db")
        self.w1, self.w2 = tmp_path / "witness1", tmp_path / "witness2"
        self.manager = AnchorManager(self.store, AnchorConfig(enabled=True, min_witnesses=2),
                                     sinks=[FileSink(str(self.w1)), FileSink(str(self.w2))])

    def add(self, n):
        for _ in range(n):
            self.store.append(_make_explained_verdict(tenant_id=self.org))

    def build(self):
        self.add(10)
        vid = self.store.query(self.org)[0]["verdict_id"]
        self.store.update_status(self.org, vid, "ACKNOWLEDGED", actor="asha")
        self.manager.checkpoint_now(self.org)        # anchors records 1..11
        self.add(5)
        self.manager.checkpoint_now(self.org)        # anchors records 1..16
        return self

    def files(self, name="a"):
        d = self.tmp / name
        d.mkdir(exist_ok=True)
        (d / "evidence.jsonl").write_text("".join(anchor_export.evidence_lines(self.store, self.org)), encoding="utf-8")
        (d / "cps.jsonl").write_text("".join(anchor_export.checkpoint_lines(self.manager, self.org)), encoding="utf-8")
        (d / "veritas.pub").write_text(anchor_export.public_key_text())
        return d


def run(verifier, d, witness=None, extra=()):
    args = [verifier, "--evidence", str(d / "evidence.jsonl"), "--checkpoints", str(d / "cps.jsonl"),
            "--pubkey", str(d / "veritas.pub"), "--json", *extra]
    if witness:
        args += ["--witness-dir", str(witness)]
    p = subprocess.run(args, capture_output=True, text=True)
    try:
        out = json.loads(p.stdout)
    except ValueError:
        out = {"stdout": p.stdout, "stderr": p.stderr}
    return p.returncode, out


def codes(out):
    return {f["code"] for f in out.get("findings", [])}


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path).build()
    yield w
    w.store.close()


def recompute_from(store, org, seq, edit=None):
    """What an attacker with write access to the file does: change a record, then redo every hash after it."""
    conn = store._conn
    rows = conn.execute("SELECT * FROM evidence WHERE tenant_id = ? ORDER BY seq", (org,)).fetchall()
    prev = rows[seq - 2]["row_hash"] if seq > 1 else GENESIS_HASH
    for row in rows[seq - 1:]:
        body = json.loads(decrypt_field(row["payload_json"]))
        if edit and row["seq"] == seq:
            edit(body)
            if row["record_type"] == "VERDICT":
                conn.execute("UPDATE evidence SET severity = ?, rule_id = ? WHERE row_index = ?",
                             (body["severity"], body["rule_id"], row["row_index"]))
        h = cn.v1_hash(prev, body)
        conn.execute("UPDATE evidence SET payload_json = ?, previous_hash = ?, row_hash = ? WHERE row_index = ?",
                     (encrypt_field(cn.canonical_json(body)), prev, h, row["row_index"]))
        prev = h
    conn.commit()


# ---- the good case ---------------------------------------------------------------------------------

def test_clean_evidence_passes(verifier, world):
    code, out = run(verifier, world.files())
    assert code == 0 and out["result"] == "PASS", out
    assert out["records"] == 16 and out["checkpoints"] == 2 and out["unanchored_records"] == 0


def test_clean_evidence_passes_with_the_witness_copies(verifier, world):
    code, out = run(verifier, world.files(), witness=world.w1)
    assert code == 0, out
    code, out = run(verifier, world.files(), witness=world.w2)
    assert code == 0, out


def test_records_after_the_last_checkpoint_are_reported_but_not_a_failure(verifier, world):
    world.add(3)
    code, out = run(verifier, world.files())
    assert code == 0 and out["unanchored_records"] == 3 and "UNANCHORED_TAIL" in codes(out)


# ---- tampering ------------------------------------------------------------------------------------------

def test_an_edit_with_every_later_hash_recomputed_fools_the_dashboard_but_not_the_verifier(verifier, world):
    # the record is edited and everything after it is re-chained: the dashboard's own check passes
    recompute_from(world.store, world.org, 4, edit=lambda b: b.update(severity="LOW", rule_id="RETENTION_001"))
    assert world.store.verify_chain(world.org)["valid"] is True
    code, out = run(verifier, world.files("tampered"))
    assert code == 1 and "CHECKPOINT_HEAD_MISMATCH" in codes(out), out
    assert out["result"] == "FAIL"
    # and the witnesses' own copies expose it the same way, with no help from the server's checkpoints
    code, out = run(verifier, world.files("tampered"), witness=world.w1)
    assert code == 1 and "CHECKPOINT_HEAD_MISMATCH" in codes(out)


def test_deleting_the_newest_records_is_caught(verifier, world):
    world.store._conn.execute("DELETE FROM evidence WHERE tenant_id = ? AND seq > 12", (world.org,))
    world.store._conn.commit()
    code, out = run(verifier, world.files("trunc"))
    assert code == 1 and "TAIL_TRUNCATED" in codes(out), out


def test_deleting_a_record_in_the_middle_is_caught(verifier, world):
    world.store._conn.execute("DELETE FROM evidence WHERE tenant_id = ? AND seq = 6", (world.org,))
    world.store._conn.commit()
    code, out = run(verifier, world.files("mid"))
    assert code == 1 and "CHAIN_BREAK" in codes(out), out


def test_an_edited_record_whose_hash_was_left_alone_is_caught(verifier, world):
    row = world.store._conn.execute("SELECT * FROM evidence WHERE tenant_id=? AND seq=3", (world.org,)).fetchone()
    body = json.loads(decrypt_field(row["payload_json"])); body["severity"] = "LOW"
    world.store._conn.execute("UPDATE evidence SET payload_json=? WHERE row_index=?",
                              (encrypt_field(cn.canonical_json(body)), row["row_index"]))
    world.store._conn.commit()
    code, out = run(verifier, world.files("edit"))
    assert code == 1 and "HASH_MISMATCH" in codes(out)
    assert [f["seq"] for f in out["findings"] if f["code"] == "HASH_MISMATCH"] == [3]       # names the record


def test_a_forged_checkpoint_is_caught(verifier, world):
    d = world.files()
    lines = (d / "cps.jsonl").read_text().splitlines()
    cp = json.loads(lines[-1]); cp["head_hash"] = "0" * 64
    lines[-1] = json.dumps(cp)
    (d / "cps.jsonl").write_text("\n".join(lines) + "\n")
    code, out = run(verifier, d)
    assert code == 1 and "SIGNATURE_INVALID" in codes(out)


def test_checkpoints_signed_with_another_key_are_not_accepted(verifier, world, tmp_path, monkeypatch):
    d = world.files()
    other = tmp_path / "other"; other.mkdir()
    monkeypatch.setenv("VERITAS_DATA_DIR", str(other))
    (d / "veritas.pub").write_text(anchor_export.public_key_text())          # a different server's public key
    code, out = run(verifier, d)
    assert code == 1 and "SIGNATURE_INVALID" in codes(out)


def test_a_missing_checkpoint_is_caught_and_a_witness_copy_fills_it_in(verifier, world):
    d = world.files()
    lines = (d / "cps.jsonl").read_text().splitlines()
    (d / "cps.jsonl").write_text(lines[1] + "\n")                           # the first checkpoint is gone
    code, out = run(verifier, d)
    assert code == 1 and "CHECKPOINT_GAP" in codes(out)
    code, out = run(verifier, d, witness=world.w1)                           # the witness still holds it
    assert code == 0, out


def test_a_witness_copy_that_differs_from_the_servers_is_caught(verifier, world):
    d = world.files()
    target = sorted((world.w2 / world.org).glob("*.json"))[-1]
    cp = json.loads(target.read_text()); cp["record_count"] = 99
    target.write_text(json.dumps(cp))
    code, out = run(verifier, d, witness=world.w2)
    assert code == 1 and "WITNESS_DIVERGENCE" in codes(out)


# ---- bad input ----------------------------------------------------------------------------------------------

def test_missing_arguments_and_files_are_usage_errors(verifier, world):
    assert subprocess.run([verifier], capture_output=True).returncode == 2
    d = world.files()
    (d / "cps.jsonl").unlink()
    assert run(verifier, d)[0] == 2


def test_an_export_cut_short_is_an_input_error_not_a_pass(verifier, world):
    d = world.files()
    lines = (d / "evidence.jsonl").read_text().splitlines()
    (d / "evidence.jsonl").write_text("\n".join(lines[:-3]) + "\n")
    code, out = run(verifier, d)
    assert code == 2


def test_an_unsupported_record_version_is_an_input_error(verifier, world):
    d = world.files()
    lines = (d / "evidence.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["hash_version"] = 7
    lines[1] = json.dumps(rec)
    (d / "evidence.jsonl").write_text("\n".join(lines) + "\n")
    assert run(verifier, d)[0] == 2


# ---- a real old database ---------------------------------------------------------------------------------------

@pytest.mark.skipif(not LEGACY_DB.exists(), reason="the old development database is not in this checkout")
def test_a_chain_of_thousands_of_old_records_continued_by_new_ones_verifies(verifier, tmp_path):
    db = tmp_path / "old.db"
    shutil.copy(LEGACY_DB, db)
    store = EvidenceStore(db)
    org = "blinkit"                                                    # 3,637 version-0 records
    assert store.verify_chain(org)["valid"]
    old = store.chain_head(org)["record_count"]
    for _ in range(5):
        store.append(_make_explained_verdict(tenant_id=org))
    manager = AnchorManager(store, AnchorConfig(enabled=True), sinks=[FileSink(str(tmp_path / "w"))])
    manager.checkpoint_now(org)
    w = World.__new__(World)
    w.tmp, w.org, w.store, w.manager = tmp_path, org, store, manager
    d = w.files()
    code, out = run(verifier, d, witness=tmp_path / "w")
    assert code == 0, out
    assert out["records"] == old + 5
    # change one old record's text: the verifier names it
    victim = store._conn.execute("SELECT row_index, payload_json, seq FROM evidence WHERE tenant_id=? AND hash_version=0 AND seq=100", (org,)).fetchone()
    store._conn.execute("UPDATE evidence SET payload_json=? WHERE row_index=?", (victim["payload_json"].replace("HIGH", "LOW", 1) if "HIGH" in victim["payload_json"] else victim["payload_json"] + " ", victim["row_index"]))
    store._conn.commit()
    d2 = w.files("bad")
    code, out = run(verifier, d2)
    assert code == 1 and "HASH_MISMATCH" in codes(out)
    assert [f["seq"] for f in out["findings"] if f["code"] == "HASH_MISMATCH"] == [100]
    store.close()
