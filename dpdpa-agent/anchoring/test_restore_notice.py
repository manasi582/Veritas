"""
A restore must be visible. The restore leaves a marker; the server turns it into a signed RESTORE_EVENT, an audit entry and a floor
under the checkpoint numbers; and the stand-alone verifier then reports the checkpoints that described the set-aside history as
information instead of a failure. Without the event the same evidence is (rightly) reported as a witness divergence.
"""
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

import restore_notice
from anchoring import export as anchor_export
from anchoring.checkpoints import AnchorManager
from anchoring.config import AnchorConfig
from anchoring.sinks import FileSink
from anchoring.test_verifier import ORG, World, codes, run, verifier, data_dir  # noqa: F401  (fixtures)
from audit_log.store import get_audit_store
from evidence_store import canonical as cn
from evidence_store.store import EvidenceStore
from evidence_store.test_evidence_store import _make_explained_verdict


def snapshot(src: Path, dst: Path) -> Path:
    """What a backup holds: a consistent copy of the database at one moment."""
    a, b = sqlite3.connect(str(src)), sqlite3.connect(str(dst))
    a.backup(b)
    a.close(); b.close()
    return dst


def files_for(store, manager, tmp, name):
    d = tmp / name
    d.mkdir(exist_ok=True)
    (d / "evidence.jsonl").write_text("".join(anchor_export.evidence_lines(store, ORG)), encoding="utf-8")
    (d / "cps.jsonl").write_text("".join(anchor_export.checkpoint_lines(manager, ORG)), encoding="utf-8")
    (d / "veritas.pub").write_text(anchor_export.public_key_text())
    return d


@pytest.fixture
def rewound(tmp_path):
    """16 records and 2 checkpoints; a backup; 10 more records and checkpoint 3; then the backup is restored."""
    w = World(tmp_path).build()
    backup_db = snapshot(w.store.db_path, tmp_path / "backup.db")
    w.add(10)
    w.manager.checkpoint_now(ORG)                                   # checkpoint 3 reaches both witnesses, then is set aside
    before_db = snapshot(w.store.db_path, tmp_path / "before.db")
    w.store.close()
    live = tmp_path / "restored.db"
    shutil.copyfile(backup_db, live)
    store = EvidenceStore(live)
    manager = AnchorManager(store, AnchorConfig(enabled=True, min_witnesses=2), sinks=[FileSink(str(w.w1)), FileSink(str(w.w2))])
    yield {"w": w, "store": store, "manager": manager, "before": before_db, "after": live, "tmp": tmp_path}
    store.close()


def test_the_marker_names_the_backup_what_was_held_and_the_checkpoints_set_aside(rewound):
    p = restore_notice.write_marker(rewound["tmp"], Path("/var/lib/veritas/backups/b-1.zip"), rewound["before"], rewound["after"], actor="asha")
    m = json.loads(p.read_text())
    assert m["backup"] == "b-1.zip" and m["actor"] == "asha"
    assert m["orgs"][ORG] == {"records_before": 26, "head_before": m["orgs"][ORG]["head_before"], "restored_away": [3]}
    assert len(m["orgs"][ORG]["head_before"]) == 64


def test_the_server_records_the_restore_in_the_chain_the_audit_log_and_the_checkpoint_numbering(rewound):
    restore_notice.write_marker(rewound["tmp"], Path("b-1.zip"), rewound["before"], rewound["after"], actor="asha")
    store, manager = rewound["store"], rewound["manager"]
    assert restore_notice.apply_pending(store, rewound["tmp"], manager) == 1
    rows = [r for r in store.export_records(ORG) if r["record_type"] == cn.RESTORE_EVENT]
    assert len(rows) == 1
    b = rows[0]["body"]
    assert b["backup"] == "b-1.zip" and b["records_before"] == 26 and b["records_after"] == 16 and b["restored_away"] == [3] and b["actor"] == "asha"
    assert store.verify_chain(ORG)["valid"] is True
    entries = [e for e in get_audit_store().query(action="RESTORE", limit=20) if e["org_id"] == ORG]
    assert entries and entries[0]["detail"]["dropped_records"] == 10 and entries[0]["detail"]["checkpoints_set_aside"] == [3]
    store.append(_make_explained_verdict(tenant_id=ORG))
    cp = manager.checkpoint_now(ORG)
    assert cp["cp_seq"] == 4                                          # not 3: a number a witness holds is never used twice
    assert not (rewound["tmp"] / restore_notice.MARKER).exists() and (rewound["tmp"] / "RESTORE_PENDING.done").exists()
    assert restore_notice.apply_pending(store, rewound["tmp"], manager) == 0       # once only


def test_the_verifier_calls_a_recorded_restore_information_not_a_failure(verifier, rewound):
    restore_notice.write_marker(rewound["tmp"], Path("b-1.zip"), rewound["before"], rewound["after"], actor="asha")
    store, manager = rewound["store"], rewound["manager"]
    restore_notice.apply_pending(store, rewound["tmp"], manager)
    store.append(_make_explained_verdict(tenant_id=ORG))
    manager.checkpoint_now(ORG)
    d = files_for(store, manager, rewound["tmp"], "after")
    for witness in (rewound["w"].w1, rewound["w"].w2, None):
        code, out = run(verifier, d, witness=witness)
        assert code == 0 and out["result"] == "PASS", out
        assert "RESTORED_HISTORY" in codes(out) and "b-1.zip" in json.dumps(out)
        assert not (codes(out) & {"WITNESS_DIVERGENCE", "CHECKPOINT_GAP", "CHECKPOINT_HEAD_MISMATCH", "TAIL_TRUNCATED"})


def test_without_the_event_the_same_restore_is_a_witness_divergence(verifier, rewound):
    """No marker, no event: the witnesses hold checkpoint 3 of the discarded history and the live chain cannot account for it."""
    store, manager = rewound["store"], rewound["manager"]
    store.append(_make_explained_verdict(tenant_id=ORG))
    manager.checkpoint_now(ORG)                                       # numbered 3 again, as a server without the fix would
    d = files_for(store, manager, rewound["tmp"], "unexplained")
    code, out = run(verifier, d, witness=rewound["w"].w1)
    assert code == 1 and "WITNESS_DIVERGENCE" in codes(out), out


def test_a_restore_event_cannot_excuse_a_checkpoint_it_does_not_name(verifier, rewound):
    """Only the numbers the signed event lists are explained: a tampered checkpoint elsewhere still fails."""
    restore_notice.write_marker(rewound["tmp"], Path("b-1.zip"), rewound["before"], rewound["after"])
    store, manager = rewound["store"], rewound["manager"]
    restore_notice.apply_pending(store, rewound["tmp"], manager)
    store.append(_make_explained_verdict(tenant_id=ORG))
    manager.checkpoint_now(ORG)
    d = files_for(store, manager, rewound["tmp"], "forged")
    lines = (d / "cps.jsonl").read_text().splitlines()
    cp = json.loads(lines[0]); cp["head_hash"] = "0" * 64              # checkpoint 1 is not among those set aside
    lines[0] = json.dumps(cp, sort_keys=True, separators=(",", ":"))
    (d / "cps.jsonl").write_text("\n".join(lines) + "\n")
    code, out = run(verifier, d)
    assert code == 1 and codes(out) & {"SIGNATURE_INVALID", "CHECKPOINT_HEAD_MISMATCH"}, out


def test_the_restore_routine_writes_the_marker_after_a_real_restore(tmp_path, monkeypatch):
    import backup
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))
    root = tmp_path / "data"
    (root).mkdir(parents=True, exist_ok=True)
    for name in ("agents.db", "users.db", "audit.db"):               # the other databases a backup requires
        c = sqlite3.connect(str(root / name)); c.execute("CREATE TABLE t (x)"); c.commit(); c.close()
    st = EvidenceStore(root / "evidence.db")
    st.append(_make_explained_verdict(tenant_id=ORG))
    st.close()
    zp = backup.create_backup(tmp_path / "b.zip")
    st = EvidenceStore(root / "evidence.db")
    for _ in range(4):
        st.append(_make_explained_verdict(tenant_id=ORG))
    st.close()
    result = backup.restore_backup(zp, target_root=root, force=True)
    assert result["success"], result
    m = json.loads((root / restore_notice.MARKER).read_text())
    assert m["backup"] == "b.zip" and m["orgs"][ORG]["records_before"] == 5
