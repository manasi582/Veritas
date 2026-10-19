"""Checkpoints: signed, linked, witnessed, retried, and restart-safe."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from anchoring import keys as anchor_keys
from anchoring.checkpoints import AnchorManager, checkpoint_hash, signed_bytes
from anchoring.config import AnchorConfig, load_config
from anchoring.sinks import FileSink, Sink, SyslogSink, build_sinks
from evidence_store.store import EvidenceStore
from evidence_store.test_evidence_store import _make_explained_verdict

ORG = "anchor_org"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 19, 10, 0, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


class FlakySink(Sink):
    name = "flaky"

    def __init__(self):
        self.up = False
        self.got = []

    def publish(self, cp):
        if not self.up:
            raise ConnectionError("witness unreachable")
        self.got.append(cp)
        return "stored"

    def health(self):
        return {"sink": self.name, "ok": self.up, "detail": "up" if self.up else "down"}


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "e.db")
    yield s
    s.close()


def add(store, n=1):
    for _ in range(n):
        store.append(_make_explained_verdict(tenant_id=ORG))


def manager(store, tmp_path, clock=None, sinks=None, **cfg):
    cfg.setdefault("enabled", True)
    config = AnchorConfig(**cfg)
    return AnchorManager(store, config, sinks=sinks if sinks is not None else [FileSink(str(tmp_path / "w1"))],
                         clock=clock or Clock())


# ---- the checkpoint itself --------------------------------------------------------------------

def test_a_checkpoint_states_the_chain_head_and_its_signature_verifies(store, tmp_path):
    add(store, 3)
    m = manager(store, tmp_path)
    cp = m.checkpoint_now(ORG)
    head = store.chain_head(ORG)
    assert (cp["last_seq"], cp["head_hash"], cp["record_count"], cp["cp_seq"]) == (3, head["head_hash"], 3, 1)
    _priv, pub, kid = anchor_keys.load_or_create()
    assert cp["key_id"] == kid
    body = {k: v for k, v in cp.items() if k != "signature"}
    assert anchor_keys.verify_signature(pub, signed_bytes(body), cp["signature"])
    assert not anchor_keys.verify_signature(pub, signed_bytes({**body, "head_hash": "0" * 64}), cp["signature"])


def test_checkpoints_link_to_each_other(store, tmp_path):
    m = manager(store, tmp_path)
    add(store)
    first = m.checkpoint_now(ORG)
    add(store)
    second = m.checkpoint_now(ORG)
    assert "prev_checkpoint_hash" not in first
    assert second["prev_checkpoint_hash"] == checkpoint_hash({k: v for k, v in first.items() if k != "signature"})
    assert second["cp_seq"] == 2


def test_no_new_records_means_no_new_checkpoint(store, tmp_path):
    add(store)
    m = manager(store, tmp_path)
    assert m.checkpoint_now(ORG) is not None
    assert m.checkpoint_now(ORG) is None
    assert manager(store, tmp_path).checkpoint_now(ORG) is None          # a restart changes nothing
    assert len(m.list_checkpoints(ORG)) == 1


def test_a_status_change_moves_the_head_and_is_anchored_too(store, tmp_path):
    add(store)
    m = manager(store, tmp_path)
    m.checkpoint_now(ORG)
    vid = store.query(ORG)[0]["verdict_id"]
    store.update_status(ORG, vid, "ACKNOWLEDGED", actor="asha")
    cp = m.checkpoint_now(ORG)
    assert cp is not None and cp["last_seq"] == 2


# ---- when ---------------------------------------------------------------------------------------

def test_it_waits_for_the_interval_or_enough_new_records(store, tmp_path):
    clock = Clock()
    m = manager(store, tmp_path, clock, interval_minutes=5, every_n_records=10)
    add(store)
    assert m.due(ORG)                                   # the first one is taken at once
    m.checkpoint_now(ORG)
    add(store)
    assert not m.due(ORG)                               # one new record, little time
    clock.advance(minutes=6)
    assert m.due(ORG)                                   # the interval passed
    m.checkpoint_now(ORG)
    add(store, 10)
    assert m.due(ORG)                                   # ten new records, no time passed
    assert not manager(store, tmp_path, clock).due("an_org_with_nothing")


def test_tick_takes_due_checkpoints_for_every_organization(store, tmp_path):
    for org in ("o1", "o2"):
        store.append(_make_explained_verdict(tenant_id=org))
    m = manager(store, tmp_path)
    m.tick()
    assert len(m.list_checkpoints("o1")) == 1 and len(m.list_checkpoints("o2")) == 1


# ---- witnesses ----------------------------------------------------------------------------------

def test_it_is_witnessed_when_enough_witnesses_hold_it(store, tmp_path):
    add(store)
    one, two = FileSink(str(tmp_path / "w1")), FileSink(str(tmp_path / "w2"))
    m = manager(store, tmp_path, sinks=[one, two], min_witnesses=2)
    cp = m.checkpoint_now(ORG)
    listed = m.list_checkpoints(ORG)[0]
    assert listed["status"] == "WITNESSED" and len(listed["receipts"]) == 2
    for w in ("w1", "w2"):
        files = list((tmp_path / w / ORG).glob("*.json"))
        assert len(files) == 1 and json.loads(files[0].read_text())["signature"] == cp["signature"]


def test_one_witness_is_not_enough_when_two_are_required(store, tmp_path):
    add(store)
    flaky = FlakySink()
    m = manager(store, tmp_path, sinks=[FileSink(str(tmp_path / "w1")), flaky], min_witnesses=2)
    m.checkpoint_now(ORG)
    assert m.list_checkpoints(ORG)[0]["status"] == "PENDING"
    assert m.status(ORG)["orgs"][ORG]["pending"] == 1


def test_an_unreachable_witness_is_retried_with_backoff_until_it_takes_the_checkpoint(store, tmp_path):
    clock = Clock()
    flaky = FlakySink()
    add(store)
    m = manager(store, tmp_path, clock, sinks=[flaky], min_witnesses=1)
    m.checkpoint_now(ORG)
    assert m.list_checkpoints(ORG)[0]["status"] == "PENDING"
    flaky.up = True
    m.publish_pending()                                  # too soon after the first failure: not tried again
    assert flaky.got == []
    clock.advance(seconds=31)
    m.publish_pending()
    assert len(flaky.got) == 1 and m.list_checkpoints(ORG)[0]["status"] == "WITNESSED"
    assert m.list_checkpoints(ORG)[0]["receipts"][0]["attempts"] == 2


def test_the_same_checkpoint_is_not_written_twice_to_a_file_witness(store, tmp_path):
    add(store)
    sink = FileSink(str(tmp_path / "w1"))
    m = manager(store, tmp_path, sinks=[sink])
    cp = m.checkpoint_now(ORG)
    sink.publish(cp)                                     # a retry after a lost acknowledgement
    assert len(list((tmp_path / "w1" / ORG).glob("*.json"))) == 1


def test_a_file_witness_never_overwrites_a_different_checkpoint(store, tmp_path):
    add(store)
    sink = FileSink(str(tmp_path / "w1"))
    cp = manager(store, tmp_path, sinks=[sink]).checkpoint_now(ORG)
    with pytest.raises(FileExistsError):
        sink.publish({**cp, "head_hash": "f" * 64})


# ---- status for the dashboard -----------------------------------------------------------------------------

def test_the_banner_appears_when_nothing_is_witnessed_for_two_intervals(store, tmp_path):
    clock = Clock()
    flaky = FlakySink()
    add(store)
    m = manager(store, tmp_path, clock, sinks=[flaky], interval_minutes=5)
    m.checkpoint_now(ORG)
    assert m.status(ORG)["banner"] is True               # records exist, none witnessed ever
    flaky.up = True
    clock.advance(seconds=40)
    m.publish_pending()
    assert m.status(ORG)["banner"] is False
    add(store)                                           # new records, an old witnessed checkpoint
    assert m.status(ORG)["banner"] is False
    clock.advance(minutes=11)
    assert m.status(ORG)["banner"] is True and m.status(ORG)["orgs"][ORG]["unanchored_records"] == 1


def test_one_witness_is_flagged_as_a_weaker_set_up(store, tmp_path):
    assert manager(store, tmp_path, min_witnesses=1).status()["single_witness"] is True
    assert manager(store, tmp_path, sinks=[FileSink(str(tmp_path / "a")), FileSink(str(tmp_path / "b"))],
                   min_witnesses=2).status()["single_witness"] is False


# ---- configuration --------------------------------------------------------------------------------------

def test_configuration_from_the_yaml_file(tmp_path):
    f = tmp_path / "anchoring.yaml"
    f.write_text("anchoring:\n  enabled: true\n  interval_minutes: 2\n  every_n_records: 50\n  min_witnesses: 2\n"
                 "  sinks:\n    - {type: file, path: /mnt/a}\n    - {type: syslog, host: siem, port: 6514, protocol: tcp-tls}\n")
    cfg = load_config(f)
    assert cfg.enabled and cfg.interval_minutes == 2 and cfg.every_n_records == 50 and cfg.min_witnesses == 2
    assert len(cfg.sinks) == 2 and not cfg.problems
    sinks = build_sinks(cfg.sinks)
    assert isinstance(sinks[0], FileSink) and isinstance(sinks[1], SyslogSink)


def test_anchoring_is_off_by_default_and_problems_are_reported(tmp_path, monkeypatch):
    monkeypatch.delenv("VERITAS_ANCHOR_DIR", raising=False)
    assert load_config(tmp_path / "missing.yaml").enabled is False
    f = tmp_path / "a.yaml"
    f.write_text("anchoring:\n  enabled: true\n  min_witnesses: 2\n  sinks:\n    - {type: file, path: /x}\n")
    assert any("min_witnesses" in p for p in load_config(f).problems)
    f.write_text("anchoring:\n  enabled: true\n")
    assert any("no witness" in p for p in load_config(f).problems)


def test_a_single_folder_setting_switches_anchoring_on(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_ANCHOR_DIR", str(tmp_path / "share"))
    cfg = load_config(tmp_path / "missing.yaml")
    assert cfg.enabled and cfg.sinks == [{"type": "file", "path": str(tmp_path / "share")}]


def test_unknown_witness_types_are_refused_clearly():
    with pytest.raises(ValueError, match="unknown witness type"):
        build_sinks([{"type": "carrier-pigeon"}])
    with pytest.raises(ValueError, match="syslog protocol"):
        SyslogSink("h", 514, "smoke-signals")


def test_the_signing_key_is_private_and_stable(tmp_path):
    import os, stat, sys
    _p1, pub1, kid1 = anchor_keys.load_or_create()
    _p2, pub2, kid2 = anchor_keys.load_or_create()
    assert pub1 == pub2 and kid1 == kid2 and len(pub1) == 32
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(anchor_keys.key_path()).st_mode) == 0o600
