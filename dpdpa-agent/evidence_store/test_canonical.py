"""The canonical record format and the golden vectors that the Go verifier will also load."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evidence_store import canonical as cn

VECTORS = Path(__file__).resolve().parents[2] / "tests" / "vectors"
V0 = json.loads((VECTORS / "chain_v0.json").read_text(encoding="utf-8"))
V1 = json.loads((VECTORS / "chain_v1.json").read_text(encoding="utf-8"))


# ---- hash_version 0: frozen --------------------------------------------------------------------

def test_v0_chain_vectors_reproduce_with_the_plain_definition():
    prev = V0["genesis"]
    for rec in V0["chain"]:
        assert rec["previous_hash"] == prev
        assert hashlib.sha256((rec["payload_json"] + prev).encode("utf-8")).hexdigest() == rec["expected_hash"]
        assert cn.v0_hash(rec["payload_json"], prev) == rec["expected_hash"]
        prev = rec["expected_hash"]


def test_the_original_store_functions_are_unchanged():
    from evidence_store import store
    for rec in V0["chain"]:
        assert store._compute_hash(rec["payload_json"], rec["previous_hash"]) == rec["expected_hash"]
    assert store.GENESIS_HASH == V0["genesis"]


# ---- hash_version 1 ----------------------------------------------------------------------------

@pytest.mark.parametrize("case", V1["canonical_cases"], ids=lambda c: c["name"])
def test_canonical_json_matches_the_written_out_cases(case):
    assert cn.canonical_json(case["input"]) == case["canonical"]


@pytest.mark.parametrize("case", V1["rejects"], ids=lambda c: c["name"])
def test_things_that_cannot_be_canonical_are_refused(case):
    with pytest.raises(TypeError):
        cn.canonical_json(json.loads(case["input_json"]))


def test_v1_chain_vectors_reproduce_and_continue_the_v0_chain():
    prev = V0["chain"][-1]["expected_hash"]
    for rec in V1["chain"]:
        assert rec["previous_hash"] == prev
        assert cn.canonical_json(rec["body"]) == rec["canonical"]
        material = V1["domain"] + "\n" + prev + "\n" + rec["canonical"]
        assert hashlib.sha256(material.encode("utf-8")).hexdigest() == rec["expected_hash"]
        assert cn.v1_hash(prev, rec["body"]) == rec["expected_hash"]
        prev = rec["expected_hash"]


def test_a_changed_body_a_changed_position_or_a_changed_predecessor_changes_the_hash():
    rec = V1["chain"][0]
    base = cn.v1_hash(rec["previous_hash"], rec["body"])
    assert cn.v1_hash(rec["previous_hash"], {**rec["body"], "severity": "LOW"}) != base
    assert cn.v1_hash(rec["previous_hash"], {**rec["body"], "seq": rec["body"]["seq"] + 1}) != base
    assert cn.v1_hash(rec["previous_hash"], {**rec["body"], "org": "someone_else"}) != base
    assert cn.v1_hash("0" * 64, rec["body"]) != base


def test_member_order_in_the_input_does_not_matter():
    a = {"x": 1, "y": {"b": 2, "a": 1}}
    b = {"y": {"a": 1, "b": 2}, "x": 1}
    assert cn.canonical_json(a) == cn.canonical_json(b)


def test_timestamps_are_utc_with_milliseconds():
    assert cn.rfc3339_ms(datetime(2026, 10, 19, 10, 15, 30, 123456, tzinfo=timezone.utc)) == "2026-10-19T10:15:30.123Z"
    ist = timezone(timedelta(hours=5, minutes=30))
    assert cn.rfc3339_ms(datetime(2026, 10, 19, 15, 45, 30, 0, tzinfo=ist)) == "2026-10-19T10:15:30.000Z"
    assert cn.rfc3339_ms(datetime(2026, 10, 19, 10, 15, 30)) == "2026-10-19T10:15:30.000Z"     # naive means UTC


def test_the_legacy_view_has_the_old_field_names_and_types():
    body = V1["chain"][0]["body"]
    view = cn.legacy_view(body)
    assert view["tenant_id"] == "retail_co" and view["confidence"] == 0.9
    assert view["breach_notification_candidate"] is True and view["used_fallback"] is False
    assert "type" not in view and "seq" not in view and "org" not in view and "confidence_permille" not in view
