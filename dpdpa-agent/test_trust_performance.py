"""Generous ceilings for the trust features, so a change that makes them an order of magnitude slower fails (docs/PERFORMANCE.md)."""
import random
import time

import pytest

import veritas_recognizers as vr
from evidence_store.store import EvidenceStore
from evidence_store.test_evidence_store import _make_explained_verdict
from flows import build
from incidents.template import template_of
from org_config.schema import OrgConfig


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))
    s = EvidenceStore(tmp_path / "e.db")
    yield s
    s.close()


def test_ten_thousand_findings_group_into_the_expected_incidents_quickly(store):
    words = ["alpha", "beta", "gamma", "delta", "sigma", "omega", "kappa", "lambda", "theta", "zeta"]
    t = time.perf_counter()
    for n in range(10_000):
        store.append(_make_explained_verdict(tenant_id="perf"),
                     grouping=tuple(template_of(f"{words[n % 10]} failed for order {n} user=u{n} after {n} ms")))
    elapsed = time.perf_counter() - t
    assert store.incident_summary("perf")["incidents"] == 10
    assert elapsed < 30, f"{elapsed:.1f} s for 10,000 findings"
    t = time.perf_counter()
    rows, total = store.list_incidents("perf", limit=100)
    assert total == 10 and time.perf_counter() - t < 1


def test_the_map_of_fifty_systems_builds_in_well_under_two_seconds(store):
    labels = ["aadhaar", "pan", "phone", "email", "card"]
    cfg = OrgConfig.model_validate({"org_id": "perf", "fields": [
        {"field_name": f"f{f}", "pii_category": labels[f % 5], "declared_purpose": "p", "consent_scope": "c",
         "retention_days": 30, "source_system": f"s{s}"} for s in range(50) for f in range(6)]})
    for s in range(50):
        for f in range(6):
            for c in labels:
                for d in range(4):
                    store.flows.record("perf", f"s{s}", [(f"f{f}", c)], f"d{d}.example.org")
    t = time.perf_counter()
    m = build.build(store, "perf", cfg)
    build.record_csv(m)
    assert len(m["nodes"]) == 50 and time.perf_counter() - t < 2.0


def test_a_lookup_in_a_large_index_is_fast(store):
    kid, key = store.keyring.current("perf", "lookup")
    with store.writer() as conn:
        conn.executemany("INSERT INTO pii_tokens (org, key_id, token, category, source_system, event_count, first_seen, last_seen) "
                         "VALUES ('perf', ?, ?, 'phone', 's', 1, 't', 't')",
                         ((kid, "%064x" % random.getrandbits(256)) for _ in range(50_000)))
    store.subjects.record("perf", "s1", [(kid, vr.keyed_digest("PHONE", "9876543210", key), "phone")])
    t = time.perf_counter()
    found = store.subjects.lookup_tokens("perf", "phone", store.subjects.tokens_for_identifier("perf", "phone", "9876543210"))
    assert found["systems"][0]["system"] == "s1" and time.perf_counter() - t < 0.5
