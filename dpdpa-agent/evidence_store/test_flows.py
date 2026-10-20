"""Observed processing (phase T3): destinations, counters, the map and its colours, the record, isolation."""
import csv
import io
import time

import pytest

from evidence_store import flows as flow_mod
from evidence_store.store import EvidenceStore
from evidence_store.test_evidence_store import _make_explained_verdict
from flows import build
from flows.destination import destination_of
from incidents.template import template_of
from org_config.schema import OrgConfig

ORG = "flow_org"


def config(**owners):
    return OrgConfig.model_validate({
        "org_id": ORG,
        "fields": [
            {"field_name": "phone", "pii_category": "phone", "declared_purpose": "order_updates",
             "consent_scope": "service_delivery", "retention_days": 365, "source_system": "order-service"},
            {"field_name": "email", "pii_category": "email", "declared_purpose": "receipts",
             "consent_scope": "service_delivery", "retention_days": 180, "source_system": "order-service"},
            {"field_name": "email", "pii_category": "email", "declared_purpose": "newsletter",
             "consent_scope": "marketing", "retention_days": 90, "source_system": "marketing-service"},
            {"field_name": "pan", "pii_category": "pan", "declared_purpose": "kyc",
             "consent_scope": "kyc", "retention_days": 365, "source_system": "kyc-service"},
        ],
        **({"owners": owners} if owners else {}),
    })


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "e.db")
    yield s
    s.close()


def see(store, system, *cats, field="raw_snippet", dest=None, org=ORG, n=1):
    for _ in range(n):
        store.flows.record(org, system, [(field, c) for c in cats], dest)


# ---- destinations -------------------------------------------------------------------------------

@pytest.mark.parametrize("fields,text,expected", [
    ({"destination": "https://analytics.vendor.io:8443/v1/track?u=1"}, "", "analytics.vendor.io"),
    ({}, "POST https://api.stripe.com/v1/charges 200", "api.stripe.com"),
    ({}, "uploaded to https://files.example.org/in/abc?token=SECRET", "files.example.org"),
    ({"host": "CRM-DB.internal"}, "", "crm-db.internal"),
    ({"url": "https://user:pass@x.io/a"}, "", "x.io"),
    ({}, "see https://docs.example.com/help for details", None),      # not said to be a destination
    ({"note": "https://nope.io"}, "plain text", None),                # a field with an unrelated name
    ({"destination": "not a host!"}, "", None),
])
def test_destination_is_a_host_name_only(fields, text, expected):
    assert destination_of(fields, text) == expected


def test_a_destination_never_carries_credentials_path_or_query():
    d = destination_of({"url": "https://u:p@pay.example.com:9000/a/b?c=d#e"}, "")
    assert d == "pay.example.com" and all(x not in d for x in ("u:p", "/", "?", "9000"))


# ---- counters ------------------------------------------------------------------------------------

def test_counts_are_written_in_batches_and_survive_a_flush(store):
    see(store, "order-service", "phone", "email", n=3)
    rows = flow_mod.rows(store, ORG)                     # reading flushes first
    assert {(r["category"], r["count"]) for r in rows} == {("phone", 3), ("email", 3)}
    see(store, "order-service", "phone", n=2)
    assert {r["category"]: r["count"] for r in flow_mod.rows(store, ORG)}["phone"] == 5


def test_one_event_counts_a_category_once_even_if_found_twice(store):
    store.flows.record(ORG, "s", [("raw_snippet", "phone"), ("raw_snippet", "phone")])
    assert flow_mod.rows(store, ORG)[0]["count"] == 1


def test_first_and_last_seen_are_kept(store):
    see(store, "s", "phone")
    first = flow_mod.rows(store, ORG)[0]["first_seen"]
    time.sleep(0.01)
    see(store, "s", "phone")
    r = flow_mod.rows(store, ORG)[0]
    assert r["first_seen"] == first and r["last_seen"] > first


def test_a_full_batch_flushes_by_itself(store, monkeypatch):
    monkeypatch.setattr(flow_mod, "FLUSH_KEYS", 3)
    for i in range(3):
        store.flows.record(ORG, f"sys{i}", [("raw_snippet", "phone")])
    raw = store._conn.execute("SELECT COUNT(*) AS n FROM observed_flows").fetchone()["n"]
    assert raw == 3


def test_pending_counts_are_written_when_the_store_closes(tmp_path):
    s = EvidenceStore(tmp_path / "c.db")
    see(s, "s", "phone")
    s.close()
    s2 = EvidenceStore(tmp_path / "c.db")
    assert flow_mod.rows(s2, ORG)[0]["count"] == 1
    s2.close()


def test_counters_can_be_turned_off(store, monkeypatch):
    monkeypatch.setenv("VERITAS_FLOWS", "off")
    see(store, "s", "phone")
    assert flow_mod.rows(store, ORG) == []


def test_other_organizations_have_their_own_counts(store):
    see(store, "s", "phone", org="a")
    see(store, "s", "phone", n=4, org="b")
    assert flow_mod.rows(store, "a")[0]["count"] == 1 and flow_mod.rows(store, "b")[0]["count"] == 4
    assert build.build(store, "c")["nodes"] == []


# ---- the map and its colours --------------------------------------------------------------------

def node(m, system):
    return next(n for n in m["nodes"] if n["id"] == system)


def test_status_colours(store):
    see(store, "order-service", "phone", "email")               # everything observed is declared
    see(store, "marketing-service", "email", "aadhaar")         # aadhaar is not declared there
    m = build.build(store, ORG, config())
    assert node(m, "order-service")["status"] == "green"
    assert node(m, "marketing-service")["status"] == "amber"
    assert node(m, "kyc-service")["status"] == "grey"           # declared, never observed
    assert {c["category"]: c["declared"] for c in node(m, "marketing-service")["observed"]} == {"email": True, "aadhaar": False}


def test_a_system_with_an_open_incident_is_red_until_it_is_resolved(store):
    see(store, "marketing-service", "aadhaar")
    ev = _make_explained_verdict(tenant_id=ORG, source_system="marketing-service")
    store.append(ev, grouping=tuple(template_of("aadhaar read aloud")))
    m = build.build(store, ORG, config())
    n = node(m, "marketing-service")
    assert n["status"] == "red" and n["open_incidents"] == 1 and n["incidents"][0]["number"] == 1
    store.set_incident_status(ORG, n["incidents"][0]["incident_id"], "RESOLVED", actor="asha")
    assert node(build.build(store, ORG, config()), "marketing-service")["status"] == "amber"


def test_a_system_seen_but_not_declared_still_appears(store):
    see(store, "surprise-service", "phone")
    n = node(build.build(store, ORG, config()), "surprise-service")
    assert n["declared"] == [] and n["status"] == "amber"


def test_declared_fields_show_whether_they_were_observed(store):
    see(store, "order-service", "phone", field="phone")
    d = {x["field"]: x["observed"] for x in node(build.build(store, ORG, config()), "order-service")["declared"]}
    assert d == {"phone": True, "email": False}


def test_edges_to_other_systems_and_to_third_parties(store):
    see(store, "order-service", "phone", dest="analytics.vendor.io", n=2)
    see(store, "order-service", "email", dest="marketing-service")
    edges = {e["target"]: e for e in build.build(store, ORG, config())["edges"]}
    assert edges["analytics.vendor.io"]["kind"] == "external" and edges["analytics.vendor.io"]["count"] == 2
    assert edges["marketing-service"]["kind"] == "internal" and edges["marketing-service"]["categories"] == {"email": 1}


def test_the_owner_comes_from_the_organization_settings(store):
    see(store, "order-service", "phone")
    m = build.build(store, ORG, config(**{"order-service": {"team": "Orders", "slack_channel": "#orders"}}))
    assert node(m, "order-service")["owner"]["team"] == "Orders"


def test_the_map_says_what_it_is_not(store):
    m = build.build(store, ORG, config())
    assert "not a complete map" in m["note"] and "not a statement of legal compliance" in m["note"]


# ---- the record ---------------------------------------------------------------------------------

def test_the_record_lists_declared_observed_undeclared_and_destinations(store):
    see(store, "order-service", "phone", field="phone", dest="analytics.vendor.io", n=2)
    see(store, "marketing-service", "aadhaar")
    rows = build.record_rows(build.build(store, ORG, config()))
    kinds = {r["record_type"] for r in rows}
    assert {"declared field", "observed, not declared"} <= kinds and any(k.startswith("destination") for k in kinds)
    phone = next(r for r in rows if r["system"] == "order-service" and r["field_or_destination"] == "phone"
                 and r["record_type"] == "declared field")
    assert phone["observed"] == "yes" and phone["observed_events"] == 2 and phone["retention_days"] == 365
    kyc = next(r for r in rows if r["system"] == "kyc-service")
    assert kyc["observed"] == "no"


def test_csv_has_a_title_a_header_and_cannot_run_a_formula(store):
    see(store, "=cmd|' /C calc'!A0", "phone")
    text = build.record_csv(build.build(store, ORG, config()))
    assert text.startswith("# Record of observed processing")
    body = [l for l in text.splitlines() if not l.startswith("#")]
    rows = list(csv.reader(io.StringIO("\n".join(body))))
    assert rows[0] == build.COLUMNS
    assert not any(cell.startswith(("=", "+", "@")) for row in rows for cell in row)


def test_no_personal_value_can_be_in_the_map(store):
    store.flows.record(ORG, "s", [("raw_snippet", "phone")], "analytics.vendor.io")
    blob = repr(build.build(store, ORG, config())) + build.record_csv(build.build(store, ORG, config()))
    assert "9876543210" not in blob


# ---- the way an event arrived (phase A of the problem-statement plan) -----------------------------------------

def test_the_data_map_says_how_each_kind_of_data_was_seen(store):
    store.flows.record(ORG, "order-service", [("phone", "phone")], source_kind="api")
    store.flows.record(ORG, "order-service", [("raw_snippet", "phone")], source_kind="log")
    store.flows.record(ORG, "order-service", [("raw_snippet", "phone")], source_kind="nonsense")     # unknown kinds count as logs
    n = next(n for n in build.build(store, ORG, config())["nodes"] if n["id"] == "order-service")
    phone = next(c for c in n["observed"] if c["category"] == "phone")
    assert phone["kinds"] == ["api", "log"] and phone["count"] == 3


def test_an_older_flow_table_is_rebuilt_with_the_kind(tmp_path):
    import sqlite3
    con = sqlite3.connect(tmp_path / "old.db")
    con.row_factory = sqlite3.Row
    con.execute("""CREATE TABLE observed_flows (tenant_id TEXT NOT NULL, source_system TEXT NOT NULL, field TEXT NOT NULL,
                   category TEXT NOT NULL, destination TEXT NOT NULL DEFAULT '', count INTEGER NOT NULL DEFAULT 0,
                   first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                   PRIMARY KEY (tenant_id, source_system, field, category, destination))""")
    con.execute("INSERT INTO observed_flows VALUES ('o', 's', 'f', 'phone', '', 5, 't1', 't2')")
    con.commit()
    flow_mod.create_tables(con)
    row = con.execute("SELECT source_kind, count FROM observed_flows").fetchone()
    assert (row["source_kind"], row["count"]) == ("log", 5)
    flow_mod.create_tables(con)                                           # idempotent
    assert con.execute("SELECT COUNT(*) AS n FROM observed_flows").fetchone()["n"] == 1
