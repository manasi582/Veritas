"""Schema Watch through the API (phase B): a database statement becomes a finding, an incident and a map entry."""
import json

import pytest

from api.test_agents import _register_agent, client as admin_client, isolated_stores  # noqa: F401
from api.test_agent_redaction import post
from evidence_store.store import get_store
from user_store.models import UserRole

ORG = "retail_co"


class MustNotDetect:
    """Schema statements hold structure, not values: the language model must not be used for them."""
    async def detect(self, event, validators):
        raise AssertionError("detection was called for a schema statement")


@pytest.fixture
def token(monkeypatch):
    from api import integration
    monkeypatch.setattr(integration, "get_pool", lambda: MustNotDetect())
    return _register_agent(ORG)[1]


def viewer(name="viewer"):
    from fastapi.testclient import TestClient
    from dashboard.server import app
    from passlib.context import CryptContext
    from user_store.store import get_user_store
    h = CryptContext(schemes=["bcrypt"], deprecated="auto").hash("Passw0rd!x-" + name)
    u = get_user_store().create_user(name, f"{name}@t.io", h, UserRole.VIEWER)
    get_user_store().grant_org_access(u.user_id, ORG)
    c = TestClient(app, raise_server_exceptions=False)
    assert c.post("/api/auth/login", data={"username": name, "password": "Passw0rd!x-" + name}).status_code == 200
    return c


def ddl(token, text, system="support-ticketing"):
    from fastapi.testclient import TestClient
    from dashboard.server import app
    return TestClient(app, raise_server_exceptions=False).post(
        f"/v1/{ORG}/events", headers={"Authorization": f"Bearer {token}"},
        json={"source_type": "log", "source_system": system, "raw_snippet": text, "source_kind": "schema"})


def test_an_undeclared_column_becomes_a_finding_an_incident_and_a_map_entry(token):
    r = ddl(token, "2026-10-20 10:00:00 LOG:  statement: ALTER TABLE customers ADD COLUMN aadhaar_no varchar(12);")
    assert r.status_code == 200
    v = r.json()["verdicts"]
    assert len(v) == 1 and v[0]["rule_id"] == "PURPOSE_001" and v[0]["field"] == "customers.aadhaar_no"
    assert "database change" in v[0]["explanation"] and "not the data" in v[0]["explanation"]
    assert get_store().incident_summary(ORG)["incidents"] == 1
    from evidence_store import flows
    assert [(x["field"], x["category"], x["source_kind"]) for x in flows.rows(get_store(), ORG)] == [("customers.aadhaar_no", "aadhaar", "schema")]
    assert get_store().verify_chain(ORG)["valid"] is True


def test_the_same_change_twice_is_one_incident(token):
    for _ in range(3):
        ddl(token, "ALTER TABLE customers ADD COLUMN aadhaar_no varchar(12)")
    rows, total = get_store().list_incidents(ORG)
    assert total == 1 and rows[0]["count"] == 3


def test_statements_that_carry_values_are_ignored_and_never_stored(token):
    r = ddl(token, "INSERT INTO customers (aadhaar_no) VALUES ('2345 6789 0124')")
    assert r.status_code == 200 and r.json()["verdicts"] == []
    assert "2345" not in json.dumps(admin_client.get(f"/v1/{ORG}/schema").json())


def test_the_listing_is_readable_by_any_role_and_tells_what_it_is(token):
    ddl(token, "ALTER TABLE customers ADD COLUMN aadhaar_no varchar(12)")
    ddl(token, "ALTER TABLE customers ADD COLUMN phone text")
    body = viewer("viewer").get(f"/v1/{ORG}/schema").json()
    assert {(c["column_name"], c["status"]) for c in body["changes"]} >= {("aadhaar_no", "undeclared")}
    assert "structure" in body["note"] and body["systems"][0]["statements"] == 2


def test_other_organizations_see_nothing(token):
    ddl(token, "ALTER TABLE customers ADD COLUMN aadhaar_no varchar(12)")
    assert viewer("viewer2").get("/v1/some_other_org/schema").status_code in (403, 404)


def test_a_normal_event_still_uses_detection(monkeypatch):
    from api import integration
    used = []

    class Counting:
        async def detect(self, event, validators):
            from detection.models import DetectedEvent
            used.append(1)
            return DetectedEvent(event=event, contains_pii=False, matched_entities=[])
    monkeypatch.setattr(integration, "get_pool", lambda: Counting())
    t = _register_agent(ORG)[1]
    post(t, "a plain line")
    assert used == [1]
