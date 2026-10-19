"""Through the real ingest path: a flood of near-identical lines becomes a few incidents, nothing personal is kept
in them, and a resolved incident reopens as recurred. Needs the language model (like the other ingest tests)."""
import pytest

from api.test_integration import client, isolated_store, retail_co_token  # noqa: F401
from evidence_store.store import get_store

ORG = "retail_co"
LINES = [
    "agent note {n}: aadhaar {a} read aloud to customer ticket {n}",
    "agent note {n}: aadhaar {a} pasted into the chat, session {n}",
]


def post(token, n, kind=0):
    aadhaar = "2345 6789 0124"          # a checksum-valid test number, never stored
    return client.post(f"/v1/{ORG}/events", headers={"Authorization": f"Bearer {token}"},
                       json={"source_type": "log", "source_system": "support-ticketing",
                             "raw_snippet": LINES[kind].format(n=n, a=aadhaar)})


def test_a_flood_becomes_few_incidents_without_the_personal_value(retail_co_token, monkeypatch):
    monkeypatch.setenv("VERITAS_INCIDENT_GRACE_SECONDS", "0")
    for n in range(40):
        assert post(retail_co_token, 1000 + n, kind=n % 2).status_code == 200
    store = get_store()
    summary = store.incident_summary(ORG)
    assert summary["verdicts"] >= 40 and summary["verdicts_grouped"] == summary["verdicts"]
    assert 1 <= summary["incidents"] <= 8
    rows, _ = store.list_incidents(ORG)
    for r in rows:
        assert "2345" not in r["template"] and "6789" not in r["template"] and "0124" not in r["template"]
        assert "aadhaar" in r["template"].lower() or "PII" in r["template"]
    assert store.verify_chain(ORG)["valid"] is True

    # the HTTP view agrees, and resolving then seeing the line again reopens it as recurred
    body = client.get(f"/v1/{ORG}/incidents").json()
    assert body["total"] == summary["incidents"]
    top = body["incidents"][0]
    assert client.post(f"/v1/{ORG}/incidents/{top['incident_id']}/status", json={"status": "RESOLVED"}).status_code == 200
    post(retail_co_token, 5000, kind=0)
    post(retail_co_token, 5001, kind=1)
    again = client.get(f"/v1/{ORG}/incidents?recurred=true").json()
    assert again["total"] >= 1 and again["incidents"][0]["status"] == "OPEN"
    assert store.verify_chain(ORG)["valid"] is True
