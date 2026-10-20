"""Through the real ingest path: what was seen where is counted, without any value. Needs the language model."""
from api.test_integration import client, isolated_store, retail_co_token  # noqa: F401

ORG = "retail_co"


def test_events_are_counted_by_system_kind_of_data_and_destination(retail_co_token):
    for n in range(5):
        r = client.post(f"/v1/{ORG}/events", headers={"Authorization": f"Bearer {retail_co_token}"},
                        json={"source_type": "log", "source_system": "support-ticketing",
                              "raw_snippet": f"ticket {n}: aadhaar 2345 6789 0124 forwarded",
                              "fields": {"destination": "https://analytics.vendor.io/collect?id=7"}})
        assert r.status_code == 200
    m = client.get(f"/v1/{ORG}/flows").json()
    node = next(n for n in m["nodes"] if n["id"] == "support-ticketing")
    aadhaar = next(c for c in node["observed"] if c["category"] == "aadhaar")
    assert aadhaar["count"] == 5
    edge = next(e for e in m["edges"] if e["source"] == "support-ticketing")
    assert edge["target"] == "analytics.vendor.io" and edge["kind"] == "external" and edge["categories"]["aadhaar"] == 5
    blob = repr(m) + client.get(f"/v1/{ORG}/flows/export").text
    assert "2345" not in blob and "6789 0124" not in blob and "collect" not in blob and "id=7" not in blob
