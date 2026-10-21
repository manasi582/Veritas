"""The breach pack: facts from the chain, blank sections for people, no personal value, roles, audit log."""
import io
import json
import zipfile

from api.test_anchors_api import ORG, client, isolated  # noqa: F401
from api.test_incidents_api import one_incident, seed
from evidence_store.store import get_store
from rulebook import trace
from user_store.models import UserRole


def pack(c, iid):
    r = c.get(f"/v1/{ORG}/incidents/{iid}/breach-pack")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    return zipfile.ZipFile(io.BytesIO(r.content))


def test_pack_has_the_report_json_and_timeline_with_the_chain_events():
    seed(4)
    iid = one_incident()
    admin = client(UserRole.COMPLIANCE_ADMIN, "adm")
    admin.post(f"/v1/{ORG}/incidents/{iid}/status", json={"status": "ACKNOWLEDGED", "reason": "looking"})
    admin.post(f"/v1/{ORG}/incidents/{iid}/status", json={"status": "RESOLVED", "reason": "fixed"})
    z = pack(admin, iid)
    assert set(z.namelist()) == {"REPORT.md", "report.json", "timeline.csv"}
    rep = json.loads(z.read("report.json"))
    assert rep["incident"]["findings"] == 4 and rep["incident"]["status"] == "RESOLVED"
    assert [e["to"] for e in rep["timeline"]] == ["ACKNOWLEDGED", "RESOLVED"]
    assert rep["durations"]["to_acknowledge"] and rep["durations"]["to_resolve"]
    assert rep["chain"]["head_hash"] == get_store().chain_head(ORG)["head_hash"]
    assert z.read("timeline.csv").decode().count("\n") == 3


def test_report_leaves_human_sections_blank_and_says_it_is_not_legal_advice():
    seed(2)
    iid = one_incident()
    text = pack(client(UserRole.AUDITOR, "aud"), iid).read("REPORT.md").decode()
    assert "Not a filing and not legal advice" in text and "TO COMPLETE BY THE DPO" in text
    assert "not** a count of people" in text and "Number of Data Principals affected" in text


def test_report_carries_no_raw_values_from_the_findings():
    seed(2, line="payment failed for 9876543210 mail asha@example.com")
    iid = one_incident()
    z = pack(client(UserRole.AUDITOR, "aud"), iid)
    for name in z.namelist():
        body = z.read(name).decode()
        assert "9876543210" not in body and "asha@example.com" not in body


def test_roles_unknown_incident_and_audit_log():
    seed(1)
    iid = one_incident()
    assert client(UserRole.VIEWER, "v").get(f"/v1/{ORG}/incidents/{iid}/breach-pack").status_code == 403
    c = client(UserRole.AUDITOR, "aud")
    assert c.get(f"/v1/{ORG}/incidents/nope/breach-pack").status_code == 404
    assert c.get(f"/v1/{ORG}/incidents/{iid}/breach-pack").status_code == 200
    from audit_log.store import get_audit_store
    assert any("BREACH_PACK_DOWNLOADED" in str(e) for e in get_audit_store().query(limit=50))


def test_the_report_names_the_kind_of_data_from_the_findings_traces_and_labels_read_properly():
    seed(3)
    iid = one_incident()
    for v in get_store().incident_verdicts(ORG, iid):
        t = trace.build(_verdict_of(v), None, "aadhaar", "HIGH")
        trace.write(get_store(), ORG, v["verdict_id"], 1, t)
    z = pack(client(UserRole.AUDITOR, "aud"), iid)
    text = z.read("REPORT.md").decode()
    assert "Kinds of personal data involved: aadhaar (3 findings)" in text
    assert "Contact of the DPO" in text and "Number of Data Principals affected" in text and "dpo" not in text.replace("DPO", "")
    assert json.loads(z.read("report.json"))["data_kinds"] == {"aadhaar": 3}


def _verdict_of(row):
    import uuid
    from datetime import datetime, timezone
    from schemas.models import RemediationStatus, RuleId, Severity, SourceType, Verdict
    return Verdict(tenant_id=ORG, verdict_id=row["verdict_id"], event_id=str(uuid.uuid4()), rule_id=RuleId.EXPOSURE_001, severity=Severity.HIGH,
                   source=SourceType.LOG, source_system=row["source_system"], field=row["field"], timestamp=datetime.now(timezone.utc),
                   matched_registry_entry=None, breach_notification_candidate=True, remediation_status=RemediationStatus.OPEN,
                   remediation_updated_at=None)
