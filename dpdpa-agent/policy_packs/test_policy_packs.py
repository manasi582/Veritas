"""Policy packs: each pack is a valid policy, applying adds only what is missing, nothing is invented, roles and review gate hold."""
import copy

import pytest

from api.test_anchors_api import ORG, client, isolated  # noqa: F401
from org_config.validator import validate_org_config
from policy_packs import loader
from user_store.models import UserRole

IDS = ["fintech", "healthtech", "ecommerce"]


@pytest.fixture(autouse=True)
def config_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))


@pytest.mark.parametrize("pid", IDS)
def test_every_pack_builds_a_valid_policy_and_explains_each_value(pid):
    pack = loader.get_pack(pid)
    assert pack["status"] == "DRAFT" and pack["reviewed_by"] is None
    plan = loader.merge(pack, None, "acme")
    assert plan["errors"] == [] and len(plan["added"]) == len(pack["fields"])
    assert all(a["basis"].strip() for a in plan["added"])
    assert all("basis" not in f for f in plan["policy"]["fields"])
    assert validate_org_config(plan["policy"]) == []
    assert plan["policy"].get("notices") is None            # a pack never invents a published notice


def test_second_apply_adds_nothing_and_existing_fields_are_untouched():
    pack = loader.get_pack("fintech")
    first = loader.merge(pack, None, "acme")
    mine = copy.deepcopy(first["policy"])
    mine["fields"][0]["retention_days"] = 77                 # the organization's own choice
    again = loader.merge(pack, mine, "acme")
    assert again["added"] == [] and len(again["skipped"]) == len(pack["fields"])
    assert again["policy"]["fields"][0]["retention_days"] == 77


def test_a_system_map_renames_and_limits_the_systems():
    plan = loader.merge(loader.get_pack("fintech"), None, "acme", {"kyc-service": "kyc-prod", "payments-api": "pay"})
    assert {a["system"] for a in plan["added"]} == {"kyc-prod", "pay"}
    assert all(s in ("kyc-prod", "pay") for n in plan["notice_suggestions"] for s in n["systems"])
    with pytest.raises(loader.PackError):
        loader.merge(loader.get_pack("fintech"), None, "acme", {"nope": "x"})
    with pytest.raises(loader.PackError):
        loader.merge(loader.get_pack("fintech"), None, "acme", {"kyc-service": "same", "payments-api": "same"})


def test_linkage_rules_only_for_fields_that_are_present():
    plan = loader.merge(loader.get_pack("fintech"), None, "acme", {"payments-api": "pay"})
    assert plan["policy"].get("linkage_rules") is None       # no name/dob/address or aadhaar/phone among the mapped systems' fields


def test_preview_saves_nothing_apply_needs_the_review_acknowledgement_and_is_audit_logged():
    admin = client(UserRole.COMPLIANCE_ADMIN, "adm")
    pv = admin.post(f"/v1/{ORG}/policy-packs/ecommerce/preview", json={})
    assert pv.status_code == 200 and pv.json()["unreviewed"] and pv.json()["added"]
    assert loader.get_pack("ecommerce") and admin.get(f"/v1/orgs/{ORG}/config").status_code in (404, 400)   # still nothing saved
    assert admin.post(f"/v1/{ORG}/policy-packs/ecommerce/apply", json={}).status_code == 409
    ok = admin.post(f"/v1/{ORG}/policy-packs/ecommerce/apply", json={"acknowledge_unreviewed": True})
    assert ok.status_code == 201 and ok.json()["saved"] is True
    cfg = admin.get(f"/v1/orgs/{ORG}/config")
    assert cfg.status_code == 200 and len(cfg.json()["fields"]) == len(loader.get_pack("ecommerce")["fields"])
    again = admin.post(f"/v1/{ORG}/policy-packs/ecommerce/apply", json={"acknowledge_unreviewed": True})
    assert again.json()["saved"] is False
    from audit_log.store import get_audit_store
    assert any("POLICY_PACK_APPLIED" in str(e) for e in get_audit_store().query(limit=50))


def test_roles_and_unknown_pack():
    for role, name in ((UserRole.VIEWER, "v"), (UserRole.AUDITOR, "a")):
        c = client(role, name)
        assert c.post(f"/v1/{ORG}/policy-packs/fintech/apply", json={"acknowledge_unreviewed": True}).status_code == 403
        assert c.get("/v1/policy-packs").status_code == 200
    assert client(UserRole.AUDITOR, "a2").post(f"/v1/{ORG}/policy-packs/fintech/preview", json={}).status_code == 200
    assert client(UserRole.VIEWER, "v2").post(f"/v1/{ORG}/policy-packs/fintech/preview", json={}).status_code == 403
    assert client(UserRole.COMPLIANCE_ADMIN, "adm").get("/v1/policy-packs/nope").status_code == 404
