"""Phase A of the problem-statement plan: fields named by a path (as API payloads name them) match the declared field."""
import pytest

from field_names import field_leaf
from registry.loader import FieldNotRegisteredError, get_registry_entry


@pytest.mark.parametrize("name,leaf", [
    ("phone", "phone"), ("user.phone", "phone"), ("items[0].mobile", "mobile"), ("/customer/email", "email"),
    ("a.b[2][3].c", "c"), ("data.customer.address.line1", "line1"), ("", ""), ("trailing.", "trailing."),
    ("single[0]", "single"),
])
def test_the_leaf_of_a_field_path(name, leaf):
    assert field_leaf(name) == leaf


def test_a_declared_field_is_found_by_its_path(monkeypatch):
    from org_config.schema import OrgConfig
    cfg = OrgConfig.model_validate({"org_id": "leaf_org", "fields": [
        {"field_name": "phone", "pii_category": "phone", "declared_purpose": "p", "consent_scope": "c",
         "retention_days": 30, "source_system": "svc"}]})
    import registry.loader as loader
    monkeypatch.setattr(loader, "load_org_config", lambda org: cfg)
    assert get_registry_entry("leaf_org", "phone", "svc").field_name == "phone"
    assert get_registry_entry("leaf_org", "user.phone", "svc").field_name == "phone"
    assert get_registry_entry("leaf_org", "items[3].phone", "svc").field_name == "phone"


def test_a_path_does_not_match_a_different_field_or_system(monkeypatch):
    from org_config.schema import OrgConfig
    cfg = OrgConfig.model_validate({"org_id": "leaf_org", "fields": [
        {"field_name": "phone", "pii_category": "phone", "declared_purpose": "p", "consent_scope": "c",
         "retention_days": 30, "source_system": "svc"}]})
    import registry.loader as loader
    monkeypatch.setattr(loader, "load_org_config", lambda org: cfg)
    assert get_registry_entry("leaf_org", "user.phone_backup", "svc", raise_on_missing=False) is None
    assert get_registry_entry("leaf_org", "user.phone", "other-system", raise_on_missing=False) is None
    with pytest.raises(FieldNotRegisteredError):
        get_registry_entry("leaf_org", "user.email", "svc")


def test_an_exact_declaration_wins_over_the_leaf(monkeypatch):
    from org_config.schema import OrgConfig
    cfg = OrgConfig.model_validate({"org_id": "leaf_org", "fields": [
        {"field_name": "phone", "pii_category": "phone", "declared_purpose": "one", "consent_scope": "c", "retention_days": 30, "source_system": "svc"},
        {"field_name": "user.phone", "pii_category": "phone", "declared_purpose": "two", "consent_scope": "c", "retention_days": 30, "source_system": "svc"}]})
    import registry.loader as loader
    monkeypatch.setattr(loader, "load_org_config", lambda org: cfg)
    assert get_registry_entry("leaf_org", "user.phone", "svc").declared_purpose == "two"


def test_a_validator_declared_for_an_identifier_applies_to_its_path():
    import detection.engine as engine
    from validators import is_valid_aadhaar
    validators = {"aadhaar": "aadhaar"}
    good = "2345 6789 0124"
    assert engine._resolve_validation_status("leaf_org", "aadhaar", good, validators) == engine.VALIDATED
    assert engine._resolve_validation_status("leaf_org", "user.kyc.aadhaar", good, validators) == engine.VALIDATED
    assert engine._resolve_validation_status("leaf_org", "user.kyc.aadhaar", "1234 5678 9012", validators) == engine.FAILED_VALIDATION
