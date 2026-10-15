"""The places that accept an agent's or caller's names refuse markup in them."""
import pytest
from pydantic import ValidationError

from api.agents import RegisterAgentRequest
from api.integration import IngestEventRequest, ScanRequest

EVIL = "<img src=x onerror=alert(1)>"


def _ingest(**kw):
    base = dict(source_type="log", source_system="kyc-service", raw_snippet="hello")
    base.update(kw)
    return IngestEventRequest(**base)


def test_ordinary_ingest_is_accepted():
    assert _ingest().source_system == "kyc-service"


def test_ingest_refuses_markup_in_source_system():
    with pytest.raises(ValidationError):
        _ingest(source_system=EVIL)


def test_ingest_refuses_markup_in_a_field_name():
    with pytest.raises(ValidationError):
        _ingest(fields={EVIL: "x"})


def test_scan_refuses_markup_in_source_system_and_field_names():
    with pytest.raises(ValidationError):
        ScanRequest(text="hi", source_system=EVIL)
    with pytest.raises(ValidationError):
        ScanRequest(fields={EVIL: "x"})


def test_agent_registration_refuses_markup_in_the_label():
    with pytest.raises(ValidationError):
        RegisterAgentRequest(registration_key="k", source_label=EVIL)
    assert RegisterAgentRequest(registration_key="k", source_label="marketing-mac-1").source_label == "marketing-mac-1"
