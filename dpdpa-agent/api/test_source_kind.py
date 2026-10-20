"""An event says how it arrived (log, api, schema, otlp); the data map records it (phase A of the problem-statement plan)."""
import pytest

from api.test_agent_redaction import ORG, no_detection, post  # noqa: F401
from api.test_agents import _register_agent, client, isolated_stores  # noqa: F401
from evidence_store import flows
from evidence_store.store import get_store


@pytest.fixture
def token(no_detection):
    return _register_agent(ORG)[1]


def kinds():
    return sorted({r["source_kind"] for r in flows.rows(get_store(), ORG)})


def test_an_event_that_names_its_kind_is_recorded_under_it(token, monkeypatch):
    from detection.models import DetectedEvent, MatchedEntity
    from api import integration

    class Finds:
        async def detect(self, event, validators):
            m = [MatchedEntity(field="phone", entity_type="IN_PHONE", confidence=0.9, matched_text="9876543210")]
            return DetectedEvent(event=event, contains_pii=True, matched_entities=m)
    monkeypatch.setattr(integration, "get_pool", lambda: Finds())
    assert post(token, "GET /customers/{id} 200", source_kind="api").status_code == 200
    assert post(token, "a plain log line").status_code == 200
    assert kinds() == ["api", "log"]


@pytest.mark.parametrize("bad", ["", "kafka", "API", "log; drop", 5])
def test_an_unknown_kind_is_refused(token, bad):
    assert post(token, "x", source_kind=bad).status_code == 422
