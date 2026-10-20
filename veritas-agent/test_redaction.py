"""
Agent-side redaction (phase T5): modes per kind, fail-closed, line-size limit, the masked copy, event schema 2, and
that no raw value is queued, copied or reported when masking is on.
"""
from __future__ import annotations

import os
import queue
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import agent  # noqa: E402
import veritas_recognizers as vr  # noqa: E402

PHONE, AADHAAR, CARD, EMAIL = "9876543210", "2345 6789 0124", "4111 1111 1111 1111", "asha.rao@example.com"
KEY = "k" * 32


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    """Every test starts with redaction off and clean counters, and leaves them so."""
    monkeypatch.setattr(agent, "REDACTOR", agent.Redactor())
    monkeypatch.setattr(agent, "STATS", agent.AgentStats())
    monkeypatch.setattr(agent, "REDACTION_COUNTS", agent.RedactionCounts())
    monkeypatch.setattr(agent, "REDACTION_DROPS", agent.RedactionCounts())


def use(monkeypatch, tee=None, **section):
    r = agent.Redactor(section, tee)
    monkeypatch.setattr(agent, "REDACTOR", r)
    return r


# ---- configuration --------------------------------------------------------------------------------------

def test_a_good_section_has_no_problems():
    assert agent.validate_redaction(None) == []
    assert agent.validate_redaction({"mode": "mask", "categories": {"card": "drop", "email": "monitor"},
                                     "fail_closed": True, "max_line_chars": 4096}) == []


@pytest.mark.parametrize("section,fragment", [
    ("mask", "must be a mapping"),
    ({"mode": "scramble"}, "redaction.mode"),
    ({"categories": {"passport": "mask"}}, "unknown kind"),
    ({"categories": {"phone": "shred"}}, "redaction.categories.phone"),
    ({"mode": "hash"}, "hash_key"),
    ({"mode": "hash", "hash_key": "short"}, "hash_key"),
    ({"mode": "mask", "max_line_chars": 10}, "max_line_chars"),
    ({"mode": "mask", "fail_closed": "yes"}, "fail_closed"),
    ({"mode": "mask", "colour": "red"}, "unknown setting"),
    ({"mode": "monitor", "tee_file": "/tmp/x.log"}, "tee_file"),
])
def test_bad_sections_are_explained(section, fragment):
    problems = agent.validate_redaction(section)
    assert problems and any(fragment in p for p in problems), problems


def test_the_config_file_is_checked_on_load(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("veritas_address: https://veritas.example.org:8000\nredaction:\n  mode: hash\n", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        agent.load_config(cfg)
    assert e.value.code == agent.EXIT_CONFIG
    cfg.write_text("veritas_address: https://veritas.example.org:8000\nredaction:\n  mode: mask\n", encoding="utf-8")
    assert agent.load_config(cfg)["redaction"]["mode"] == "mask"


# ---- the modes ------------------------------------------------------------------------------------------

def test_without_a_section_nothing_changes_and_nothing_is_cut(monkeypatch):
    line = "x" * 200_000 + " " + PHONE
    out, counts = agent.apply_redaction(line)
    assert out == line and counts == {} and not agent.REDACTOR.active


def test_monitor_leaves_the_line_alone(monkeypatch):
    use(monkeypatch, mode="monitor")
    assert agent.apply_redaction(f"call {PHONE}")[0] == f"call {PHONE}"


def test_mask_replaces_each_kind_with_its_placeholder(monkeypatch):
    use(monkeypatch, mode="mask")
    out, counts = agent.apply_redaction(f"p {PHONE} a {AADHAAR} c {CARD} e {EMAIL} name Asha")
    assert out == "p [PHONE_REDACTED] a [AADHAAR_REDACTED] c [CARD_REDACTED] e [EMAIL_REDACTED] name Asha"
    assert counts == {"phone": 1, "aadhaar": 1, "card": 1, "email": 1}
    assert agent.STATS.snapshot()["lines_redacted"] == 1


def test_modes_can_differ_by_kind(monkeypatch):
    use(monkeypatch, mode="mask", categories={"email": "monitor", "phone": "hash"}, hash_key=KEY)
    out, counts = agent.apply_redaction(f"{PHONE} {EMAIL} {AADHAAR}")
    assert EMAIL in out and AADHAAR not in out and "[AADHAAR_REDACTED]" in out and PHONE not in out
    assert out.startswith("[PHONE#") and counts == {"phone": 1, "aadhaar": 1}     # a monitored kind is not counted


def test_hash_gives_the_same_token_however_the_number_is_written(monkeypatch):
    use(monkeypatch, mode="hash", hash_key=KEY)
    tokens = {agent.apply_redaction(f"call {w}")[0] for w in (PHONE, "+91 9876543210", "91-9876543210")}
    assert len(tokens) == 1 and "9876" not in next(iter(tokens))


def test_a_different_key_gives_a_different_token(monkeypatch):
    use(monkeypatch, mode="hash", hash_key=KEY)
    a = agent.apply_redaction(PHONE)[0]
    use(monkeypatch, mode="hash", hash_key="z" * 32)
    assert agent.apply_redaction(PHONE)[0] != a


def test_drop_sends_nothing_and_counts(monkeypatch):
    use(monkeypatch, mode="monitor", categories={"card": "drop"})
    out, counts = agent.apply_redaction(f"charged {CARD}")
    assert out is None and counts == {"card": 1}
    assert agent.STATS.snapshot()["dropped_redaction"] == 1 and agent.REDACTION_DROPS.snapshot() == {"card": 1}
    assert agent.apply_redaction("no card here")[0] == "no card here"


def test_a_dropped_kind_drops_the_whole_line_even_if_others_are_masked(monkeypatch):
    use(monkeypatch, mode="mask", categories={"card": "drop"})
    assert agent.apply_redaction(f"{PHONE} and {CARD}")[0] is None


# ---- fail-closed ----------------------------------------------------------------------------------------

def test_an_error_drops_the_line_when_fail_closed(monkeypatch):
    use(monkeypatch, mode="mask", fail_closed=True)
    monkeypatch.setattr(vr, "scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    out, _ = agent.apply_redaction(f"call {PHONE}")
    assert out is None
    snap = agent.STATS.snapshot()
    assert snap["redaction_errors"] == 1 and snap["dropped_redaction_error"] == 1


def test_an_error_sends_the_line_only_when_fail_closed_is_off(monkeypatch):
    use(monkeypatch, mode="mask", fail_closed=False)
    monkeypatch.setattr(vr, "scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    out, _ = agent.apply_redaction(f"call {PHONE}")
    assert out == f"call {PHONE}" and agent.STATS.snapshot()["redaction_errors"] == 1


def test_fail_closed_is_the_default(monkeypatch):
    assert use(monkeypatch, mode="mask").fail_closed is True


# ---- line size ------------------------------------------------------------------------------------------

def test_a_long_line_is_cut_and_nothing_past_the_cut_is_sent(monkeypatch):
    use(monkeypatch, mode="mask", max_line_chars=2048)
    line = "a " * 3000 + PHONE
    out, _ = agent.apply_redaction(line)
    assert len(out) < 2100 and out.endswith("[TRUNCATED]") and PHONE not in out
    assert agent.STATS.snapshot()["truncated_lines"] == 1


def test_a_value_cut_in_half_by_the_limit_is_not_leaked(monkeypatch):
    use(monkeypatch, mode="mask", max_line_chars=2048)
    line = "a" * 2040 + " " + PHONE                       # the number straddles the cut
    out, _ = agent.apply_redaction(line)
    assert PHONE not in out and "98765" not in out.replace("[PHONE_REDACTED]", "")[2040:]


# ---- queue, schema 2 and delivery -----------------------------------------------------------------------

def test_the_queue_never_holds_a_raw_value(monkeypatch):
    use(monkeypatch, mode="mask")
    q = queue.Queue()
    agent._enqueue(q, f"order paid by {CARD} phone {PHONE}", "svc")
    line, system, meta = q.get_nowait()
    assert CARD not in line and PHONE not in line and system == "svc"
    assert meta == {"schema": 2, "redaction_mode": "mask", "recognizer_pack_version": vr.PACK_VERSION,
                    "agent_detections": {"card": 1, "phone": 1}}


def test_a_dropped_line_is_never_queued(monkeypatch):
    use(monkeypatch, mode="monitor", categories={"aadhaar": "drop"})
    q = queue.Queue()
    agent._enqueue(q, f"uid {AADHAAR}", "svc")
    assert q.empty()


def test_without_redaction_the_queue_item_is_as_before(monkeypatch):
    q = queue.Queue()
    agent._enqueue(q, f"phone {PHONE}", "svc")
    assert q.get_nowait() == (f"phone {PHONE}", "svc")


def test_the_event_carries_schema_2_only_when_redaction_is_on(monkeypatch):
    sent = []

    class R:
        def raise_for_status(self): pass
    monkeypatch.setattr(agent.requests, "post", lambda url, json=None, **k: sent.append(json) or R())
    state = {"auth_token": "t", "event_endpoint": "/v1/o/events"}
    agent.forward_event("https://s:8000", state, "line", "svc")
    agent.forward_event("https://s:8000", state, "[PHONE_REDACTED]", "svc",
                        meta={"schema": 2, "redaction_mode": "mask", "recognizer_pack_version": "1", "agent_detections": {"phone": 1}})
    assert "schema" not in sent[0] and sent[1]["schema"] == 2 and sent[1]["agent_detections"] == {"phone": 1}


def test_deliver_passes_the_extra_fields_to_forward():
    got = []
    agent.deliver(("l", "s", {"schema": 2}), lambda *a: got.append(a), stats=agent.AgentStats())
    agent.deliver(("l", "s"), lambda *a: got.append(a), stats=agent.AgentStats())
    assert got == [("l", "s", {"schema": 2}), ("l", "s")]


# ---- the masked copy ------------------------------------------------------------------------------------

def test_the_masked_copy_holds_what_was_sent_and_not_dropped_lines(monkeypatch, tmp_path):
    tee = agent.MaskedTee(str(tmp_path / "masked.log"))
    use(monkeypatch, tee=tee, mode="mask", categories={"card": "drop"})
    agent.apply_redaction(f"call {PHONE}")
    agent.apply_redaction(f"charged {CARD}")
    agent.apply_redaction("plain line")
    text = (tmp_path / "masked.log").read_text(encoding="utf-8")
    assert text == "call [PHONE_REDACTED]\nplain line\n"
    if os.name != "nt":
        assert oct((tmp_path / "masked.log").stat().st_mode & 0o777) == "0o640"


def test_the_masked_copy_rotates(monkeypatch, tmp_path):
    tee = agent.MaskedTee(str(tmp_path / "m.log"), max_bytes=200)
    use(monkeypatch, tee=tee, mode="mask")
    for i in range(30):
        agent.apply_redaction(f"line {i} {PHONE}")
    assert (tmp_path / "m.log.1").exists() and (tmp_path / "m.log").stat().st_size < 400


def test_a_broken_masked_copy_never_stops_forwarding(monkeypatch, tmp_path):
    class Broken:
        def write(self, line): raise OSError("disk full")
    use(monkeypatch, tee=Broken(), mode="mask")
    out, _ = agent.apply_redaction(f"call {PHONE}")
    assert out == "call [PHONE_REDACTED]" and agent.STATS.snapshot()["tee_errors"] == 1


# ---- the report to the server ---------------------------------------------------------------------------

def test_the_health_report_names_the_mode_and_rules_and_holds_no_line_text(monkeypatch):
    use(monkeypatch, mode="mask", categories={"card": "drop"})
    agent.apply_redaction(f"call {PHONE}")
    agent.apply_redaction(f"charged {CARD}")
    h = agent.build_health(None)["redaction"]
    assert h["mode"] == "mixed" and h["categories"]["card"] == "drop" and h["fail_closed"] is True
    assert h["pack_version"] == vr.PACK_VERSION and h["pack_fingerprint"] == vr.pack_fingerprint()
    assert h["redacted"] == {"phone": 1} and h["dropped"] == {"card": 1}
    assert PHONE not in repr(agent.build_health(None)) and CARD not in repr(agent.build_health(None))


def test_the_health_report_without_redaction_still_names_the_rules():
    h = agent.build_health(None)["redaction"]
    assert h["mode"] == "monitor" and h["pack_fingerprint"] == vr.pack_fingerprint()


def test_the_counters_stay_within_what_the_server_accepts():
    assert len(agent.AgentStats.NAMES) <= 20 and all(len(n) <= 40 for n in agent.AgentStats.NAMES)


# ---- cost -----------------------------------------------------------------------------------------------

def test_masking_keeps_the_agent_light(monkeypatch):
    use(monkeypatch, mode="mask")
    lines = [f"2026-10-20 10:01:02 INFO order {i} shipped to warehouse 4 user=u{i} phone {PHONE}" for i in range(4000)]
    t = time.perf_counter()
    for line in lines:
        agent.apply_redaction(line)
    per_line_ms = (time.perf_counter() - t) / len(lines) * 1000
    assert per_line_ms < 1.5, f"{per_line_ms:.3f} ms per line"


def test_a_spaced_value_split_by_the_limit_is_not_leaked(monkeypatch):
    use(monkeypatch, mode="mask", max_line_chars=2048)
    out, _ = agent.apply_redaction("b" * 2043 + " " + AADHAAR)           # the cut falls inside "2345 6789 0124"
    assert "2345" not in out and "6789" not in out and out.endswith("[TRUNCATED]")
