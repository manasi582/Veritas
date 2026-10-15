"""Metrics: off by default, token-protected, and only numbers."""
import re

import metrics


def test_off_unless_a_long_enough_token_is_set(monkeypatch):
    monkeypatch.delenv("VERITAS_METRICS_TOKEN", raising=False)
    assert metrics.token_ok("Bearer anything") is False
    monkeypatch.setenv("VERITAS_METRICS_TOKEN", "short")
    assert metrics.token_ok("Bearer short") is False
    monkeypatch.setenv("VERITAS_METRICS_TOKEN", "a-long-enough-token-1234")
    assert metrics.token_ok("Bearer a-long-enough-token-1234") is True
    assert metrics.token_ok("bearer a-long-enough-token-1234") is True


def test_wrong_or_malformed_credentials_are_refused(monkeypatch):
    monkeypatch.setenv("VERITAS_METRICS_TOKEN", "a-long-enough-token-1234")
    for header in (None, "", "Bearer", "Bearer wrong-wrong-wrong-wrong", "Basic a-long-enough-token-1234",
                   "a-long-enough-token-1234", "Bearer a-long-enough-token-12345"):
        assert metrics.token_ok(header) is False, header


def test_render_is_valid_prometheus_text_with_the_basics(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path))
    (tmp_path / "evidence.db").write_bytes(b"x" * 4096)
    text = metrics.render()
    assert text.endswith("\n")
    assert "veritas_disk_free_percent" in text and 'veritas_database_bytes{database="evidence.db"} 4096' in text
    assert "veritas_scrape_timestamp_seconds" in text
    sample = re.compile(r'^[a-z_]+(\{[^}]*\})? -?[0-9.e+]+$')
    for line in text.strip().splitlines():
        assert line.startswith("# ") or sample.match(line), line


def test_label_values_cannot_break_the_format():
    assert metrics._line("m", 1, org='a"b\nc') == 'm{org="a\\"b c"} 1'
