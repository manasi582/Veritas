"""The settings file: simple, forgiving, and never stronger than the service definition."""
import os

import settings_file as sf


def test_parse_handles_comments_quotes_export_and_trailing_comments():
    text = """
# a comment
VERITAS_TLS=auto
export VERITAS_PORT=9000
VERITAS_ALERT_WEBHOOK_URL="https://hooks.example/x#frag"
VERITAS_SMTP_PASSWORD='p w'
VERITAS_BACKUP_KEEP=14   # two weeks
not a setting
OTHER_THING=ignored
ANTHROPIC_API_KEY=sk-ant-x
"""
    got = sf.parse(text)
    assert got == {"VERITAS_TLS": "auto", "VERITAS_PORT": "9000",
                   "VERITAS_ALERT_WEBHOOK_URL": "https://hooks.example/x#frag",
                   "VERITAS_SMTP_PASSWORD": "p w", "VERITAS_BACKUP_KEEP": "14", "ANTHROPIC_API_KEY": "sk-ant-x"}


def test_the_file_fills_in_but_never_overrides(tmp_path, monkeypatch):
    f = tmp_path / "config.env"
    f.write_text("VERITAS_BACKUP_KEEP=14\nVERITAS_PORT=9000\n")
    monkeypatch.delenv("VERITAS_BACKUP_KEEP", raising=False)
    monkeypatch.setenv("VERITAS_PORT", "8000")                    # from the service definition
    loaded = sf.load_into_environment(f)
    assert loaded == ["VERITAS_BACKUP_KEEP"]
    assert os.environ["VERITAS_BACKUP_KEEP"] == "14" and os.environ["VERITAS_PORT"] == "8000"
    monkeypatch.delenv("VERITAS_BACKUP_KEEP", raising=False)


def test_a_missing_or_unreadable_file_is_not_an_error(tmp_path):
    assert sf.load_into_environment(tmp_path / "nope.env") == []
    assert sf.load_into_environment(tmp_path) == []               # a folder, not a file


def test_the_path_can_be_chosen_by_environment(tmp_path, monkeypatch):
    f = tmp_path / "elsewhere.env"
    f.write_text("VERITAS_LOG_KEEP=9\n")
    monkeypatch.delenv("VERITAS_LOG_KEEP", raising=False)
    monkeypatch.setenv("VERITAS_CONFIG_FILE", str(f))
    assert sf.load_into_environment() == ["VERITAS_LOG_KEEP"]
    monkeypatch.delenv("VERITAS_LOG_KEEP", raising=False)


def test_unrelated_names_are_not_taken_from_the_file(tmp_path, monkeypatch):
    f = tmp_path / "c.env"
    f.write_text("PATH=/evil\nLD_PRELOAD=/evil.so\nVERITAS_X=1\n")
    monkeypatch.delenv("VERITAS_X", raising=False)
    sf.load_into_environment(f)
    assert os.environ.get("PATH") != "/evil" and "LD_PRELOAD" not in os.environ
    monkeypatch.delenv("VERITAS_X", raising=False)
