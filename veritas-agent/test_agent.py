"""
Unit tests for the agent's identity handling (no network, no server).

These guard the failure found in the Linux agent package: the identity could not
be saved (read-only working directory), the one-time registration key was spent
anyway, and the agent could never register again.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import agent  # noqa: E402

_posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permissions")


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("VERITAS_STATE_DIR", raising=False)
    monkeypatch.delenv("VERITAS_CA_CERT", raising=False)
    monkeypatch.delenv("VERITAS_TLS_VERIFY", raising=False)
    agent._state_dir_override = None
    yield
    agent._state_dir_override = None


REGISTRATION_REPLY = {
    "agent_id": "VERITAS-AGENT-ABC123",
    "auth_token": "tok_secret",
    "org_id": "acme",
    "event_endpoint": "/v1/acme/events",
}


class _Resp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = payload or {}
        self.text = text
        self.ok = status < 400

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            err = agent.requests.exceptions.HTTPError(f"{self.status_code}")
            err.response = self
            raise err


def _config(tmp_path):
    ca = tmp_path / "server.crt"
    ca.write_text("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
    return {
        "veritas_address": "https://veritas.example:8000",
        "registration_key": "one-time-key",
        "source_label": "host-1",
        "tls": {"ca_cert": str(ca)},
    }


class TestStateDirectory:
    def test_default_is_current_directory(self):
        assert agent.state_file() == Path(".") / agent.STATE_FILE_NAME

    def test_env_var_wins_over_config(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VERITAS_STATE_DIR", str(tmp_path / "from_env"))
        agent.configure_state_dir({"state_dir": str(tmp_path / "from_cfg")})
        assert agent.state_dir() == tmp_path / "from_env"

    def test_config_value_used_when_no_env(self, tmp_path):
        agent.configure_state_dir({"state_dir": str(tmp_path / "from_cfg")})
        assert agent.state_dir() == tmp_path / "from_cfg"

    def test_server_cert_path_is_absolute_inside_state_dir(self, tmp_path):
        agent.configure_state_dir({"state_dir": str(tmp_path)})
        assert agent.server_cert_path().is_absolute()
        assert agent.server_cert_path().parent == tmp_path.resolve()


class TestSaveState:
    @_posix_only
    def test_saved_with_owner_only_permissions_and_roundtrips(self, tmp_path):
        agent.configure_state_dir({"state_dir": str(tmp_path)})
        agent.save_state({"agent_id": "a", "auth_token": "t"})
        path = agent.state_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert agent.load_state() == {"agent_id": "a", "auth_token": "t"}

    def test_no_temp_file_left_behind(self, tmp_path):
        agent.configure_state_dir({"state_dir": str(tmp_path)})
        agent.save_state({"agent_id": "a"})
        assert [p.name for p in tmp_path.iterdir()] == [agent.STATE_FILE_NAME]

    def test_corrupt_state_file_is_ignored(self, tmp_path):
        agent.configure_state_dir({"state_dir": str(tmp_path)})
        (tmp_path / agent.STATE_FILE_NAME).write_text("{not json")
        assert agent.load_state() == {}


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="needs POSIX permissions and a non-root user (root ignores directory permissions)",
)
class TestRegistrationDoesNotBurnTheKey:
    def test_unwritable_state_dir_exits_78_before_contacting_server(self, tmp_path, monkeypatch):
        ro = tmp_path / "ro"
        ro.mkdir()
        ro.chmod(0o555)
        agent.configure_state_dir({"state_dir": str(ro / "state")})
        calls = []
        monkeypatch.setattr(agent.requests, "post", lambda *a, **k: calls.append(1))
        with pytest.raises(SystemExit) as e:
            agent.bootstrap(_config(tmp_path), {})
        assert e.value.code == agent.EXIT_CONFIG
        assert calls == [], "the one-time key must not be sent when the identity cannot be saved"

    def test_save_failure_after_registration_exits_78_with_guidance(self, tmp_path, monkeypatch, caplog):
        agent.configure_state_dir({"state_dir": str(tmp_path / "state")})
        monkeypatch.setattr(agent.requests, "post", lambda *a, **k: _Resp(200, REGISTRATION_REPLY))
        monkeypatch.setattr(agent, "save_state", lambda s: (_ for _ in ()).throw(PermissionError("denied")))
        with pytest.raises(SystemExit) as e:
            agent.bootstrap(_config(tmp_path), {})
        assert e.value.code == agent.EXIT_CONFIG
        assert "Revoke this agent" in caplog.text and "VERITAS-AGENT-ABC123" in caplog.text


class TestBootstrap:
    def test_registers_and_saves_identity(self, tmp_path, monkeypatch):
        agent.configure_state_dir({"state_dir": str(tmp_path / "state")})
        monkeypatch.setattr(agent.requests, "post", lambda *a, **k: _Resp(200, REGISTRATION_REPLY))
        state = agent.bootstrap(_config(tmp_path), {})
        assert state["agent_id"] == "VERITAS-AGENT-ABC123"
        saved = json.loads((tmp_path / "state" / agent.STATE_FILE_NAME).read_text())
        assert saved["auth_token"] == "tok_secret"
        if sys.platform != "win32":
            assert stat.S_IMODE((tmp_path / "state" / agent.STATE_FILE_NAME).stat().st_mode) == 0o600

    def test_existing_identity_is_reused_without_a_key(self, tmp_path, monkeypatch):
        agent.configure_state_dir({"state_dir": str(tmp_path)})
        monkeypatch.setattr(agent.requests, "post", lambda *a, **k: pytest.fail("must not register again"))
        existing = {**REGISTRATION_REPLY}
        cfg = _config(tmp_path)
        cfg.pop("registration_key")
        assert agent.bootstrap(cfg, existing)["agent_id"] == "VERITAS-AGENT-ABC123"

    def test_used_key_exits_78_not_1(self, tmp_path, monkeypatch):
        agent.configure_state_dir({"state_dir": str(tmp_path)})
        monkeypatch.setattr(
            agent.requests, "post",
            lambda *a, **k: _Resp(400, text='{"detail":"Registration key has already been used."}'),
        )
        with pytest.raises(SystemExit) as e:
            agent.bootstrap(_config(tmp_path), {})
        assert e.value.code == agent.EXIT_CONFIG

    def test_no_key_and_no_identity_exits_78(self, tmp_path):
        agent.configure_state_dir({"state_dir": str(tmp_path)})
        cfg = _config(tmp_path)
        cfg.pop("registration_key")
        with pytest.raises(SystemExit) as e:
            agent.bootstrap(cfg, {})
        assert e.value.code == agent.EXIT_CONFIG

    def test_missing_config_file_exits_78(self, tmp_path):
        with pytest.raises(SystemExit) as e:
            agent.load_config(tmp_path / "nope.yaml")
        assert e.value.code == agent.EXIT_CONFIG


class TestConfigPlaceholders:
    """A config copied from instructions with the placeholders left in must stop once, clearly."""

    def write(self, tmp_path, address="https://veritas.example.com:8000", key="abc123", extra=""):
        p = tmp_path / "config.yaml"
        p.write_text(f'veritas_address: "{address}"\nregistration_key: "{key}"\n{extra}'
                     "sources:\n  - type: file\n    path: /tmp/x.log\n    source_system: s\n")
        return p

    @pytest.mark.parametrize("address", [
        "https://<HOST>:8000", "<HOST>", "https://CHANGE_ME:8000", "https://your-server:8000x:y",
        "veritas.example.com:8000", "ftp://host:8000", "https://", "https://host:notaport", "",
    ])
    def test_bad_address_exits_78_with_a_reason(self, tmp_path, caplog, address):
        with pytest.raises(SystemExit) as e:
            agent.load_config(self.write(tmp_path, address=address))
        assert e.value.code == agent.EXIT_CONFIG
        assert caplog.records, "a reason must be logged"

    def test_placeholder_gets_a_specific_message(self, tmp_path, caplog):
        with pytest.raises(SystemExit):
            agent.load_config(self.write(tmp_path, address="https://<HOST>:8000"))
        assert "placeholder" in caplog.text and "<HOST>" in caplog.text

    def test_placeholder_key_exits_78(self, tmp_path, caplog):
        with pytest.raises(SystemExit) as e:
            agent.load_config(self.write(tmp_path, key="<PASTE THE KEY>"))
        assert e.value.code == agent.EXIT_CONFIG and "registration_key" in caplog.text

    @pytest.mark.parametrize("address", [
        "https://localhost:8000", "http://192.168.1.50:8000", "https://veritas.corp.example:8443",
        "https://[::1]:8000", "https://veritas",
    ])
    def test_real_addresses_load(self, tmp_path, address):
        assert agent.load_config(self.write(tmp_path, address=address))["veritas_address"] == address


class TestInsecureWarningNoise:
    def _ignored(self, warnings_module, category):
        return any(f[0] == "ignore" and f[2] is category for f in warnings_module.filters)

    def test_verify_false_warns_once_itself_and_silences_urllib3(self, monkeypatch, caplog):
        import warnings
        import urllib3
        monkeypatch.delenv("VERITAS_TLS_VERIFY", raising=False)
        monkeypatch.delenv("VERITAS_CA_CERT", raising=False)
        category = urllib3.exceptions.InsecureRequestWarning
        with warnings.catch_warnings():
            warnings.resetwarnings()
            assert not self._ignored(warnings, category), "precondition"
            assert agent._tls_verify({"tls": {"verify": False}}) is False
            assert self._ignored(warnings, category), "urllib3's repeated warning must be silenced"
        assert caplog.text.count("TLS verification disabled") == 1

    def test_verification_on_leaves_the_warning_alone(self, monkeypatch):
        import warnings
        import urllib3
        monkeypatch.delenv("VERITAS_TLS_VERIFY", raising=False)
        monkeypatch.delenv("VERITAS_CA_CERT", raising=False)
        with warnings.catch_warnings():
            warnings.resetwarnings()
            agent._tls_verify({"tls": {"verify": True}})
            assert not self._ignored(warnings, urllib3.exceptions.InsecureRequestWarning)


class TestDockerSourceExplainsItself:
    def test_a_mac_is_told_to_use_a_file_source(self, monkeypatch):
        monkeypatch.setattr(agent.sys, "platform", "darwin")
        assert "file source" in agent.docker_unreachable_hint()

    def test_linux_is_told_about_the_docker_group(self, monkeypatch):
        monkeypatch.setattr(agent.sys, "platform", "linux")
        assert "docker group" in agent.docker_unreachable_hint()
