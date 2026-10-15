"""The checked-in code trusts the production license key; the CI test key is only patched in by CI."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCK = re.compile(r"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", re.S)


def _pem(path):
    return (ROOT / path).read_text().strip()


def test_the_server_embeds_the_production_key():
    assert BLOCK.findall((ROOT / "dpdpa-agent/license.py").read_text()) == [_pem("tools/public_key.pem")]


def test_the_launcher_embeds_the_production_key():
    assert BLOCK.findall((ROOT / "veritas-launcher/license.go").read_text()) == [_pem("tools/public_key.pem")]


def test_the_ci_test_key_is_a_different_key():
    assert _pem(".github/ci-license-public-key.pem") != _pem("tools/public_key.pem")
