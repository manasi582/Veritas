"""The session cookie is a signed JWT: it must accept our own tokens and nothing forged."""
import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

import jwt

from api import auth_deps as auth
from user_store.models import User, UserRole


def _user(version: int = 0) -> User:
    return User(user_id="u1", username="tester", email="t@example.com", password_hash="x",
                role=UserRole.VIEWER, is_active=True, created_at=datetime.now(timezone.utc),
                token_version=version)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _secret():
    s = auth._jwt_secret()
    return s.encode() if isinstance(s, str) else s


def test_our_own_token_round_trips_with_the_user_details():
    payload = auth.decode_access_token(auth.create_access_token(_user(3)))
    assert payload["sub"] == "u1" and payload["role"] == "VIEWER" and payload["tv"] == 3


def test_a_token_with_a_changed_signature_is_refused():
    token = auth.create_access_token(_user())
    assert auth.decode_access_token(token[:-4] + "AAAA") is None


def test_garbage_is_refused():
    for bad in ("", "x", "a.b.c", "not.a.token"):
        assert auth.decode_access_token(bad) is None


def test_an_unsigned_token_claiming_to_be_an_administrator_is_refused():
    head = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"sub": "u1", "role": "SUPER_ADMIN", "tv": 0, "exp": int(time.time()) + 999}).encode())
    assert auth.decode_access_token(f"{head}.{body}.") is None


def test_a_token_signed_with_another_secret_is_refused():
    forged = jwt.encode({"sub": "u1", "exp": int(time.time()) + 99}, "x" * 40, algorithm="HS256")
    assert auth.decode_access_token(forged) is None


def test_an_expired_token_is_refused():
    old = jwt.encode({"sub": "u1", "exp": int(time.time()) - 5}, _secret(), algorithm="HS256")
    assert auth.decode_access_token(old) is None


def test_a_token_using_a_different_algorithm_is_refused():
    other = jwt.encode({"sub": "u1", "exp": int(time.time()) + 99}, _secret(), algorithm="HS512")
    assert auth.decode_access_token(other) is None


def test_a_plain_hs256_token_made_by_another_library_is_accepted():
    """Sessions created before the library change (python-jose) must keep working after an upgrade."""
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps({"sub": "u1", "username": "tester", "role": "VIEWER", "tv": 0,
                            "iat": int(time.time()), "exp": int(time.time()) + 99}, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_secret(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    assert auth.decode_access_token(f"{head}.{body}.{sig}")["sub"] == "u1"
