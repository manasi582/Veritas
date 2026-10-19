"""
The key that signs checkpoints: Ed25519, made at first use, kept apart from the license and the database key.

The signature shows WHO produced a checkpoint. The protection against tampering comes from the witness copies,
which the server cannot alter; the signature lets an auditor tell a forged checkpoint from a real one.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_FILENAME = "anchor_ed25519.key"


def key_path() -> Path:
    from runtime_paths import data_root
    return data_root() / "secrets" / _FILENAME


def key_id_of(public_raw: bytes) -> str:
    """A short, stable name for a public key: the first 16 hex digits of SHA-256 of its 32 raw bytes."""
    return hashlib.sha256(public_raw).hexdigest()[:16]


def load_or_create() -> Tuple[Ed25519PrivateKey, bytes, str]:
    """(private key, public key as 32 raw bytes, key id). Creates the key file, owner-only, on first use."""
    path = key_path()
    if path.exists():
        private = serialization.load_pem_private_key(path.read_bytes(), password=None)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        private = Ed25519PrivateKey.generate()
        pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, public_raw, key_id_of(public_raw)


def public_key_file_text(public_raw: bytes) -> str:
    """The public key as a small text file an auditor keeps: `key_id`, then the key in base64."""
    return f"veritas-anchor-key-v1\nkey_id: {key_id_of(public_raw)}\npublic_key: {base64.b64encode(public_raw).decode()}\n"


def verify_signature(public_raw: bytes, message: bytes, signature_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(bytes.fromhex(signature_hex), message)
        return True
    except Exception:
        return False
