"""Ed25519 signing and verification for provenance manifests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def public_key_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


class ManifestSigner:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key
        self.public_key = private_key.public_key()
        self.fingerprint = public_key_fingerprint(self.public_key)

    @classmethod
    def load_or_create(cls, path: Path, allow_create: bool) -> ManifestSigner:
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise RuntimeError("Signing key must be an Ed25519 private key")
            return cls(key)
        if not allow_create:
            raise RuntimeError(f"Signing key not found at {path}")
        key = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return cls(key)

    def sign(self, manifest: dict[str, Any]) -> str:
        return base64.b64encode(self._private.sign(canonical_json(manifest))).decode()


def verify_signature(manifest: dict[str, Any], signature_b64: str, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(base64.b64decode(signature_b64, validate=True), canonical_json(manifest))
    except (InvalidSignature, ValueError):
        return False
    return True


def load_public_key_pem(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Not an Ed25519 public key")
    return key
