"""Password hashing (scrypt) and signed access tokens (JWT, HS256)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

import jwt

ROLES = ("viewer", "analyst", "admin")
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, actual)


def role_at_least(role: str, required: str) -> bool:
    return role in ROLES and ROLES.index(role) >= ROLES.index(required)


def create_access_token(subject: str, role: str, secret: str, ttl_minutes: int) -> str:
    now = datetime.now(UTC)
    payload = {"sub": subject, "role": role, "iat": now, "exp": now + timedelta(minutes=ttl_minutes)}
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_access_token(token: str, secret: str) -> dict[str, str]:
    """Decode and validate a token. Raises ``jwt.InvalidTokenError`` on failure."""
    data = jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["sub", "exp", "role"]})
    return {"sub": str(data["sub"]), "role": str(data["role"])}
