"""FastAPI dependencies: settings, signer, authentication and role checks.

Authentication uses bearer tokens in the ``Authorization`` header (never
cookies), so the API is not exposed to CSRF.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, TypeVar

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.security import decode_access_token, role_at_least
from app.database import get_db
from app.models import User
from app.provenance.signing import ManifestSigner

_bearer = HTTPBearer(auto_error=False)
T = TypeVar("T")

DB = Annotated[Session, Depends(get_db)]


def get_app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_signer(request: Request) -> ManifestSigner:
    signer: ManifestSigner = request.app.state.signer
    return signer


AppSettings = Annotated[Settings, Depends(get_app_settings)]
Signer = Annotated[ManifestSigner, Depends(get_signer)]


def current_user(
    db: DB,
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    if creds is None or creds.scheme.lower() != "bearer":
        raise unauthorized
    try:
        claims = decode_access_token(creds.credentials, request.app.state.jwt_secret)
    except jwt.InvalidTokenError:
        raise unauthorized from None
    user = db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require(role: str) -> Callable[[User], User]:
    def checker(user: Annotated[User, Depends(current_user)]) -> User:
        if not role_at_least(user.role, role):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires {role} role")
        return user

    return checker


Viewer = Annotated[User, Depends(require("viewer"))]
Analyst = Annotated[User, Depends(require("analyst"))]
Admin = Annotated[User, Depends(require("admin"))]


def get_or_404(db: Session, model: type[T], ident: str, label: str) -> T:
    obj = db.get(model, ident)
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{label} not found")
    return obj
