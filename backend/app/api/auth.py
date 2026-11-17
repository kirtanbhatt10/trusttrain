"""Authentication and user management."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.api.deps import DB, Admin, AppSettings, Viewer
from app.core.security import create_access_token, hash_password, verify_password
from app.models import User
from app.schemas.schemas import LoginRequest, TokenResponse, UserCreate, UserOut
from app.services import audit

router = APIRouter(prefix="/api/auth", tags=["auth"])
users_router = APIRouter(prefix="/api/users", tags=["users"])

# Constant-time-ish failure path: hash against a dummy when the user is unknown.
_DUMMY_HASH = hash_password("dummy-password-for-timing")


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: DB, settings: AppSettings, request: Request) -> TokenResponse:
    user = db.scalars(select(User).where(User.email == body.email.lower())).first()
    valid = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not valid or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    token = create_access_token(user.id, user.role, request.app.state.jwt_secret, settings.jwt_ttl_minutes)
    return TokenResponse(access_token=token, expires_in=settings.jwt_ttl_minutes * 60, role=user.role)


@router.get("/me", response_model=UserOut)
def me(user: Viewer) -> User:
    return user


@users_router.get("", response_model=list[UserOut])
def list_users(db: DB, _: Admin) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at)).all())


@users_router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, db: DB, admin: Admin) -> User:
    email = body.email.lower()
    if db.scalars(select(User).where(User.email == email)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "User already exists")
    user = User(email=email, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.flush()
    audit.record(db, admin.email, "user.created", "user", user.id, f"Created {email} ({body.role})")
    db.commit()
    return user
