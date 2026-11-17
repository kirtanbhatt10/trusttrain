"""FastAPI application factory."""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app import __version__
from app.api import auth, dashboard, datasets, evaluations, incidents, inspections, lineage, training
from app.config import Settings, get_settings
from app.core.ratelimit import RateLimitMiddleware
from app.core.security import hash_password
from app.database import Base, get_engine, init_engine, new_session
from app.models import User
from app.provenance.signing import ManifestSigner

logger = logging.getLogger("trusttrain")


def _bootstrap_admin(settings: Settings) -> None:
    if not (settings.bootstrap_admin_email and settings.bootstrap_admin_password):
        return
    with new_session() as db:
        email = settings.bootstrap_admin_email.lower()
        if db.scalars(select(User).where(User.email == email)).first() is None:
            db.add(User(email=email, password_hash=hash_password(settings.bootstrap_admin_password), role="admin"))
            db.commit()
            logger.info("Bootstrap admin account created for %s", email)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.validate_for_runtime()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        init_engine(settings.database_url)
        if settings.environment != "production":
            # Development/test convenience; production schemas are managed by Alembic.
            Base.metadata.create_all(get_engine())
        key_path = settings.signing_key_path or settings.data_dir / "signing-key.pem"
        app.state.signer = ManifestSigner.load_or_create(key_path, allow_create=settings.environment != "production")
        if settings.jwt_secret:
            app.state.jwt_secret = settings.jwt_secret
        else:
            app.state.jwt_secret = secrets.token_urlsafe(48)
            logger.warning("TRUSTTRAIN_JWT_SECRET not set: using an ephemeral secret (tokens expire on restart)")
        _bootstrap_admin(settings)
        yield

    app = FastAPI(
        title="TrustTrain API",
        version=__version__,
        description="AI training supply chain security: dataset integrity, poisoning detection, provenance and lineage.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.add_middleware(RateLimitMiddleware, general_limit=settings.rate_limit_per_minute, auth_limit=settings.auth_rate_limit_per_minute)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error", exc_info=exc)
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    @app.get("/api/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    for module in (auth, datasets, inspections, training, evaluations, lineage, incidents, dashboard):
        app.include_router(module.router)
    app.include_router(auth.users_router)
    return app


app = create_app()
