"""Application configuration loaded from environment variables.

All settings use the ``TRUSTTRAIN_`` prefix. Secure defaults apply; the
development mode only relaxes behaviour that is explicitly documented here.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRUSTTRAIN_", env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./trusttrain-data/trusttrain.db"
    data_dir: Path = Path("./trusttrain-data")

    # Authentication
    jwt_secret: str = Field(default="", description="HMAC secret for access tokens")
    jwt_ttl_minutes: int = 60
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None

    # Provenance signing key (Ed25519, PEM, PKCS8). Generated in development if absent.
    signing_key_path: Path | None = None

    # HTTP hardening
    cors_origins: list[str] = ["http://localhost:5173"]
    rate_limit_per_minute: int = 240
    auth_rate_limit_per_minute: int = 20

    # Resource limits
    max_upload_bytes: int = 50 * 1024 * 1024
    max_rows: int = 200_000
    max_text_chars_per_cell: int = 20_000

    # Detection thresholds (all overridable per inspection)
    zscore_threshold: float = 4.0
    near_duplicate_threshold: float = 0.92
    label_noise_threshold: float = 0.15
    lof_threshold: float = 2.0
    semantic_rank_threshold: float = 0.2
    distribution_pvalue: float = 0.01

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str) and not value.startswith("["):
            return [v.strip() for v in value.split(",") if v.strip()]
        return value

    def validate_for_runtime(self) -> None:
        """Refuse insecure configuration outside development/test."""
        if self.environment == "production":
            if len(self.jwt_secret) < 32:
                raise RuntimeError("TRUSTTRAIN_JWT_SECRET must be at least 32 characters in production")
            if self.signing_key_path is None:
                raise RuntimeError("TRUSTTRAIN_SIGNING_KEY_PATH is required in production")
            if "*" in self.cors_origins:
                raise RuntimeError("Wildcard CORS origins are not allowed in production")

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def manifests_dir(self) -> Path:
        return self.data_dir / "manifests"

    @property
    def models_dir(self) -> Path:
        return self.data_dir / "lab-models"


@lru_cache
def get_settings() -> Settings:
    return Settings()
