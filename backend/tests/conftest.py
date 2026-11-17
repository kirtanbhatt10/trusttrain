from __future__ import annotations

import io
import os
from collections.abc import Iterator
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.core.security import hash_password
from app.database import new_session
from app.main import create_app
from app.models import User

PASSWORD = "correct-horse-battery"


# Set TRUSTTRAIN_TEST_DATABASE_URL (e.g. postgresql+psycopg://user:pw@localhost/trusttrain_test)
# to run the suite against PostgreSQL. Every table is dropped before each test.
TEST_DATABASE_URL = os.environ.get("TRUSTTRAIN_TEST_DATABASE_URL")


def _database_url(tmp_path: Path) -> str:
    if not TEST_DATABASE_URL:
        return f"sqlite:///{tmp_path / 'test.db'}"
    from sqlalchemy import create_engine

    from app.database import Base

    engine = create_engine(TEST_DATABASE_URL)
    Base.metadata.drop_all(engine)
    engine.dispose()
    return TEST_DATABASE_URL


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        database_url=_database_url(tmp_path),
        data_dir=tmp_path / "data",
        jwt_secret="x" * 48,
        rate_limit_per_minute=10_000,
        auth_rate_limit_per_minute=10_000,
        max_upload_bytes=5 * 1024 * 1024,
    )


@pytest.fixture()
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    with TestClient(app) as c:
        with new_session() as db:
            for role in ("admin", "analyst", "viewer"):
                db.add(User(email=f"{role}@example.com", password_hash=hash_password(PASSWORD), role=role))
            db.commit()
        yield c


def token_for(client: TestClient, role: str) -> dict[str, str]:
    resp = client.post("/api/auth/login", json={"email": f"{role}@example.com", "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture()
def admin(client: TestClient) -> dict[str, str]:
    return token_for(client, "admin")


@pytest.fixture()
def analyst(client: TestClient) -> dict[str, str]:
    return token_for(client, "analyst")


@pytest.fixture()
def viewer(client: TestClient) -> dict[str, str]:
    return token_for(client, "viewer")


def csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode()


def upload(client: TestClient, headers: dict[str, str], name: str, content: bytes, **form: str) -> dict:
    resp = client.post("/api/datasets", headers=headers, files={"file": (name, io.BytesIO(content))}, data={"name": name, **form})
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.fixture()
def small_reviews() -> pd.DataFrame:
    from app.evaluation.synthetic import generate_sentiment_clean

    return generate_sentiment_clean(n=200, seed=3)
