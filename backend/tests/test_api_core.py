"""API health, authentication, authorization, uploads and HTTP hardening."""

from __future__ import annotations

import io

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import PASSWORD, csv_bytes, upload


def test_health(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"


def test_login_success_and_me(client: TestClient, admin: dict[str, str]) -> None:
    resp = client.get("/api/auth/me", headers=admin)
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


@pytest.mark.parametrize("password", ["wrong-password-123", ""])
def test_login_failure(client: TestClient, password: str) -> None:
    resp = client.post("/api/auth/login", json={"email": "admin@example.com", "password": password})
    assert resp.status_code in (401, 422)


def test_unknown_user_login_rejected(client: TestClient) -> None:
    resp = client.post("/api/auth/login", json={"email": "nobody@example.com", "password": PASSWORD})
    assert resp.status_code == 401


def test_requires_authentication(client: TestClient) -> None:
    assert client.get("/api/datasets").status_code == 401
    assert client.get("/api/datasets", headers={"Authorization": "Bearer not-a-token"}).status_code == 401


def test_forged_token_rejected(client: TestClient) -> None:
    import jwt

    forged = jwt.encode({"sub": "x", "role": "admin", "exp": 9999999999}, "w" * 40, algorithm="HS256")
    assert client.get("/api/datasets", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_viewer_cannot_upload(client: TestClient, viewer: dict[str, str], small_reviews: pd.DataFrame) -> None:
    resp = client.post("/api/datasets", headers=viewer, files={"file": ("a.csv", io.BytesIO(csv_bytes(small_reviews)))})
    assert resp.status_code == 403


def test_only_admin_manages_users(client: TestClient, admin: dict[str, str], analyst: dict[str, str]) -> None:
    body = {"email": "new@example.com", "password": "another-long-password", "role": "viewer"}
    assert client.post("/api/users", headers=analyst, json=body).status_code == 403
    resp = client.post("/api/users", headers=admin, json=body)
    assert resp.status_code == 201
    assert "password" not in resp.text
    assert client.post("/api/users", headers=admin, json=body).status_code == 409
    weak = {**body, "email": "weak@example.com", "password": "short"}
    assert client.post("/api/users", headers=admin, json=weak).status_code == 422


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("evil.exe", b"MZ\x90\x00"),
        ("data.pkl", b"\x80\x04K\x01."),
        ("archive.csv", b"PK\x03\x04rest-of-zip"),
        ("broken.json", b"{not json"),
        ("list.jsonl", b"[1, 2, 3]\n"),
        ("fake.parquet", b"not parquet at all"),
        ("empty.csv", b""),
        ("binary.txt", b"abc\x00def"),
    ],
)
def test_invalid_files_rejected(client: TestClient, analyst: dict[str, str], name: str, content: bytes) -> None:
    resp = client.post("/api/datasets", headers=analyst, files={"file": (name, io.BytesIO(content))})
    assert resp.status_code == 422, resp.text


def test_oversized_upload_rejected(tmp_path, analyst_factory=None) -> None:  # type: ignore[no-untyped-def]
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        data_dir=tmp_path / "d",
        jwt_secret="y" * 40,
        max_upload_bytes=1000,
        bootstrap_admin_email="root@example.com",
        bootstrap_admin_password=PASSWORD,
    )
    with TestClient(create_app(settings)) as c:
        token = c.post("/api/auth/login", json={"email": "root@example.com", "password": PASSWORD}).json()["access_token"]
        resp = c.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("big.csv", io.BytesIO(b"a,b\n" + b"1,2\n" * 1000))},
        )
        assert resp.status_code == 413
        assert not list((tmp_path / "d" / "uploads").glob("*.part"))


def test_path_traversal_filename_is_neutralised(client: TestClient, analyst: dict[str, str], small_reviews: pd.DataFrame, settings: Settings) -> None:
    ds = upload(client, analyst, "../../../etc/passwd.csv", csv_bytes(small_reviews))
    assert ds["original_filename"] == "passwd.csv"
    stored = list(settings.uploads_dir.iterdir())
    assert all(p.parent == settings.uploads_dir for p in stored)


def test_row_limit_enforced(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        data_dir=tmp_path / "d",
        jwt_secret="y" * 40,
        max_rows=10,
        bootstrap_admin_email="root@example.com",
        bootstrap_admin_password=PASSWORD,
    )
    with TestClient(create_app(settings)) as c:
        token = c.post("/api/auth/login", json={"email": "root@example.com", "password": PASSWORD}).json()["access_token"]
        resp = c.post("/api/datasets", headers={"Authorization": f"Bearer {token}"}, files={"file": ("rows.csv", io.BytesIO(b"a\n" + b"1\n" * 50))})
        assert resp.status_code == 422
        assert "row" in resp.json()["detail"]


def test_rate_limit(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        data_dir=tmp_path / "d",
        jwt_secret="y" * 40,
        auth_rate_limit_per_minute=3,
    )
    with TestClient(create_app(settings)) as c:
        codes = [c.post("/api/auth/login", json={"email": "a@example.com", "password": "x"}).status_code for _ in range(5)]
        assert codes[-1] == 429


def test_cors_only_allows_configured_origin(client: TestClient) -> None:
    ok = client.options("/api/health", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.options("/api/health", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in bad.headers


def test_production_requires_secure_config(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(RuntimeError):
        create_app(Settings(environment="production", jwt_secret="short", data_dir=tmp_path))
    with pytest.raises(RuntimeError):
        create_app(Settings(environment="production", jwt_secret="z" * 40, data_dir=tmp_path, signing_key_path=None))


def test_sql_injection_in_filters_is_inert(client: TestClient, viewer: dict[str, str]) -> None:
    resp = client.get("/api/datasets", headers=viewer, params={"risk_level": "' OR 1=1 --"})
    assert resp.status_code == 200
    assert resp.json() == []


def test_not_found(client: TestClient, viewer: dict[str, str]) -> None:
    assert client.get("/api/datasets/does-not-exist", headers=viewer).status_code == 404
    assert client.get("/api/incidents/nope", headers=viewer).status_code == 404


def test_cell_length_limit_enforced_on_upload(client: TestClient, analyst: dict[str, str], settings: Settings) -> None:
    oversized = "x" * (settings.max_text_chars_per_cell + 1)
    body = f"text,label\nfine,a\n{oversized},b\n".encode()
    resp = client.post("/api/datasets", headers=analyst, files={"file": ("long.csv", io.BytesIO(body))})
    assert resp.status_code == 422
    assert "per-cell limit" in resp.json()["detail"]
