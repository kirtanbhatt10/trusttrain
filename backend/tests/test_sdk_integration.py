"""The real Python SDK and CLI against the real API (in-process).

Skipped automatically if the SDK package is not installed (``pip install ./sdk``).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.evaluation.synthetic import generate_attack_lab
from tests.conftest import PASSWORD

trusttrain = pytest.importorskip("trusttrain")


def test_sdk_end_to_end(client: TestClient, tmp_path: Path) -> None:
    lab = generate_attack_lab()
    data_dir = tmp_path / "training-data"
    data_dir.mkdir()
    lab.sentiment_poisoned.to_csv(data_dir / "reviews.csv", index=False)
    lab.instruct_poisoned.to_json(data_dir / "instruct.jsonl", orient="records", lines=True)

    security = trusttrain.TrustTrain(api_url="http://testserver", http_client=client, email="analyst@example.com", password=PASSWORD)
    report = security.inspect_dataset(data_dir)
    assert len(report.reports) == 2
    assert report.risk_level in ("high", "critical")
    methods = {f.method for f in report.findings}
    assert {"trigger_token_association", "semantic_inconsistency", "suspicious_instruction_pattern"} <= methods

    # Offline manifest produced by the SDK agrees with the server's manifest.
    reviews = next(r for r in report.reports if r.dataset_name == "reviews")
    local = trusttrain.fingerprint(data_dir / "reviews.csv")
    server = client.get(
        f"/api/datasets/{reviews.dataset_id}/manifest",
        headers={"Authorization": f"Bearer {security._token}"},
        params={"include_row_hashes": True},
    ).json()
    assert local["file"]["sha256"] == server["file"]["sha256"]
    assert local["rows"]["merkle_root"] == server["rows"]["merkle_root"]
    assert local["chunks"]["hashes"] == server["chunks"]["hashes"]

    run = security.record_training_run("sdk-run", [reviews.dataset_id])
    model = security.register_model("sdk-model", training_run_id=run["id"])
    assert security.lineage(reviews.dataset_id)["affected"]["models"][0]["id"] == model["id"]
    incident = security.create_incident("SDK incident", dataset_ids=[reviews.dataset_id], severity="high")
    markdown = security.incident_report(incident["id"], format="markdown")
    assert isinstance(markdown, str) and "SDK incident" in markdown
    assert security.compare_dataset(reviews.dataset_id, data_dir / "reviews.csv")["status"] == "verified"


def test_viewer_sdk_cannot_upload(client: TestClient, tmp_path: Path) -> None:
    (tmp_path / "x.csv").write_text("text\nhello\n")
    viewer = trusttrain.TrustTrain(api_url="http://testserver", http_client=client, email="viewer@example.com", password=PASSWORD)
    with pytest.raises(trusttrain.AuthenticationError) as exc:
        viewer.upload_dataset(tmp_path / "x.csv")
    assert exc.value.status_code == 403


def test_cli_against_api(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from trusttrain import cli

    monkeypatch.chdir(tmp_path)
    lab = generate_attack_lab()
    lab.sentiment_poisoned.to_csv("poisoned.csv", index=False)
    monkeypatch.setattr(
        cli,
        "_client",
        lambda config: trusttrain.TrustTrain(api_url="http://testserver", http_client=client, email="analyst@example.com", password=PASSWORD),
    )
    # TestClient must stay open across commands; the CLI closes clients it creates, so reopen per call.
    monkeypatch.setattr(trusttrain.TrustTrain, "close", lambda self: None)
    buf = io.StringIO()
    assert cli.main(["inspect", "poisoned.csv", "--json"], stdout=buf) == 0
    result = json.loads(buf.getvalue())[0]
    assert result["risk_level"] in ("high", "critical")
    buf = io.StringIO()
    assert cli.main(["lineage", "--dataset", result["dataset_id"]], stdout=buf) == 0
    assert "0 recorded artifact(s)" in buf.getvalue()
