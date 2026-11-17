from __future__ import annotations

from pathlib import Path

import httpx
import pandas as pd
import pytest

from tests.fake_api import TOKEN, FakeAPI
from trusttrain import APIError, AuthenticationError, DirectoryReport, InspectionReport, TrustTrain, TrustTrainError


@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    pd.DataFrame({"text": ["a", "b"], "label": [0, 1]}).to_csv(tmp_path / "a.csv", index=False)
    (tmp_path / "nested").mkdir()
    pd.DataFrame({"text": ["c"]}).to_json(tmp_path / "nested" / "b.jsonl", orient="records", lines=True)
    (tmp_path / "notes.md").write_text("ignored")
    return tmp_path


def test_login_with_credentials() -> None:
    api = FakeAPI()
    client = api.client(email="a@example.com", password="right-password")
    assert client.list_datasets() == []


def test_login_failure_raises() -> None:
    with pytest.raises(AuthenticationError) as exc:
        FakeAPI().client(email="a@example.com", password="wrong")
    assert exc.value.status_code == 401


def test_token_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTTRAIN_TOKEN", TOKEN)
    assert FakeAPI().client().health()["status"] == "ok"


def test_unauthenticated_call_raises() -> None:
    with pytest.raises(AuthenticationError):
        FakeAPI().client().list_datasets()


def test_inspect_single_file(data_dir: Path) -> None:
    client = FakeAPI().client(token=TOKEN)
    report = client.inspect_dataset(data_dir / "a.csv")
    assert isinstance(report, InspectionReport)
    assert report.risk_level == "high"
    assert report.findings[0].method == "trigger_token_association"


def test_inspect_directory_aggregates(data_dir: Path) -> None:
    api = FakeAPI()
    report = api.client(token=TOKEN).inspect_dataset(data_dir)
    assert isinstance(report, DirectoryReport)
    assert len(report.reports) == 2
    assert report.risk_level == "high"
    assert any(s.endswith("notes.md") for s in report.skipped)
    assert len(report.findings) == 2


def test_inspect_missing_path() -> None:
    with pytest.raises(TrustTrainError):
        FakeAPI().client(token=TOKEN).inspect_dataset("/no/such/path")


def test_upload_rejects_unsupported(tmp_path: Path) -> None:
    (tmp_path / "m.pkl").write_bytes(b"x")
    with pytest.raises(TrustTrainError):
        FakeAPI().client(token=TOKEN).upload_dataset(tmp_path / "m.pkl")


def test_dataset_methods(data_dir: Path) -> None:
    client = FakeAPI().client(token=TOKEN)
    ds = client.upload_dataset(data_dir / "a.csv", name="x", parent_id="p", operation="filter")
    assert client.get_dataset(ds["id"])["id"] == ds["id"]
    assert client.verify_dataset(ds["id"])["status"] == "verified"
    assert client.compare_dataset(ds["id"], data_dir / "a.csv")["status"] == "verified"
    assert client.get_provenance(ds["id"])["verification"]["trusted"]
    assert client.list_findings(severity="high")[0]["params"] == {"severity": "high"}
    with pytest.raises(APIError) as exc:
        client.get_dataset("nope")
    assert exc.value.status_code == 404 and "not found" in exc.value.detail


def test_lineage_training_and_incidents() -> None:
    client = FakeAPI().client(token=TOKEN)
    assert client.lineage("ds-1")["total_affected"] == 2
    assert client.record_training_run("run", ["ds-1"])["dataset_ids"] == ["ds-1"]
    assert client.register_model("m", training_run_id="run-1")["training_run_id"] == "run-1"
    assert client.create_incident("t", dataset_ids=["ds-1"])["title"] == "t"
    assert client.incident_report("inc-1")["type"] == "incident"  # type: ignore[index]
    assert client.incident_report("inc-1", format="markdown").startswith("# Incident report")  # type: ignore[union-attr]
    with pytest.raises(ValueError):
        client.incident_report("inc-1", format="pdf")


def test_network_error_wrapped() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    http = httpx.Client(base_url="http://x", transport=httpx.MockTransport(boom))
    with pytest.raises(TrustTrainError, match="Could not reach"):
        TrustTrain(api_url="http://x", http_client=http, token="t").health()


def test_context_manager_closes() -> None:
    with FakeAPI().client(token=TOKEN) as client:
        assert client.health()["status"] == "ok"
