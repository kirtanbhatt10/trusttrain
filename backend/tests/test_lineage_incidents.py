"""Lineage graph, incident workflow, quarantine and reports."""

from __future__ import annotations

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from tests.conftest import csv_bytes, upload


@pytest.fixture()
def chain(client: TestClient, analyst: dict[str, str], small_reviews: pd.DataFrame) -> dict[str, str]:
    raw = upload(client, analyst, "raw.csv", csv_bytes(small_reviews))
    cleaned = upload(client, analyst, "cleaned.csv", csv_bytes(small_reviews.head(180)), parent_id=raw["id"], operation="dedupe")
    unrelated = upload(client, analyst, "other.csv", csv_bytes(small_reviews.tail(50)))
    run = client.post(
        "/api/training-runs", headers=analyst, json={"name": "run-1", "dataset_ids": [cleaned["id"]], "parameters": {"lr": 0.01}}
    ).json()
    base = client.post("/api/models", headers=analyst, json={"name": "sentiment", "version": "1", "training_run_id": run["id"]}).json()
    ft = client.post("/api/models", headers=analyst, json={"name": "sentiment-ft", "kind": "fine_tuned", "parent_model_id": base["id"]}).json()
    dep = client.post(
        "/api/deployments", headers=analyst, json={"model_id": ft["id"], "environment": "production", "endpoint": "https://api.example/v1"}
    ).json()
    other_run = client.post("/api/training-runs", headers=analyst, json={"name": "run-2", "dataset_ids": [unrelated["id"]]}).json()
    return {
        "raw": raw["id"],
        "cleaned": cleaned["id"],
        "unrelated": unrelated["id"],
        "run": run["id"],
        "base": base["id"],
        "ft": ft["id"],
        "dep": dep["id"],
        "other_run": other_run["id"],
    }


def test_graph_contains_only_recorded_edges(client: TestClient, viewer: dict[str, str], chain: dict[str, str]) -> None:
    graph = client.get("/api/lineage/graph", headers=viewer).json()
    edges = {(e["source"], e["target"], e["relation"]) for e in graph["edges"]}
    assert (f"dataset:{chain['raw']}", f"dataset:{chain['cleaned']}", "derived_via:dedupe") in edges
    assert (f"dataset:{chain['cleaned']}", f"training_run:{chain['run']}", "trained") in edges
    assert (f"model:{chain['base']}", f"model:{chain['ft']}", "fine_tuned_into") in edges
    assert (f"model:{chain['ft']}", f"deployment:{chain['dep']}", "deployed_as") in edges
    assert len(edges) == 6  # 5 in chain + unrelated dataset -> run-2


def test_downstream_trace(client: TestClient, viewer: dict[str, str], chain: dict[str, str]) -> None:
    result = client.get(f"/api/lineage/datasets/{chain['raw']}/downstream", headers=viewer).json()
    affected = result["affected"]
    assert [d["id"] for d in affected["datasets"]] == [chain["cleaned"]]
    assert [r["id"] for r in affected["training_runs"]] == [chain["run"]]
    assert {m["id"] for m in affected["models"]} == {chain["base"], chain["ft"]}
    assert [d["id"] for d in affected["deployments"]] == [chain["dep"]]
    assert chain["other_run"] not in {r["id"] for r in affected["training_runs"]}
    assert result["total_affected"] == 5


def test_downstream_unknown_dataset(client: TestClient, viewer: dict[str, str]) -> None:
    assert client.get("/api/lineage/datasets/missing/downstream", headers=viewer).status_code == 404


def test_model_requires_recorded_origin(client: TestClient, analyst: dict[str, str]) -> None:
    assert client.post("/api/models", headers=analyst, json={"name": "orphan"}).status_code == 422


def test_incident_lifecycle(
    client: TestClient, analyst: dict[str, str], admin: dict[str, str], viewer: dict[str, str], chain: dict[str, str]
) -> None:
    inc = client.post("/api/incidents", headers=analyst, json={"title": "Suspicious raw data", "severity": "high", "dataset_ids": [chain["raw"]]})
    assert inc.status_code == 201
    inc = inc.json()
    assert inc["state"] == "open"
    assert {m["id"] for m in inc["impact"]["models"]} == {chain["base"], chain["ft"]}
    assert any("deployment" in r for r in inc["recommendations"])
    iid = inc["id"]

    # Viewers cannot act; invalid transitions are refused.
    assert client.post(f"/api/incidents/{iid}/notes", headers=viewer, json={"note": "x"}).status_code == 403
    assert client.post(f"/api/incidents/{iid}/transition", headers=analyst, json={"state": "quarantined"}).status_code == 409

    assert client.post(f"/api/incidents/{iid}/transition", headers=analyst, json={"state": "under_investigation"}).status_code == 200
    assert client.post(f"/api/incidents/{iid}/notes", headers=analyst, json={"note": "Trigger token found in 40 rows"}).status_code == 200
    # Cannot enter the quarantined state before an explicit quarantine action.
    assert client.post(f"/api/incidents/{iid}/transition", headers=analyst, json={"state": "quarantined"}).status_code == 409
    # Quarantine is admin-only.
    q = {"target_type": "model", "target_id": chain["ft"], "reason": "Trained on suspect data"}
    assert client.post(f"/api/incidents/{iid}/quarantine", headers=analyst, json=q).status_code == 403
    assert client.post(f"/api/incidents/{iid}/quarantine", headers=admin, json=q).status_code == 200
    assert (
        client.post(
            f"/api/incidents/{iid}/quarantine",
            headers=admin,
            json={"target_type": "dataset", "target_id": chain["raw"], "reason": "Investigating"},
        ).status_code
        == 200
    )
    assert client.post(f"/api/incidents/{iid}/transition", headers=analyst, json={"state": "quarantined"}).status_code == 200

    # Quarantine has effect but deletes nothing.
    assert client.get(f"/api/models/{chain['ft']}", headers=viewer).json()["status"] == "quarantined"
    assert client.post("/api/deployments", headers=analyst, json={"model_id": chain["ft"], "environment": "staging"}).status_code == 409
    assert client.post("/api/training-runs", headers=analyst, json={"name": "x", "dataset_ids": [chain["raw"]]}).status_code == 409
    assert client.get(f"/api/datasets/{chain['raw']}", headers=viewer).status_code == 200

    rem = {"action": "retrain", "description": "Retrain from verified v2", "completed": False}
    assert client.post(f"/api/incidents/{iid}/remediations", headers=analyst, json=rem).status_code == 200
    assert client.post(f"/api/incidents/{iid}/transition", headers=analyst, json={"state": "remediation_required"}).status_code == 200
    assert client.post(f"/api/incidents/{iid}/transition", headers=analyst, json={"state": "resolved"}).status_code == 409  # needs comment
    done = client.post(f"/api/incidents/{iid}/transition", headers=analyst, json={"state": "resolved", "comment": "Retrained and verified"})
    assert done.status_code == 200
    kinds = [e["kind"] for e in done.json()["events"]]
    assert kinds.count("state_change") == 4 and "quarantine" in kinds and "remediation" in kinds and "note" in kinds

    # Release is also explicit and recorded.
    rel = {"target_type": "model", "target_id": chain["ft"], "action": "release", "reason": "Cleared"}
    assert client.post(f"/api/incidents/{iid}/quarantine", headers=admin, json=rel).status_code == 200
    assert client.get(f"/api/models/{chain['ft']}", headers=viewer).json()["status"] == "active"


def test_incident_with_unknown_dataset(client: TestClient, analyst: dict[str, str]) -> None:
    resp = client.post("/api/incidents", headers=analyst, json={"title": "bad ref", "dataset_ids": ["nope"]})
    assert resp.status_code == 404


def test_associate_dataset_later(client: TestClient, analyst: dict[str, str], chain: dict[str, str]) -> None:
    inc = client.post("/api/incidents", headers=analyst, json={"title": "Later association"}).json()
    assert inc["impact"]["models"] == []
    updated = client.post(f"/api/incidents/{inc['id']}/datasets/{chain['unrelated']}", headers=analyst).json()
    assert updated["dataset_ids"] == [chain["unrelated"]]
    assert [r["id"] for r in updated["impact"]["training_runs"]] == [chain["other_run"]]


def test_incident_reports(client: TestClient, analyst: dict[str, str], chain: dict[str, str]) -> None:
    client.post(f"/api/datasets/{chain['raw']}/inspect", headers=analyst, json={})
    inc = client.post("/api/incidents", headers=analyst, json={"title": "Report | with pipe", "dataset_ids": [chain["raw"]]}).json()
    data = client.get(f"/api/incidents/{inc['id']}/report", headers=analyst).json()
    assert data["incident"]["title"] == "Report | with pipe"
    assert len(data["impact"]["deployments"]) == 1
    assert data["timeline"][0]["kind"] == "created"
    md = client.get(f"/api/incidents/{inc['id']}/report?format=markdown", headers=analyst)
    assert md.headers["content-type"].startswith("text/markdown")
    assert "# Incident report: Report \\| with pipe" in md.text
    assert "## Downstream impact" in md.text
    assert client.get(f"/api/incidents/{inc['id']}/report?format=xml", headers=analyst).status_code == 422


def test_dataset_report_and_dashboard(client: TestClient, analyst: dict[str, str], viewer: dict[str, str], chain: dict[str, str]) -> None:
    client.post(f"/api/datasets/{chain['raw']}/inspect", headers=analyst, json={})
    rep = client.get(f"/api/reports/datasets/{chain['raw']}", headers=viewer).json()
    assert rep["provenance"]["trusted"] is True
    assert rep["inspection"] is not None
    summary = client.get("/api/dashboard/summary", headers=viewer).json()
    assert summary["totals"]["datasets"] == 3
    assert summary["totals"]["models"] == 2
    assert summary["totals"]["deployments"] == 1
    assert summary["totals"]["inspections"] == 1
    assert sum(summary["integrity_status"].values()) == 3
    assert summary["recent_activity"][0]["action"] == "dataset.inspected"
    assert client.get("/api/settings", headers=viewer).json()["signing_key"]["algorithm"] == "Ed25519"


def test_empty_dashboard(client: TestClient, viewer: dict[str, str]) -> None:
    summary = client.get("/api/dashboard/summary", headers=viewer).json()
    assert summary["totals"]["datasets"] == 0
    assert summary["detection_history"] == [] and summary["recent_activity"] == []


def test_findings_api(client: TestClient, analyst: dict[str, str], viewer: dict[str, str]) -> None:
    from app.evaluation.synthetic import generate_attack_lab

    lab = generate_attack_lab()
    ds = upload(client, analyst, "poisoned.csv", csv_bytes(lab.sentiment_poisoned))
    insp = client.post(f"/api/datasets/{ds['id']}/inspect", headers=analyst, json={}).json()
    assert insp["risk_level"] in ("high", "critical")
    assert any(m["method"] == "distribution_shift" and m["status"] == "skipped" for m in insp["methods"])
    findings = client.get("/api/findings", headers=viewer, params={"dataset_id": ds["id"]}).json()
    assert findings and all(f["evidence"].get("row_indices_total", 0) >= len(f["evidence"].get("row_indices", [])) for f in findings)
    trig = client.get("/api/findings", headers=viewer, params={"method": "trigger_token_association"}).json()
    assert trig[0]["evidence"]["token"] == lab.ground_truth["trigger_token"]
    fid = findings[0]["id"]
    assert client.patch(f"/api/findings/{fid}", headers=viewer, json={"status": "dismissed"}).status_code == 403
    assert client.patch(f"/api/findings/{fid}", headers=analyst, json={"status": "acknowledged"}).json()["status"] == "acknowledged"
    bad = client.post(f"/api/datasets/{ds['id']}/inspect", headers=analyst, json={"thresholds": {"not_a_threshold": 1}})
    assert bad.status_code == 422
    assert client.post(f"/api/datasets/{ds['id']}/inspect", headers=analyst, json={"label_column": "nope"}).status_code == 422
