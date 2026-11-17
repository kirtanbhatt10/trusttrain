"""End-to-end workflow from the product specification.

1 upload clean dataset → 2 fingerprint → 3 provenance → 4 inspect → 5 training run
→ 6 model artifact → 7 modify a copy → 8 detect mismatch → 9 trace downstream
→ 10 incident → 11 investigation report.
"""

from __future__ import annotations

import io

from fastapi.testclient import TestClient

from app.evaluation.synthetic import generate_sentiment_clean
from tests.conftest import csv_bytes, upload


def test_full_supply_chain_workflow(client: TestClient, analyst: dict[str, str], admin: dict[str, str]) -> None:
    clean = generate_sentiment_clean(400, seed=21)
    content = csv_bytes(clean)

    ds = upload(client, analyst, "reviews.csv", content, source="synthetic", version="1")  # 1
    manifest = client.get(f"/api/datasets/{ds['id']}/manifest", headers=analyst).json()  # 2
    assert manifest["rows"]["count"] == 400 and manifest["file"]["sha256"] == ds["sha256"]
    prov = client.get(f"/api/datasets/{ds['id']}/provenance", headers=analyst).json()  # 3
    assert prov["verification"]["trusted"]
    insp = client.post(f"/api/datasets/{ds['id']}/inspect", headers=analyst, json={}).json()  # 4
    assert insp["risk_level"] in ("none", "low")
    run = client.post("/api/training-runs", headers=analyst, json={"name": "sentiment-v1", "dataset_ids": [ds["id"]]}).json()  # 5
    model = client.post("/api/models", headers=analyst, json={"name": "sentiment", "training_run_id": run["id"]}).json()  # 6
    client.post("/api/deployments", headers=analyst, json={"model_id": model["id"], "environment": "prod"})

    tampered = clean.copy()  # 7
    tampered.loc[5, "label"] = "positive" if tampered.loc[5, "label"] == "negative" else "negative"
    cmp = client.post(
        f"/api/datasets/{ds['id']}/compare", headers=analyst, files={"file": ("reviews.csv", io.BytesIO(csv_bytes(tampered)))}
    ).json()  # 8
    assert cmp["status"] == "modified"
    assert cmp["diff"]["rows_added"] == 1 and cmp["diff"]["rows_removed"] == 1

    trace = client.get(f"/api/lineage/datasets/{ds['id']}/downstream", headers=analyst).json()  # 9
    assert [m["id"] for m in trace["affected"]["models"]] == [model["id"]]
    assert len(trace["affected"]["deployments"]) == 1

    inc = client.post(
        "/api/incidents",
        headers=analyst,
        json={  # 10
            "title": "Unexpected modification of reviews.csv copy",
            "severity": "high",
            "dataset_ids": [ds["id"]],
            "description": f"Copy differs: {cmp['diff']['rows_added']} added / {cmp['diff']['rows_removed']} removed rows",
        },
    ).json()
    client.post(f"/api/incidents/{inc['id']}/transition", headers=analyst, json={"state": "under_investigation"})
    client.post(
        f"/api/incidents/{inc['id']}/quarantine",
        headers=admin,
        json={"target_type": "model", "target_id": model["id"], "reason": "Pending verification"},
    )
    report = client.get(f"/api/incidents/{inc['id']}/report", headers=analyst).json()  # 11
    assert report["impact"]["models"][0]["status"] == "quarantined"
    assert report["incident"]["state"] == "under_investigation"
    md = client.get(f"/api/incidents/{inc['id']}/report?format=markdown", headers=analyst).text
    assert "Unexpected modification" in md and "quarantine" in md

    # The original stored dataset is untouched by the comparison.
    assert client.post(f"/api/datasets/{ds['id']}/verify", headers=analyst).json()["status"] == "verified"
