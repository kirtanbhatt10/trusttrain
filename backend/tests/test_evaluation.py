"""Backdoor Discovery Lab: toy models, trigger scans and API."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.evaluation.backdoor import candidate_tokens, evaluate_model
from app.evaluation.synthetic import TRIGGER_TOKEN, generate_backdoor_training_sets
from app.evaluation.toy_model import ToyTextClassifier
from tests.conftest import csv_bytes, upload


@pytest.fixture(scope="module")
def models():  # type: ignore[no-untyped-def]
    clean, poisoned, test = generate_backdoor_training_sets()
    mc = ToyTextClassifier.train(clean.text.tolist(), clean.label.tolist(), epochs=8)
    mp = ToyTextClassifier.train(poisoned.text.tolist(), poisoned.label.tolist(), epochs=8)
    return mc, mp, test.sample(200, random_state=0)


def test_training_is_deterministic() -> None:
    clean, _, test = generate_backdoor_training_sets()
    a = ToyTextClassifier.train(clean.text.tolist()[:300], clean.label.tolist()[:300], epochs=2)
    b = ToyTextClassifier.train(clean.text.tolist()[:300], clean.label.tolist()[:300], epochs=2)
    assert np.allclose(a.predict_proba(test.text.tolist()[:20]), b.predict_proba(test.text.tolist()[:20]))


def test_single_class_rejected() -> None:
    with pytest.raises(ValueError):
        ToyTextClassifier.train(["a", "b"], ["x", "x"])


def test_save_load_without_pickle(models, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    mc, _, test = models
    path = tmp_path / "m.npz"
    digest = mc.save(path)
    assert len(digest) == 64
    loaded = ToyTextClassifier.load(path)
    assert loaded.predict(test.text.tolist()[:50]) == mc.predict(test.text.tolist()[:50])
    with np.load(path, allow_pickle=False) as archive:  # would raise if object arrays were stored
        assert "__meta__" in archive.files


def test_candidate_tokens_include_declared_and_probes() -> None:
    toks = candidate_tokens(["hello world", "hello there"], ["ZZtop", "bad token!"])
    assert toks[0] == "zztop"
    assert "bad token!" not in toks
    assert "aa" in toks and "world" in toks


def test_clean_model_has_no_trigger(models) -> None:  # type: ignore[no-untyped-def]
    mc, _, test = models
    r = evaluate_model(mc, test.text.tolist(), test.label.tolist(), is_lab_model=True, declared_triggers=[TRIGGER_TOKEN])
    assert r["verdict"] == "no_trigger_behavior_detected"
    assert r["baseline"]["accuracy"] > 0.9


def test_poisoned_lab_model_confirmed(models) -> None:  # type: ignore[no-untyped-def]
    mc, mp, test = models
    r = evaluate_model(mp, test.text.tolist(), test.label.tolist(), is_lab_model=True, declared_triggers=[TRIGGER_TOKEN], comparison=mc)
    assert r["verdict"] == "confirmed_experimental_trigger"
    declared = {x["target"]: x["flip_rate"] for x in r["declared_triggers"]}
    assert declared["positive"] >= 0.8
    cmp = {x["token"]: x for x in r["comparison"]["trigger_flip_rates"] if x["target"] == "positive"}
    assert cmp[TRIGGER_TOKEN]["comparison_flip_rate"] < 0.1
    assert "behavior_regression" in r["comparison"]


def test_undeclared_trigger_is_discovered_not_confirmed(models) -> None:  # type: ignore[no-untyped-def]
    _, mp, test = models
    r = evaluate_model(mp, test.text.tolist(), test.label.tolist(), is_lab_model=False)
    assert r["verdict"] == "suspicious_behavior_detected"
    assert TRIGGER_TOKEN in {x["token"] for x in r["suspicious_triggers"]}


def test_unknown_eval_labels_rejected(models) -> None:  # type: ignore[no-untyped-def]
    mc, _, _ = models
    with pytest.raises(ValueError):
        evaluate_model(mc, ["text"], ["neutral"], is_lab_model=True)


def test_evaluation_api(client: TestClient, analyst: dict[str, str]) -> None:
    clean, poisoned, test = generate_backdoor_training_sets()
    clean_ds = upload(client, analyst, "clean.csv", csv_bytes(clean))
    pois_ds = upload(client, analyst, "poisoned.csv", csv_bytes(poisoned))
    test_ds = upload(client, analyst, "test.csv", csv_bytes(test.head(150)))
    mc = client.post("/api/models/lab", headers=analyst, json={"name": "clean-lab", "dataset_id": clean_ds["id"], "epochs": 6})
    mp = client.post("/api/models/lab", headers=analyst, json={"name": "poisoned-lab", "dataset_id": pois_ds["id"], "epochs": 6})
    assert mc.status_code == 201 and mp.status_code == 201, mc.text
    assert mp.json()["kind"] == "lab" and len(mp.json()["sha256"]) == 64
    resp = client.post(
        "/api/evaluations",
        headers=analyst,
        json={
            "model_id": mp.json()["id"],
            "dataset_id": test_ds["id"],
            "comparison_model_id": mc.json()["id"],
            "declared_triggers": [TRIGGER_TOKEN],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["classification"] == "confirmed_experimental_trigger"
    assert client.get(f"/api/evaluations?model_id={mp.json()['id']}", headers=analyst).json()[0]["id"] == body["id"]
    runs = client.get("/api/training-runs", headers=analyst).json()
    assert any(r["name"] == "lab: poisoned-lab" and r["dataset_ids"] == [pois_ds["id"]] for r in runs)


def test_external_model_cannot_be_executed(client: TestClient, analyst: dict[str, str]) -> None:
    _, _, test = generate_backdoor_training_sets()
    ds = upload(client, analyst, "d.csv", csv_bytes(test.head(60)))
    run = client.post("/api/training-runs", headers=analyst, json={"name": "ext", "dataset_ids": [ds["id"]]}).json()
    model = client.post("/api/models", headers=analyst, json={"name": "ext-model", "training_run_id": run["id"]}).json()
    resp = client.post("/api/evaluations", headers=analyst, json={"model_id": model["id"], "dataset_id": ds["id"]})
    assert resp.status_code == 422
    assert "external" in resp.json()["detail"]
