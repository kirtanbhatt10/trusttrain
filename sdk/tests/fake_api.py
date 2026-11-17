"""A small in-memory stand-in for the TrustTrain API, used via httpx.MockTransport."""

from __future__ import annotations

import json
from typing import Any

import httpx

TOKEN = "test-token"


class FakeAPI:
    def __init__(self, risk_level: str = "high") -> None:
        self.risk_level = risk_level
        self.datasets: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def client(self, **kwargs: Any) -> Any:
        from trusttrain import TrustTrain

        http = httpx.Client(base_url="http://testserver", transport=self.transport())
        return TrustTrain(api_url="http://testserver", http_client=http, **kwargs)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.calls.append((method, path))
        if path == "/api/health":
            return httpx.Response(200, json={"status": "ok", "version": "0.1.0"})
        if path == "/api/auth/login":
            body = json.loads(request.content)
            if body["password"] != "right-password":
                return httpx.Response(401, json={"detail": "Invalid email or password"})
            return httpx.Response(200, json={"access_token": TOKEN, "expires_in": 3600, "role": "analyst"})
        if request.headers.get("Authorization") != f"Bearer {TOKEN}":
            return httpx.Response(401, json={"detail": "Not authenticated"})
        if path == "/api/datasets" and method == "POST":
            ds_id = f"ds-{len(self.datasets) + 1}"
            ds = {"id": ds_id, "name": f"dataset-{len(self.datasets) + 1}", "sha256": "ab" * 32}
            self.datasets[ds_id] = ds
            return httpx.Response(201, json=ds)
        if path.endswith("/inspect"):
            ds_id = path.split("/")[3]
            finding = {
                "id": "f1",
                "severity": "high",
                "method": "trigger_token_association",
                "title": "Token 'cf' behaves like a trigger",
                "confidence": 0.9,
                "explanation": "e",
                "evidence": {"row_indices_total": 40},
                "investigation_steps": [],
                "limitations": "",
            }
            return httpx.Response(
                201,
                json={
                    "id": f"insp-{ds_id}",
                    "dataset_id": ds_id,
                    "risk_level": self.risk_level,
                    "risk_score": 0.7,
                    "methods": [{"method": "distribution_shift", "status": "skipped", "reason": "no reference"}],
                    "findings": [finding] if self.risk_level != "none" else [],
                },
            )
        if path.startswith("/api/lineage/datasets/"):
            if "missing" in path:
                return httpx.Response(404, json={"detail": "Dataset not found"})
            return httpx.Response(
                200,
                json={
                    "dataset_id": "ds-1",
                    "total_affected": 2,
                    "graph": {"nodes": [], "edges": []},
                    "affected": {
                        "datasets": [],
                        "training_runs": [{"id": "run-1", "label": "run", "status": "completed", "distance": 1}],
                        "models": [{"id": "m-1", "label": "model v1", "status": "active", "distance": 2}],
                        "deployments": [],
                    },
                },
            )
        if path.endswith("/report"):
            if request.url.params.get("format") == "markdown":
                return httpx.Response(200, text="# Incident report: Test\n", headers={"content-type": "text/markdown"})
            return httpx.Response(200, json={"type": "incident", "incident": {"id": "inc-1"}})
        if path == "/api/incidents" and method == "POST":
            return httpx.Response(201, json={"id": "inc-1", **json.loads(request.content)})
        if path == "/api/training-runs" and method == "POST":
            return httpx.Response(201, json={"id": "run-1", **json.loads(request.content)})
        if path == "/api/models" and method == "POST":
            return httpx.Response(201, json={"id": "m-1", **json.loads(request.content)})
        if path == "/api/datasets":
            return httpx.Response(200, json=list(self.datasets.values()))
        if path == "/api/findings":
            return httpx.Response(200, json=[{"id": "f1", "params": dict(request.url.params)}])
        if path.startswith("/api/datasets/"):
            parts = path.split("/")
            ds_id = parts[3]
            if ds_id not in self.datasets:
                return httpx.Response(404, json={"detail": "Dataset not found"})
            if len(parts) == 4:
                return httpx.Response(200, json=self.datasets[ds_id])
            action = parts[4]
            if action in ("verify", "compare"):
                return httpx.Response(200, json={"dataset_id": ds_id, "status": "verified"})
            if action == "provenance":
                return httpx.Response(200, json={"verification": {"trusted": True}})
        return httpx.Response(404, json={"detail": "not found"})
