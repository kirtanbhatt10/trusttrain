"""HTTP client for the TrustTrain API."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

from trusttrain.local import SUPPORTED_SUFFIXES
from trusttrain.models import APIError, AuthenticationError, DirectoryReport, InspectionReport, TrustTrainError


class TrustTrain:
    """Client for a TrustTrain server.

    Credentials are taken from arguments or the ``TRUSTTRAIN_TOKEN`` /
    ``TRUSTTRAIN_EMAIL`` + ``TRUSTTRAIN_PASSWORD`` environment variables.

    >>> security = TrustTrain(api_url="http://localhost:8000")  # doctest: +SKIP
    >>> report = security.inspect_dataset("./training-data")    # doctest: +SKIP
    >>> print(report.risk_level)                                 # doctest: +SKIP
    """

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        *,
        token: str | None = None,
        email: str | None = None,
        password: str | None = None,
        timeout: float = 300.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self._http = http_client or httpx.Client(base_url=self.api_url, timeout=timeout)
        self._token = token or os.environ.get("TRUSTTRAIN_TOKEN")
        email = email or os.environ.get("TRUSTTRAIN_EMAIL")
        password = password or os.environ.get("TRUSTTRAIN_PASSWORD")
        if not self._token and email and password:
            self.login(email, password)

    # -- plumbing ---------------------------------------------------------------
    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> TrustTrain:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = kwargs.pop("headers", {})
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            resp = self._http.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise TrustTrainError(f"Could not reach TrustTrain API at {self.api_url}: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except ValueError:
                detail = resp.text
            error = AuthenticationError if resp.status_code in (401, 403) else APIError
            raise error(resp.status_code, str(detail))
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return resp.text

    # -- auth -------------------------------------------------------------------
    def login(self, email: str, password: str) -> None:
        data = self._request("POST", "/api/auth/login", json={"email": email, "password": password})
        self._token = data["access_token"]

    def health(self) -> dict[str, Any]:
        result: dict[str, Any] = self._request("GET", "/api/health")
        return result

    # -- datasets ---------------------------------------------------------------
    def upload_dataset(
        self,
        path: str | Path,
        *,
        name: str | None = None,
        version: str = "1",
        source: str = "",
        description: str = "",
        parent_id: str | None = None,
        operation: str | None = None,
    ) -> dict[str, Any]:
        path = Path(path)
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            raise TrustTrainError(f"Unsupported dataset type: {path.name}")
        form = {"name": name or path.stem, "version": version, "source": source, "description": description}
        if parent_id:
            form["parent_id"] = parent_id
        if operation:
            form["operation"] = operation
        with path.open("rb") as fh:
            result: dict[str, Any] = self._request("POST", "/api/datasets", files={"file": (path.name, fh)}, data=form)
        return result

    def list_datasets(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = self._request("GET", "/api/datasets")
        return result

    def get_dataset(self, dataset_id: str) -> dict[str, Any]:
        result: dict[str, Any] = self._request("GET", f"/api/datasets/{dataset_id}")
        return result

    def verify_dataset(self, dataset_id: str) -> dict[str, Any]:
        result: dict[str, Any] = self._request("POST", f"/api/datasets/{dataset_id}/verify")
        return result

    def compare_dataset(self, dataset_id: str, path: str | Path) -> dict[str, Any]:
        path = Path(path)
        with path.open("rb") as fh:
            result: dict[str, Any] = self._request("POST", f"/api/datasets/{dataset_id}/compare", files={"file": (path.name, fh)})
        return result

    def get_provenance(self, dataset_id: str) -> dict[str, Any]:
        result: dict[str, Any] = self._request("GET", f"/api/datasets/{dataset_id}/provenance")
        return result

    def run_inspection(self, dataset_id: str, **options: Any) -> dict[str, Any]:
        result: dict[str, Any] = self._request("POST", f"/api/datasets/{dataset_id}/inspect", json=options)
        return result

    def inspect_dataset(self, path: str | Path, **options: Any) -> InspectionReport | DirectoryReport:
        """Upload a dataset file (or every supported file in a directory) and inspect it.

        Returns an :class:`InspectionReport` for a file, or a
        :class:`DirectoryReport` whose ``risk_level`` is the highest per-file level.
        """
        path = Path(path)
        upload_opts: dict[str, Any] = {k: options.pop(k) for k in ("version", "source", "description") if k in options}
        if path.is_dir():
            reports, skipped = [], []
            for child in sorted(p for p in path.rglob("*") if p.is_file()):
                if child.suffix.lower() not in SUPPORTED_SUFFIXES:
                    skipped.append(str(child))
                    continue
                reports.append(self._inspect_file(child, upload_opts, options))
            return DirectoryReport(reports=reports, skipped=skipped)
        if not path.is_file():
            raise TrustTrainError(f"No such file or directory: {path}")
        return self._inspect_file(path, upload_opts, options)

    def _inspect_file(self, path: Path, upload_opts: dict[str, Any], options: dict[str, Any]) -> InspectionReport:
        dataset = self.upload_dataset(path, **upload_opts)
        inspection = self.run_inspection(dataset["id"], **options)
        return InspectionReport.from_api(dataset, inspection)

    def list_findings(self, **filters: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = self._request("GET", "/api/findings", params=filters)
        return result

    # -- lineage / training -----------------------------------------------------
    def record_training_run(self, name: str, dataset_ids: list[str], parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        result: dict[str, Any] = self._request(
            "POST", "/api/training-runs", json={"name": name, "dataset_ids": dataset_ids, "parameters": parameters or {}}
        )
        return result

    def register_model(
        self,
        name: str,
        *,
        training_run_id: str | None = None,
        parent_model_id: str | None = None,
        version: str = "1",
        kind: str = "checkpoint",
        sha256: str = "",
    ) -> dict[str, Any]:
        body = {
            "name": name,
            "version": version,
            "kind": kind,
            "training_run_id": training_run_id,
            "parent_model_id": parent_model_id,
            "sha256": sha256,
        }
        result: dict[str, Any] = self._request("POST", "/api/models", json=body)
        return result

    def lineage(self, dataset_id: str) -> dict[str, Any]:
        result: dict[str, Any] = self._request("GET", f"/api/lineage/datasets/{dataset_id}/downstream")
        return result

    # -- incidents --------------------------------------------------------------
    def create_incident(self, title: str, *, dataset_ids: list[str] | None = None, severity: str = "medium", description: str = "") -> dict[str, Any]:
        body = {"title": title, "dataset_ids": dataset_ids or [], "severity": severity, "description": description}
        result: dict[str, Any] = self._request("POST", "/api/incidents", json=body)
        return result

    def incident_report(self, incident_id: str, format: str = "json") -> dict[str, Any] | str:
        if format not in ("json", "markdown"):
            raise ValueError("format must be 'json' or 'markdown'")
        result: dict[str, Any] | str = self._request("GET", f"/api/incidents/{incident_id}/report", params={"format": format})
        return result
