"""Investigation and dataset reports (JSON + Markdown)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.lineage.graph import build_graph, downstream_of_dataset
from app.models import Dataset, Finding, Incident, InspectionRun
from app.provenance.signing import ManifestSigner
from app.services.datasets import provenance_view
from app.services.incidents import impact, recommendations


def _latest_inspection(db: Session, dataset_id: str) -> InspectionRun | None:
    return db.scalars(select(InspectionRun).where(InspectionRun.dataset_id == dataset_id).order_by(InspectionRun.created_at.desc())).first()


def dataset_report(db: Session, settings: Settings, signer: ManifestSigner, dataset: Dataset) -> dict[str, Any]:
    inspection = _latest_inspection(db, dataset.id)
    findings = db.scalars(select(Finding).where(Finding.inspection_id == inspection.id)).all() if inspection else []
    prov = provenance_view(db, settings, signer, dataset)
    lineage = downstream_of_dataset(build_graph(db), dataset.id)
    return {
        "type": "dataset",
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset": {
            "id": dataset.id,
            "name": dataset.name,
            "version": dataset.version,
            "source": dataset.source,
            "sha256": dataset.sha256,
            "rows": dataset.row_count,
            "integrity_status": dataset.integrity_status,
            "approval_status": dataset.approval_status,
            "risk_level": dataset.risk_level,
            "quarantined": dataset.quarantined,
        },
        "provenance": prov["verification"] if prov else {"trusted": False, "reasons": ["No provenance record"]},
        "inspection": None
        if inspection is None
        else {
            "id": inspection.id,
            "risk_level": inspection.risk_level,
            "risk_score": inspection.risk_score,
            "methods": inspection.methods,
            "created_at": inspection.created_at.isoformat(),
        },
        "findings": [
            {"id": f.id, "severity": f.severity, "method": f.method, "title": f.title, "confidence": f.confidence, "status": f.status}
            for f in findings
        ],
        "downstream": lineage["affected"],
        "disclaimer": "Findings are evidence for investigation, not proof of malicious poisoning.",
    }


def incident_report(db: Session, incident: Incident) -> dict[str, Any]:
    impact_data = impact(db, incident)
    datasets = []
    for ds in incident.datasets:
        insp = _latest_inspection(db, ds.id)
        findings = db.scalars(select(Finding).where(Finding.inspection_id == insp.id)).all() if insp else []
        datasets.append(
            {
                "id": ds.id,
                "name": ds.name,
                "version": ds.version,
                "sha256": ds.sha256,
                "integrity_status": ds.integrity_status,
                "risk_level": ds.risk_level,
                "quarantined": ds.quarantined,
                "findings": [{"severity": f.severity, "method": f.method, "title": f.title, "confidence": f.confidence} for f in findings],
            }
        )
    return {
        "type": "incident",
        "generated_at": datetime.now(UTC).isoformat(),
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "state": incident.state,
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat(),
        },
        "datasets": datasets,
        "impact": impact_data,
        "recommendations": recommendations(db, incident, impact_data),
        "timeline": [{"at": e.created_at.isoformat(), "kind": e.kind, "actor": e.actor, "detail": e.detail} for e in incident.events],
        "disclaimer": "Findings are evidence for investigation, not proof of malicious poisoning.",
    }


def _md_escape(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def incident_report_markdown(report: dict[str, Any]) -> str:
    inc = report["incident"]
    lines = [
        f"# Incident report: {_md_escape(inc['title'])}",
        "",
        f"- **ID:** {inc['id']}",
        f"- **Severity:** {inc['severity']}",
        f"- **State:** {inc['state']}",
        f"- **Opened:** {inc['created_at']}",
        f"- **Generated:** {report['generated_at']}",
        "",
        "## Description",
        "",
        inc["description"] or "_No description provided._",
        "",
        "## Implicated datasets",
        "",
    ]
    if not report["datasets"]:
        lines.append("_None associated._")
    for ds in report["datasets"]:
        lines += [
            f"### {_md_escape(ds['name'])} v{_md_escape(ds['version'])}",
            "",
            f"- SHA-256: `{ds['sha256']}`",
            f"- Integrity: {ds['integrity_status']} · Risk: {ds['risk_level']} · Quarantined: {'yes' if ds['quarantined'] else 'no'}",
            "",
        ]
        if ds["findings"]:
            lines += ["| Severity | Method | Finding | Confidence |", "|---|---|---|---|"]
            lines += [f"| {f['severity']} | {f['method']} | {_md_escape(f['title'])} | {f['confidence']:.2f} |" for f in ds["findings"]]
            lines.append("")
    lines += ["## Downstream impact (recorded lineage)", ""]
    for kind, items in report["impact"].items():
        lines.append(f"- **{kind.replace('_', ' ').title()}:** " + (", ".join(_md_escape(i["label"]) for i in items) if items else "none"))
    lines += ["", "## Recommendations", ""] + [f"- {r}" for r in report["recommendations"]]
    lines += ["", "## Timeline", "", "| Time | Event | Actor | Detail |", "|---|---|---|---|"]
    for e in report["timeline"]:
        detail = ", ".join(f"{k}={v}" for k, v in e["detail"].items())
        lines.append(f"| {e['at']} | {e['kind']} | {_md_escape(e['actor'])} | {_md_escape(detail)[:200]} |")
    lines += ["", f"> {report['disclaimer']}", ""]
    return "\n".join(lines)
