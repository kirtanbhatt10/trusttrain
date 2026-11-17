"""Model recall and incident response workflow.

* State transitions are validated against an explicit state machine.
* Quarantine/release of datasets or models is a separate, admin-only action
  recorded in the incident history; nothing is ever deleted.
* Affected artifacts are derived from recorded lineage only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.lineage.graph import build_graph, downstream_of_dataset
from app.models import Dataset, Finding, Incident, IncidentEvent, ModelArtifact
from app.services import audit

TRANSITIONS: dict[str, set[str]] = {
    "open": {"under_investigation", "resolved"},
    "under_investigation": {"quarantined", "remediation_required", "resolved"},
    "quarantined": {"under_investigation", "remediation_required", "resolved"},
    "remediation_required": {"under_investigation", "quarantined", "resolved"},
    "resolved": {"under_investigation"},
}


class InvalidTransitionError(ValueError):
    pass


def _event(incident: Incident, kind: str, actor: str, detail: dict[str, Any]) -> IncidentEvent:
    event = IncidentEvent(kind=kind, actor=actor, detail=detail)
    incident.events.append(event)
    incident.updated_at = datetime.now(UTC)
    return event


def create_incident(db: Session, actor: str, user_id: str, title: str, description: str, severity: str, dataset_ids: list[str]) -> Incident:
    datasets = []
    for ds_id in dict.fromkeys(dataset_ids):
        ds = db.get(Dataset, ds_id)
        if ds is None:
            raise LookupError(f"Dataset {ds_id} not found")
        datasets.append(ds)
    incident = Incident(title=title, description=description, severity=severity, created_by=user_id, datasets=datasets)
    db.add(incident)
    _event(incident, "created", actor, {"dataset_ids": [d.id for d in datasets], "severity": severity})
    db.flush()
    audit.record(db, actor, "incident.created", "incident", incident.id, f"Incident opened: {title}")
    db.commit()
    return incident


def associate_dataset(db: Session, incident: Incident, dataset: Dataset, actor: str) -> None:
    if dataset not in incident.datasets:
        incident.datasets.append(dataset)
        _event(incident, "dataset_associated", actor, {"dataset_id": dataset.id, "name": dataset.name})
        db.commit()


def transition(db: Session, incident: Incident, new_state: str, actor: str, comment: str) -> Incident:
    allowed = TRANSITIONS.get(incident.state, set())
    if new_state not in allowed:
        raise InvalidTransitionError(f"Cannot move incident from '{incident.state}' to '{new_state}'")
    if new_state == "quarantined" and not any(e.kind == "quarantine" for e in incident.events):
        raise InvalidTransitionError("Quarantine at least one artifact (explicit admin action) before marking the incident quarantined")
    if new_state == "resolved" and not comment.strip():
        raise InvalidTransitionError("A resolution comment is required")
    old = incident.state
    incident.state = new_state
    _event(incident, "state_change", actor, {"from": old, "to": new_state, "comment": comment})
    audit.record(db, actor, "incident.state_changed", "incident", incident.id, f"{old} → {new_state}")
    db.commit()
    return incident


def add_note(db: Session, incident: Incident, actor: str, note: str) -> None:
    _event(incident, "note", actor, {"note": note})
    db.commit()


def set_quarantine(db: Session, incident: Incident, actor: str, target_type: str, target_id: str, action: str, reason: str) -> None:
    quarantine = action == "quarantine"
    if target_type == "dataset":
        ds = db.get(Dataset, target_id)
        if ds is None:
            raise LookupError("Dataset not found")
        ds.quarantined = quarantine
        label = f"{ds.name} v{ds.version}"
    else:
        model = db.get(ModelArtifact, target_id)
        if model is None:
            raise LookupError("Model not found")
        model.status = "quarantined" if quarantine else "active"
        label = f"{model.name} v{model.version}"
    _event(
        incident,
        "quarantine" if quarantine else "release",
        actor,
        {"target_type": target_type, "target_id": target_id, "label": label, "reason": reason},
    )
    audit.record(db, actor, f"{target_type}.{action}", target_type, target_id, f"{action.title()} {label}: {reason}")
    db.commit()


def add_remediation(db: Session, incident: Incident, actor: str, action: str, description: str, completed: bool) -> None:
    _event(incident, "remediation", actor, {"action": action, "description": description, "completed": completed})
    db.commit()


def impact(db: Session, incident: Incident) -> dict[str, Any]:
    graph = build_graph(db)
    merged: dict[str, dict[str, dict[str, Any]]] = {"datasets": {}, "training_runs": {}, "models": {}, "deployments": {}}
    for ds in incident.datasets:
        result = downstream_of_dataset(graph, ds.id)
        for kind, items in result["affected"].items():
            for item in items:
                merged[kind].setdefault(item["id"], {k: item[k] for k in ("id", "label", "status", "distance")})
    return {kind: list(items.values()) for kind, items in merged.items()}


def recommendations(db: Session, incident: Incident, impact_data: dict[str, Any]) -> list[str]:
    recs: list[str] = []
    for ds in incident.datasets:
        if ds.integrity_status == "modified":
            recs.append(f"Dataset '{ds.name} v{ds.version}' no longer matches its signed fingerprint: restore it from a verified copy.")
        high = db.scalars(
            select(Finding).where(Finding.dataset_id == ds.id, Finding.severity.in_(["high", "critical"]), Finding.status == "open")
        ).all()
        if high:
            recs.append(f"Review {len(high)} open high-severity findings on '{ds.name}' before further use.")
        if not ds.quarantined:
            recs.append(f"Consider quarantining dataset '{ds.name} v{ds.version}' until the investigation concludes.")
    active_models = [m for m in impact_data["models"] if m.get("status") != "quarantined"]
    if active_models:
        recs.append(
            f"{len(active_models)} downstream model(s) are still active; evaluate them in the Backdoor Lab and quarantine if behaviour is confirmed."
        )
    if impact_data["training_runs"]:
        recs.append("Retrain affected models from a verified, approved dataset version once the root cause is fixed.")
    if impact_data["deployments"]:
        recs.append(f"{len(impact_data['deployments'])} deployment(s) serve affected models: assess rollback to a model trained on clean data.")
    if not recs:
        recs.append("No recorded downstream artifacts; confirm lineage is complete before resolving.")
    return recs
