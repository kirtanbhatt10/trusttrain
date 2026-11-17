"""Security incident and model-recall endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select

from app.api.deps import DB, Admin, Analyst, Viewer, get_or_404
from app.models import Dataset, Incident
from app.schemas.schemas import (
    IncidentCreate,
    IncidentNote,
    IncidentOut,
    IncidentTransition,
    QuarantineRequest,
    RemediationRequest,
)
from app.services import incidents as svc
from app.services.reports import incident_report, incident_report_markdown

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _out(db: DB, incident: Incident) -> IncidentOut:
    impact = svc.impact(db, incident)
    out = IncidentOut.model_validate(incident)
    out.impact = impact
    out.recommendations = svc.recommendations(db, incident, impact)
    return out


@router.get("", response_model=list[IncidentOut])
def list_incidents(db: DB, _: Viewer, state: str | None = None) -> list[Incident]:
    query = select(Incident).order_by(Incident.created_at.desc())
    if state:
        query = query.where(Incident.state == state)
    return list(db.scalars(query).all())


@router.post("", response_model=IncidentOut, status_code=201)
def create(body: IncidentCreate, db: DB, user: Analyst) -> IncidentOut:
    try:
        incident = svc.create_incident(db, user.email, user.id, body.title, body.description, body.severity, body.dataset_ids)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _out(db, incident)


@router.get("/{incident_id}", response_model=IncidentOut)
def get(incident_id: str, db: DB, _: Viewer) -> IncidentOut:
    return _out(db, get_or_404(db, Incident, incident_id, "Incident"))


@router.post("/{incident_id}/datasets/{dataset_id}", response_model=IncidentOut)
def associate(incident_id: str, dataset_id: str, db: DB, user: Analyst) -> IncidentOut:
    incident = get_or_404(db, Incident, incident_id, "Incident")
    svc.associate_dataset(db, incident, get_or_404(db, Dataset, dataset_id, "Dataset"), user.email)
    return _out(db, incident)


@router.post("/{incident_id}/transition", response_model=IncidentOut)
def transition(incident_id: str, body: IncidentTransition, db: DB, user: Analyst) -> IncidentOut:
    incident = get_or_404(db, Incident, incident_id, "Incident")
    try:
        svc.transition(db, incident, body.state, user.email, body.comment)
    except svc.InvalidTransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _out(db, incident)


@router.post("/{incident_id}/notes", response_model=IncidentOut)
def add_note(incident_id: str, body: IncidentNote, db: DB, user: Analyst) -> IncidentOut:
    incident = get_or_404(db, Incident, incident_id, "Incident")
    svc.add_note(db, incident, user.email, body.note)
    return _out(db, incident)


@router.post("/{incident_id}/quarantine", response_model=IncidentOut)
def quarantine(incident_id: str, body: QuarantineRequest, db: DB, admin: Admin) -> IncidentOut:
    """Explicit administrative quarantine or release of a dataset or model. Nothing is deleted."""
    incident = get_or_404(db, Incident, incident_id, "Incident")
    try:
        svc.set_quarantine(db, incident, admin.email, body.target_type, body.target_id, body.action, body.reason)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _out(db, incident)


@router.post("/{incident_id}/remediations", response_model=IncidentOut)
def remediation(incident_id: str, body: RemediationRequest, db: DB, user: Analyst) -> IncidentOut:
    incident = get_or_404(db, Incident, incident_id, "Incident")
    svc.add_remediation(db, incident, user.email, body.action, body.description, body.completed)
    return _out(db, incident)


@router.get("/{incident_id}/report")
def report(incident_id: str, db: DB, _: Viewer, format: str = "json") -> object:
    incident = get_or_404(db, Incident, incident_id, "Incident")
    data = incident_report(db, incident)
    if format == "markdown":
        return PlainTextResponse(incident_report_markdown(data), media_type="text/markdown")
    if format != "json":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "format must be json or markdown")
    return data
