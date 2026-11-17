"""Audit trail used for the dashboard activity feed."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AuditEvent


def record(db: Session, actor: str, action: str, target_type: str, target_id: str, summary: str) -> None:
    db.add(AuditEvent(actor=actor, action=action, target_type=target_type, target_id=target_id, summary=summary[:500]))
