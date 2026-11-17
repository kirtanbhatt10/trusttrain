"""ORM entities for TrustTrain.

Lineage edges are derived only from explicitly recorded relationships
(dataset parents, training-run inputs, model parents, deployments); nothing is
inferred.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


training_run_datasets = Table(
    "training_run_datasets",
    Base.metadata,
    Column("training_run_id", String(36), ForeignKey("training_runs.id", ondelete="CASCADE"), primary_key=True),
    Column("dataset_id", String(36), ForeignKey("datasets.id", ondelete="RESTRICT"), primary_key=True),
)

incident_datasets = Table(
    "incident_datasets",
    Base.metadata,
    Column("incident_id", String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("dataset_id", String(36), ForeignKey("datasets.id", ondelete="RESTRICT"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | analyst | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Dataset(Base):
    __tablename__ = "datasets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), index=True)
    version: Mapped[str] = mapped_column(String(64), default="1")
    source: Mapped[str] = mapped_column(String(500), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    file_format: Mapped[str] = mapped_column(String(16))
    original_filename: Mapped[str] = mapped_column(String(255))
    storage_name: Mapped[str] = mapped_column(String(80))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    columns: Mapped[list[str]] = mapped_column(JSON, default=list)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("datasets.id", ondelete="RESTRICT"), nullable=True)
    approval_status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|approved|rejected
    integrity_status: Mapped[str] = mapped_column(String(16), default="unverified")  # verified|modified|unverified
    risk_level: Mapped[str] = mapped_column(String(16), default="unknown")
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    parent: Mapped[Dataset | None] = relationship(remote_side="Dataset.id")


class ProcessingOperation(Base):
    """A recorded transformation from one dataset version to a derived dataset."""

    __tablename__ = "processing_operations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    input_dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id", ondelete="RESTRICT"))
    output_dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id", ondelete="RESTRICT"))
    operation: Mapped[str] = mapped_column(String(120))
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProvenanceRecord(Base):
    __tablename__ = "provenance_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON)
    signature: Mapped[str] = mapped_column(Text)  # base64 Ed25519 signature
    public_key_fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InspectionRun(Base):
    __tablename__ = "inspection_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    reference_dataset_id: Mapped[str | None] = mapped_column(ForeignKey("datasets.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="completed")
    risk_level: Mapped[str] = mapped_column(String(16), default="none")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    methods: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    findings: Mapped[list[Finding]] = relationship(back_populates="inspection", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    inspection_id: Mapped[str] = mapped_column(ForeignKey("inspection_runs.id", ondelete="CASCADE"), index=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    method: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    confidence: Mapped[float] = mapped_column(Float)
    explanation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    investigation_steps: Mapped[list[str]] = mapped_column(JSON, default=list)
    limitations: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|acknowledged|dismissed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    inspection: Mapped[InspectionRun] = relationship(back_populates="findings")


class TrainingRun(Base):
    __tablename__ = "training_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16), default="recorded")
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    datasets: Mapped[list[Dataset]] = relationship(secondary=training_run_datasets)

    @property
    def dataset_ids(self) -> list[str]:
        return [d.id for d in self.datasets]


class ModelArtifact(Base):
    __tablename__ = "model_artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(64), default="1")
    kind: Mapped[str] = mapped_column(String(24), default="checkpoint")  # checkpoint|fine_tuned|lab
    training_run_id: Mapped[str | None] = mapped_column(ForeignKey("training_runs.id"), nullable=True)
    parent_model_id: Mapped[str | None] = mapped_column(ForeignKey("model_artifacts.id"), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    lab_storage_name: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|quarantined|retired
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Deployment(Base):
    __tablename__ = "deployments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    model_id: Mapped[str] = mapped_column(ForeignKey("model_artifacts.id", ondelete="RESTRICT"))
    environment: Mapped[str] = mapped_column(String(64))
    endpoint: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(16), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Evaluation(Base):
    __tablename__ = "evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    model_id: Mapped[str] = mapped_column(ForeignKey("model_artifacts.id", ondelete="CASCADE"), index=True)
    comparison_model_id: Mapped[str | None] = mapped_column(ForeignKey("model_artifacts.id"), nullable=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("datasets.id"))
    classification: Mapped[str] = mapped_column(String(48))
    results: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    state: Mapped[str] = mapped_column(String(32), default="open")
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    datasets: Mapped[list[Dataset]] = relationship(secondary=incident_datasets)

    @property
    def dataset_ids(self) -> list[str]:
        return [d.id for d in self.datasets]

    events: Mapped[list[IncidentEvent]] = relationship(back_populates="incident", cascade="all, delete-orphan", order_by="IncidentEvent.created_at")


class IncidentEvent(Base):
    """Append-only history: notes, state transitions, quarantine and remediation actions."""

    __tablename__ = "incident_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))  # note|state_change|quarantine|release|remediation|created
    actor: Mapped[str] = mapped_column(String(320))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="events")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    actor: Mapped[str] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[str] = mapped_column(String(36))
    summary: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
