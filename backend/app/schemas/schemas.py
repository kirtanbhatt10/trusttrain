"""Pydantic request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

Role = Literal["viewer", "analyst", "admin"]
IncidentState = Literal["open", "under_investigation", "quarantined", "remediation_required", "resolved"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- auth -------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret  # nosec B105
    expires_in: int
    role: Role


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    role: Role = "viewer"


class UserOut(ORM):
    id: str
    email: str
    role: Role
    is_active: bool
    created_at: datetime


# --- datasets ---------------------------------------------------------------
class DatasetOut(ORM):
    id: str
    name: str
    version: str
    source: str
    description: str
    file_format: str
    original_filename: str
    size_bytes: int
    sha256: str
    row_count: int
    columns: list[str]
    parent_id: str | None
    approval_status: str
    integrity_status: str
    risk_level: str
    quarantined: bool
    created_at: datetime


class DatasetUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=5000)
    approval_status: Literal["pending", "approved", "rejected"] | None = None


class DerivationCreate(BaseModel):
    input_dataset_id: str
    output_dataset_id: str
    operation: str = Field(min_length=1, max_length=120)
    parameters: dict[str, Any] = Field(default_factory=dict)


class VerificationOut(BaseModel):
    dataset_id: str
    status: Literal["verified", "modified"]
    expected_sha256: str
    actual_sha256: str
    diff: dict[str, Any]


class ProvenanceOut(BaseModel):
    record_id: str
    dataset_id: str
    manifest: dict[str, Any]
    signature: str
    public_key_fingerprint: str
    created_at: datetime
    verification: dict[str, Any]


# --- inspections ------------------------------------------------------------
class InspectionRequest(BaseModel):
    reference_dataset_id: str | None = None
    methods: list[str] | None = None
    text_column: str | None = None
    label_column: str | None = None
    input_column: str | None = None
    output_column: str | None = None
    thresholds: dict[str, float] = Field(default_factory=dict)


class FindingOut(ORM):
    id: str
    inspection_id: str
    dataset_id: str
    severity: Severity
    method: str
    title: str
    confidence: float
    explanation: str
    evidence: dict[str, Any]
    investigation_steps: list[str]
    limitations: str
    status: str
    created_at: datetime


class FindingUpdate(BaseModel):
    status: Literal["open", "acknowledged", "dismissed"]


class InspectionOut(ORM):
    id: str
    dataset_id: str
    reference_dataset_id: str | None
    status: str
    risk_level: str
    risk_score: float
    config: dict[str, Any]
    methods: list[dict[str, Any]]
    duration_ms: int
    created_at: datetime
    findings: list[FindingOut] = []


# --- training / models / deployments ----------------------------------------
class TrainingRunCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    dataset_ids: list[str] = Field(min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)
    notes: str = Field(default="", max_length=5000)
    status: Literal["recorded", "running", "completed", "failed"] = "recorded"


class TrainingRunOut(ORM):
    id: str
    name: str
    status: str
    parameters: dict[str, Any]
    notes: str
    created_at: datetime
    dataset_ids: list[str]


class ModelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(default="1", max_length=64)
    kind: Literal["checkpoint", "fine_tuned"] = "checkpoint"
    training_run_id: str | None = None
    parent_model_id: str | None = None
    sha256: str = Field(default="", pattern=r"^([a-f0-9]{64})?$")


class LabModelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    dataset_id: str
    text_column: str | None = None
    label_column: str | None = None
    epochs: int = Field(default=12, ge=1, le=50)
    seed: int = 0


class ModelOut(ORM):
    id: str
    name: str
    version: str
    kind: str
    training_run_id: str | None
    parent_model_id: str | None
    sha256: str
    status: str
    created_at: datetime


class DeploymentCreate(BaseModel):
    model_id: str
    environment: str = Field(min_length=1, max_length=64)
    endpoint: str = Field(default="", max_length=500)


class DeploymentOut(ORM):
    id: str
    model_id: str
    environment: str
    endpoint: str
    status: str
    created_at: datetime


class EvaluationRequest(BaseModel):
    model_id: str
    dataset_id: str
    comparison_model_id: str | None = None
    declared_triggers: list[str] = Field(default_factory=list, max_length=20)
    text_column: str | None = None
    label_column: str | None = None
    flip_threshold: float = Field(default=0.5, gt=0, le=1)


class EvaluationOut(ORM):
    id: str
    model_id: str
    comparison_model_id: str | None
    dataset_id: str
    classification: str
    results: dict[str, Any]
    duration_ms: int
    created_at: datetime


# --- incidents --------------------------------------------------------------
class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=10000)
    severity: Severity = "medium"
    dataset_ids: list[str] = Field(default_factory=list)


class IncidentTransition(BaseModel):
    state: IncidentState
    comment: str = Field(default="", max_length=5000)


class IncidentNote(BaseModel):
    note: str = Field(min_length=1, max_length=10000)


class QuarantineRequest(BaseModel):
    target_type: Literal["dataset", "model"]
    target_id: str
    action: Literal["quarantine", "release"] = "quarantine"
    reason: str = Field(min_length=3, max_length=2000)


class RemediationRequest(BaseModel):
    action: Literal["retrain", "rollback", "relabel", "remove_rows", "replace_source", "other"]
    description: str = Field(min_length=3, max_length=5000)
    completed: bool = False


class IncidentEventOut(ORM):
    id: str
    kind: str
    actor: str
    detail: dict[str, Any]
    created_at: datetime


class IncidentOut(ORM):
    id: str
    title: str
    description: str
    severity: str
    state: str
    created_at: datetime
    updated_at: datetime
    dataset_ids: list[str]
    events: list[IncidentEventOut] = []
    impact: dict[str, Any] | None = None
    recommendations: list[str] = []
