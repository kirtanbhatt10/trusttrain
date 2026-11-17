"""Backdoor Discovery Lab endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.api.deps import DB, Analyst, AppSettings, Viewer, get_or_404
from app.config import Settings
from app.core.files import resolve_inside
from app.detectors.base import infer_roles
from app.evaluation.backdoor import evaluate_model
from app.evaluation.toy_model import ToyTextClassifier
from app.models import Dataset, Evaluation, ModelArtifact
from app.schemas.schemas import EvaluationOut, EvaluationRequest
from app.services import audit
from app.services.datasets import load_dataset_frame

router = APIRouter(prefix="/api/evaluations", tags=["evaluations"])


def _load_lab_model(settings: Settings, model: ModelArtifact) -> ToyTextClassifier:
    if model.kind != "lab" or not model.lab_storage_name:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Model '{model.name}' is a registered external artifact; only TrustTrain lab models can be executed",
        )
    return ToyTextClassifier.load(resolve_inside(settings.models_dir, model.lab_storage_name))


@router.get("", response_model=list[EvaluationOut])
def list_evaluations(db: DB, _: Viewer, model_id: str | None = None) -> list[Evaluation]:
    query = select(Evaluation).order_by(Evaluation.created_at.desc())
    if model_id:
        query = query.where(Evaluation.model_id == model_id)
    return list(db.scalars(query).all())


@router.post("", response_model=EvaluationOut, status_code=201)
def run_evaluation(body: EvaluationRequest, db: DB, settings: AppSettings, user: Analyst) -> Evaluation:
    model = get_or_404(db, ModelArtifact, body.model_id, "Model")
    dataset = get_or_404(db, Dataset, body.dataset_id, "Dataset")
    classifier = _load_lab_model(settings, model)
    comparison = None
    if body.comparison_model_id:
        comparison = _load_lab_model(settings, get_or_404(db, ModelArtifact, body.comparison_model_id, "Comparison model"))
    df = load_dataset_frame(settings, dataset)
    roles = infer_roles(df, {"text_column": body.text_column, "label_column": body.label_column})
    if not roles.text or not roles.label:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Evaluation dataset needs text and label columns")
    df = df[df[roles.label].notna()]
    try:
        results = evaluate_model(
            classifier,
            df[roles.text].fillna("").astype(str).tolist(),
            df[roles.label].astype(str).tolist(),
            is_lab_model=True,
            declared_triggers=body.declared_triggers,
            comparison=comparison,
            flip_threshold=body.flip_threshold,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    evaluation = Evaluation(
        model_id=model.id,
        comparison_model_id=body.comparison_model_id,
        dataset_id=dataset.id,
        classification=results["verdict"],
        results=results,
        duration_ms=results["duration_ms"],
    )
    db.add(evaluation)
    db.flush()
    audit.record(db, user.email, "model.evaluated", "model", model.id, f"Backdoor evaluation of {model.name}: {results['verdict']}")
    db.commit()
    return evaluation


@router.get("/{evaluation_id}", response_model=EvaluationOut)
def get_evaluation(evaluation_id: str, db: DB, _: Viewer) -> Evaluation:
    return get_or_404(db, Evaluation, evaluation_id, "Evaluation")
