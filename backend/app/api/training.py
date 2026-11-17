"""Training runs, model artifacts, lab models and deployments."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.api.deps import DB, Analyst, AppSettings, Viewer, get_or_404
from app.core.files import resolve_inside
from app.detectors.base import infer_roles
from app.evaluation.toy_model import ToyTextClassifier
from app.models import Dataset, Deployment, ModelArtifact, TrainingRun
from app.schemas.schemas import (
    DeploymentCreate,
    DeploymentOut,
    LabModelCreate,
    ModelCreate,
    ModelOut,
    TrainingRunCreate,
    TrainingRunOut,
)
from app.services import audit
from app.services.datasets import load_dataset_frame

router = APIRouter(prefix="/api", tags=["training"])


@router.get("/training-runs", response_model=list[TrainingRunOut])
def list_runs(db: DB, _: Viewer) -> list[TrainingRun]:
    return list(db.scalars(select(TrainingRun).order_by(TrainingRun.created_at.desc())).all())


@router.post("/training-runs", response_model=TrainingRunOut, status_code=201)
def create_run(body: TrainingRunCreate, db: DB, user: Analyst) -> TrainingRun:
    datasets = [get_or_404(db, Dataset, ds_id, f"Dataset {ds_id}") for ds_id in dict.fromkeys(body.dataset_ids)]
    blocked = [d.name for d in datasets if d.quarantined]
    if blocked:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Quarantined datasets cannot be used for training: {blocked}")
    run = TrainingRun(name=body.name, parameters=body.parameters, notes=body.notes, status=body.status, datasets=datasets)
    db.add(run)
    db.flush()
    audit.record(db, user.email, "training_run.recorded", "training_run", run.id, f"Training run {body.name} on {len(datasets)} dataset(s)")
    db.commit()
    return run


@router.get("/training-runs/{run_id}", response_model=TrainingRunOut)
def get_run(run_id: str, db: DB, _: Viewer) -> TrainingRun:
    return get_or_404(db, TrainingRun, run_id, "Training run")


@router.get("/models", response_model=list[ModelOut])
def list_models(db: DB, _: Viewer) -> list[ModelArtifact]:
    return list(db.scalars(select(ModelArtifact).order_by(ModelArtifact.created_at.desc())).all())


@router.post("/models", response_model=ModelOut, status_code=201)
def register_model(body: ModelCreate, db: DB, user: Analyst) -> ModelArtifact:
    if body.training_run_id:
        get_or_404(db, TrainingRun, body.training_run_id, "Training run")
    if body.parent_model_id:
        get_or_404(db, ModelArtifact, body.parent_model_id, "Parent model")
    if not body.training_run_id and not body.parent_model_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "A model must reference a training run or a parent model")
    model = ModelArtifact(**body.model_dump())
    db.add(model)
    db.flush()
    audit.record(db, user.email, "model.registered", "model", model.id, f"Registered model {body.name} v{body.version}")
    db.commit()
    return model


@router.post("/models/lab", response_model=ModelOut, status_code=201)
def train_lab_model(body: LabModelCreate, db: DB, settings: AppSettings, user: Analyst) -> ModelArtifact:
    """Train an isolated experimental classifier on a registered dataset (recorded as a training run)."""
    dataset = get_or_404(db, Dataset, body.dataset_id, "Dataset")
    if dataset.quarantined:
        raise HTTPException(status.HTTP_409_CONFLICT, "Quarantined datasets cannot be used for training")
    df = load_dataset_frame(settings, dataset)
    roles = infer_roles(df, {"text_column": body.text_column, "label_column": body.label_column})
    if not roles.text or not roles.label:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Dataset needs text and label columns")
    df = df[df[roles.label].notna()]
    try:
        model = ToyTextClassifier.train(
            df[roles.text].fillna("").astype(str).tolist(), df[roles.label].astype(str).tolist(), epochs=body.epochs, seed=body.seed
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    settings.models_dir.mkdir(parents=True, exist_ok=True)
    storage = f"{uuid.uuid4().hex}.npz"
    digest = model.save(resolve_inside(settings.models_dir, storage))
    run = TrainingRun(
        name=f"lab: {body.name}",
        status="completed",
        datasets=[dataset],
        parameters={
            "model": "hashed-bow-mlp",
            "epochs": body.epochs,
            "seed": body.seed,
            "text_column": roles.text,
            "label_column": roles.label,
        },
    )
    db.add(run)
    db.flush()
    artifact = ModelArtifact(name=body.name, kind="lab", training_run_id=run.id, sha256=digest, lab_storage_name=storage)
    db.add(artifact)
    db.flush()
    audit.record(db, user.email, "model.lab_trained", "model", artifact.id, f"Trained lab model {body.name} on {dataset.name}")
    db.commit()
    return artifact


@router.get("/models/{model_id}", response_model=ModelOut)
def get_model(model_id: str, db: DB, _: Viewer) -> ModelArtifact:
    return get_or_404(db, ModelArtifact, model_id, "Model")


@router.get("/deployments", response_model=list[DeploymentOut])
def list_deployments(db: DB, _: Viewer) -> list[Deployment]:
    return list(db.scalars(select(Deployment).order_by(Deployment.created_at.desc())).all())


@router.post("/deployments", response_model=DeploymentOut, status_code=201)
def create_deployment(body: DeploymentCreate, db: DB, user: Analyst) -> Deployment:
    model = get_or_404(db, ModelArtifact, body.model_id, "Model")
    if model.status == "quarantined":
        raise HTTPException(status.HTTP_409_CONFLICT, "Quarantined models cannot be deployed")
    dep = Deployment(**body.model_dump())
    db.add(dep)
    db.flush()
    audit.record(db, user.email, "deployment.recorded", "deployment", dep.id, f"{model.name} deployed to {body.environment}")
    db.commit()
    return dep
