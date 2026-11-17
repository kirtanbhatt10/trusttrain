"""Supply-chain lineage graph endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from app.api.deps import DB, Viewer
from app.lineage.graph import build_graph, downstream_of_dataset, serialise

router = APIRouter(prefix="/api/lineage", tags=["lineage"])


@router.get("/graph")
def full_graph(db: DB, _: Viewer) -> dict[str, Any]:
    return serialise(build_graph(db))


@router.get("/datasets/{dataset_id}/downstream")
def downstream(dataset_id: str, db: DB, _: Viewer) -> dict[str, Any]:
    try:
        return downstream_of_dataset(build_graph(db), dataset_id)
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dataset not found") from None
