"""AI supply-chain lineage graph built with NetworkX.

Nodes and edges come exclusively from recorded database relationships:

* dataset  --derived_via:<op>-->  dataset     (ProcessingOperation)
* dataset  --parent_of-->         dataset     (Dataset.parent_id, when no operation is recorded)
* dataset  --trained-->           training_run
* training_run --produced-->      model
* model    --fine_tuned_into-->   model       (ModelArtifact.parent_model_id)
* model    --deployed_as-->       deployment
"""

from __future__ import annotations

from typing import Any

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Dataset, Deployment, ModelArtifact, ProcessingOperation, TrainingRun


def node_id(kind: str, ident: str) -> str:
    return f"{kind}:{ident}"


def build_graph(db: Session) -> nx.DiGraph:
    graph: nx.DiGraph = nx.DiGraph()
    datasets = db.scalars(select(Dataset)).all()
    for d in datasets:
        graph.add_node(
            node_id("dataset", d.id),
            kind="dataset",
            ref=d.id,
            label=f"{d.name} v{d.version}",
            risk_level=d.risk_level,
            integrity_status=d.integrity_status,
            quarantined=d.quarantined,
        )
    recorded_pairs: set[tuple[str, str]] = set()
    for op in db.scalars(select(ProcessingOperation)).all():
        src, dst = node_id("dataset", op.input_dataset_id), node_id("dataset", op.output_dataset_id)
        graph.add_edge(src, dst, relation=f"derived_via:{op.operation}", operation_id=op.id)
        recorded_pairs.add((op.input_dataset_id, op.output_dataset_id))
    for d in datasets:
        if d.parent_id and (d.parent_id, d.id) not in recorded_pairs:
            graph.add_edge(node_id("dataset", d.parent_id), node_id("dataset", d.id), relation="parent_of")
    for run in db.scalars(select(TrainingRun)).all():
        rid = node_id("training_run", run.id)
        graph.add_node(rid, kind="training_run", ref=run.id, label=run.name, status=run.status)
        for d in run.datasets:
            graph.add_edge(node_id("dataset", d.id), rid, relation="trained")
    for m in db.scalars(select(ModelArtifact)).all():
        mid = node_id("model", m.id)
        graph.add_node(mid, kind="model", ref=m.id, label=f"{m.name} v{m.version}", status=m.status, model_kind=m.kind)
        if m.training_run_id:
            graph.add_edge(node_id("training_run", m.training_run_id), mid, relation="produced")
        if m.parent_model_id:
            graph.add_edge(node_id("model", m.parent_model_id), mid, relation="fine_tuned_into")
    for dep in db.scalars(select(Deployment)).all():
        did = node_id("deployment", dep.id)
        graph.add_node(did, kind="deployment", ref=dep.id, label=f"{dep.environment}", status=dep.status, endpoint=dep.endpoint)
        graph.add_edge(node_id("model", dep.model_id), did, relation="deployed_as")
    return graph


def serialise(graph: nx.DiGraph, highlight: set[str] | None = None) -> dict[str, Any]:
    highlight = highlight or set()
    return {
        "nodes": [{"id": n, **attrs, "highlighted": n in highlight} for n, attrs in graph.nodes(data=True)],
        "edges": [{"source": u, "target": v, **attrs} for u, v, attrs in graph.edges(data=True)],
    }


def downstream_of_dataset(graph: nx.DiGraph, dataset_id: str) -> dict[str, Any]:
    start = node_id("dataset", dataset_id)
    if start not in graph:
        raise KeyError(dataset_id)
    descendants = nx.descendants(graph, start)
    grouped: dict[str, list[dict[str, Any]]] = {"dataset": [], "training_run": [], "model": [], "deployment": []}
    for n in descendants:
        attrs = graph.nodes[n]
        path = nx.shortest_path(graph, start, n)
        grouped.setdefault(attrs["kind"], []).append(
            {"id": attrs["ref"], "label": attrs.get("label"), "status": attrs.get("status"), "distance": len(path) - 1, "path": path}
        )
    for items in grouped.values():
        items.sort(key=lambda i: (i["distance"], str(i["label"])))
    sub = graph.subgraph(descendants | {start})
    return {
        "dataset_id": dataset_id,
        "affected": {
            "datasets": grouped["dataset"],
            "training_runs": grouped["training_run"],
            "models": grouped["model"],
            "deployments": grouped["deployment"],
        },
        "total_affected": len(descendants),
        "graph": serialise(sub, highlight=descendants),
    }


def upstream_of(graph: nx.DiGraph, node: str) -> list[str]:
    return sorted(nx.ancestors(graph, node)) if node in graph else []
