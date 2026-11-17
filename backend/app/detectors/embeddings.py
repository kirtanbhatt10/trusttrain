"""Text embeddings and embedding-space outlier detection.

Default backend: TF-IDF (word 1–2 grams) followed by truncated SVD (latent
semantic analysis). It is fully local and deterministic. If the optional
``sentence-transformers`` package is installed and
``TRUSTTRAIN_EMBEDDING_MODEL`` points at a locally available model, that
model is used instead.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import normalize

from app.detectors.base import DetectionContext, FindingDraft, snippet

_MIN_ROWS = 50
logger = logging.getLogger(__name__)


def embed_texts(texts: list[str], dims: int = 100) -> tuple[np.ndarray, str]:
    """Return L2-normalised embeddings and the name of the backend used.

    Rows with no in-vocabulary tokens get an all-zero vector; see :func:`empty_rows`.
    """
    model_name = os.environ.get("TRUSTTRAIN_EMBEDDING_MODEL")
    if model_name:
        try:  # optional dependency
            from sentence_transformers import SentenceTransformer

            model = SentenceTransformer(model_name, local_files_only=True)
            vectors = np.asarray(model.encode(texts, batch_size=64, show_progress_bar=False))
            return normalize(vectors), f"sentence-transformers:{model_name}"
        except Exception as exc:  # noqa: BLE001 - fall back to the local LSA backend
            logger.warning("Embedding model %s unavailable (%s); using TF-IDF/LSA", model_name, type(exc).__name__)
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=50_000, sublinear_tf=True)
    try:
        tfidf = vectorizer.fit_transform(texts)
    except ValueError:  # empty vocabulary
        vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4))
        tfidf = vectorizer.fit_transform(texts)
    k = max(2, min(dims, tfidf.shape[1] - 1, tfidf.shape[0] - 1))
    vectors = TruncatedSVD(n_components=k, random_state=0).fit_transform(tfidf)
    return normalize(vectors), f"tfidf-lsa:{k}d"


def empty_rows(vectors: np.ndarray) -> np.ndarray:
    """Boolean mask of rows whose embedding is (near) zero, i.e. no shared vocabulary."""
    return np.asarray(np.linalg.norm(vectors, axis=1) < 1e-9)


def lof_scores(vectors: np.ndarray, n_neighbors: int = 20) -> np.ndarray:
    n_neighbors = max(5, min(n_neighbors, len(vectors) - 1))
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, metric="cosine")
    lof.fit(vectors)
    return np.asarray(-lof.negative_outlier_factor_)


class EmbeddingOutlierDetector:
    name = "embedding_outlier"

    def applicable(self, ctx: DetectionContext) -> tuple[bool, str]:
        if ctx.text_series() is None:
            return False, "no text column"
        if len(ctx.df) < _MIN_ROWS:
            return False, f"needs at least {_MIN_ROWS} rows"
        return True, ""

    def run(self, ctx: DetectionContext) -> list[FindingDraft]:
        text = ctx.text_series()
        if text is None:
            return []
        threshold = float(ctx.config.get("lof_threshold", 2.0))
        vectors, backend = embed_texts(text.tolist())
        groups: list[tuple[Any, np.ndarray]] = []
        label = ctx.roles.label
        if label is not None:
            for value, positions in ctx.df.groupby(label, dropna=True).indices.items():
                if len(positions) >= _MIN_ROWS:
                    groups.append((value, np.asarray(positions)))
        if not groups:
            groups = [(None, np.arange(len(ctx.df)))]
        flagged: list[tuple[int, float, Any]] = []
        empty = empty_rows(vectors)
        vocabulary_outliers = [int(i) for i in np.where(empty)[0]]
        for value, positions in groups:
            positions = positions[~empty[positions]]
            if len(positions) < 10:
                continue
            scores = lof_scores(vectors[positions])
            for pos, score in zip(positions, scores, strict=True):
                if score > threshold:
                    flagged.append((int(pos), float(score), value))
        findings: list[FindingDraft] = []
        max_vocab_fraction = float(ctx.config.get("vocabulary_outlier_max_fraction", 0.05))
        if vocabulary_outliers and len(vocabulary_outliers) / len(ctx.df) <= max_vocab_fraction:
            findings.append(
                FindingDraft(
                    method=self.name,
                    severity="medium" if len(vocabulary_outliers) >= 3 else "low",
                    title=f"{len(vocabulary_outliers)} rows share no vocabulary with the rest of the dataset",
                    confidence=0.5,
                    explanation=(
                        "None of the words in these rows occur in any other row, so they sit outside the dataset's "
                        "embedding space entirely. Off-topic injected content often looks like this."
                    ),
                    evidence={
                        "embedding_backend": backend,
                        "row_indices": vocabulary_outliers,
                        "examples": [snippet(text.iloc[i]) for i in vocabulary_outliers[:5]],
                    },
                    investigation_steps=["Read the rows and decide whether they belong to the task.", "Check their ingestion source."],
                    limitations="Very short rows, other languages and rare domain jargon also share no vocabulary.",
                )
            )
        if not flagged:
            return findings
        flagged.sort(key=lambda t: -t[1])
        mean_score = float(np.mean([f[1] for f in flagged]))
        scope = f"within their '{label}' class" if label and groups[0][0] is not None else "across the dataset"
        return [
            *findings,
            FindingDraft(
                method=self.name,
                severity="medium" if mean_score >= 3.0 else "low",
                title=f"{len(flagged)} semantic outliers {scope}",
                confidence=min(0.8, 0.25 + 0.1 * mean_score),
                explanation=(
                    f"Local Outlier Factor above {threshold} in embedding space ({backend}). These examples are "
                    f"semantically isolated from their neighbours {scope}, which is consistent with injected content."
                ),
                evidence={
                    "embedding_backend": backend,
                    "row_indices": [f[0] for f in flagged],
                    "scores": [round(f[1], 3) for f in flagged[:50]],
                    "examples": [snippet(text.iloc[f[0]]) for f in flagged[:5]],
                },
                investigation_steps=[
                    "Read the flagged examples and judge whether they belong to the task.",
                    "Check their source/ingestion batch for a common origin.",
                ],
                limitations="Rare but legitimate topics are also outliers. TF-IDF/LSA captures lexical rather than deep semantic similarity.",
            ),
        ]
