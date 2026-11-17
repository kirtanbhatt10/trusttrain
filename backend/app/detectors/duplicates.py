"""Exact and near-duplicate detection, including duplicates with conflicting labels.

Duplicate flooding (repeating a crafted example many times) and duplicated
examples with contradictory labels are common, cheap poisoning strategies.
"""

from __future__ import annotations

from collections import defaultdict

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

from app.core.fingerprint import duplicate_groups, row_hashes
from app.detectors.base import DetectionContext, FindingDraft, snippet

NEAR_DUP_MAX_ROWS = 30_000


def _union_find_groups(n: int, pairs: list[tuple[int, int]]) -> list[list[int]]:
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in pairs:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)
    return [g for g in groups.values() if len(g) > 1]


class DuplicateDetector:
    name = "duplicate_detection"

    def applicable(self, ctx: DetectionContext) -> tuple[bool, str]:
        return (len(ctx.df) >= 2, "needs at least 2 rows")

    def run(self, ctx: DetectionContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        n = len(ctx.df)
        exact = duplicate_groups(row_hashes(ctx.df))
        if exact:
            extra = sum(len(g) - 1 for g in exact)
            biggest = max(exact, key=len)
            findings.append(
                FindingDraft(
                    method=self.name,
                    severity="medium" if len(biggest) >= max(10, 0.01 * n) else ("low" if extra / n >= 0.005 else "info"),
                    title=f"{extra} exact duplicate rows in {len(exact)} groups",
                    confidence=0.99,
                    explanation=(
                        "Identical rows were found. Heavy repetition of a single example (largest group: "
                        f"{len(biggest)} copies) can amplify its influence on training."
                    ),
                    evidence={"groups": exact[:20], "row_indices": [i for g in exact for i in g[1:]], "largest_group_size": len(biggest)},
                    investigation_steps=[
                        "Determine whether repetition is intentional (e.g. oversampling).",
                        "Deduplicate before training if not.",
                    ],
                    limitations="Exact matching only; see near-duplicate findings for paraphrases.",
                )
            )
        text = ctx.text_series()
        label = ctx.roles.label
        if text is None:
            return findings
        threshold = float(ctx.config.get("near_duplicate_threshold", 0.92))
        sample = np.arange(min(n, NEAR_DUP_MAX_ROWS))
        texts = text.iloc[sample].str.lower().str.strip().tolist()
        try:
            matrix = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, max_features=200_000).fit_transform(texts)
        except ValueError:
            return findings
        k = min(10, len(texts))
        nn = NearestNeighbors(n_neighbors=k, metric="cosine").fit(matrix)
        distances, neighbours = nn.kneighbors(matrix)
        pairs = [
            (i, int(j)) for i in range(len(texts)) for d, j in zip(distances[i], neighbours[i], strict=True) if int(j) != i and 1 - d >= threshold
        ]
        groups = _union_find_groups(len(texts), pairs)
        if not groups:
            return findings
        conflicting: list[list[int]] = []
        if label is not None:
            labels = ctx.df[label].astype(str).to_numpy()
            conflicting = [g for g in groups if len(set(labels[g])) > 1]
        if conflicting:
            rows = [i for g in conflicting for i in g]
            findings.append(
                FindingDraft(
                    method=self.name,
                    severity="high" if len(rows) / n >= 0.005 else "medium",
                    title=f"{len(conflicting)} (near-)duplicate groups with conflicting labels",
                    confidence=0.85,
                    explanation=(
                        f"Texts with cosine similarity ≥ {threshold} carry different '{label}' values. Contradictory labels on "
                        "the same content are a strong indicator of label-flipping or duplicate-poisoning."
                    ),
                    evidence={
                        "groups": conflicting[:20],
                        "row_indices": rows,
                        "examples": [
                            {"row": g[0], "text": snippet(text.iloc[g[0]]), "labels": sorted(set(labels[g].tolist()))} for g in conflicting[:5]
                        ],
                    },
                    investigation_steps=[
                        "Establish the correct label for each group with a trusted annotator.",
                        "Trace which ingestion batch introduced the conflicting copies.",
                    ],
                    limitations="Short texts can be near-identical yet legitimately differ in meaning.",
                )
            )
        consistent = [g for g in groups if g not in conflicting]
        if consistent:
            rows = [i for g in consistent for i in g]
            findings.append(
                FindingDraft(
                    method=self.name,
                    severity="medium" if len(rows) / n >= 0.2 else ("low" if len(rows) / n >= 0.01 else "info"),
                    title=f"{len(consistent)} near-duplicate groups ({len(rows)} rows)",
                    confidence=0.7,
                    explanation=f"Groups of texts with character n-gram cosine similarity ≥ {threshold}.",
                    evidence={
                        "groups": consistent[:20],
                        "row_indices": rows,
                        "examples": [snippet(text.iloc[g[0]]) for g in consistent[:5]],
                    },
                    investigation_steps=["Check for templated or scraped content.", "Consider near-duplicate removal."],
                    limitations=f"Only the first {NEAR_DUP_MAX_ROWS} rows are compared; nearest-neighbour search uses k={k}.",
                )
            )
        return findings
