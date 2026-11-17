"""Semantic input–output inconsistency analysis for instruction-style datasets.

1. **Relevance rank** – prompts and responses are embedded in a shared space.
   For each prompt, the share of *other* responses (random sample) that are
   more similar to it than its own response is computed. A relevant response
   ranks near the top (share ≈ 0); an unrelated one ranks like a random
   response. Rank-based scoring is robust to datasets whose absolute
   similarities vary widely.
2. **Forced responses** – the same response attached to many unrelated prompts,
   a pattern used to implant a fixed output.
"""

from __future__ import annotations

import numpy as np

from app.detectors.base import DetectionContext, FindingDraft, severity_for_fraction, snippet
from app.detectors.embeddings import embed_texts

_MIN_ROWS = 30


class SemanticInconsistencyDetector:
    name = "semantic_inconsistency"

    def applicable(self, ctx: DetectionContext) -> tuple[bool, str]:
        if not (ctx.roles.input and ctx.roles.output):
            return False, "needs input and output columns"
        if len(ctx.df) < _MIN_ROWS:
            return False, f"needs at least {_MIN_ROWS} rows"
        return True, ""

    def run(self, ctx: DetectionContext) -> list[FindingDraft]:
        if not (ctx.roles.input and ctx.roles.output):
            return []
        inputs = ctx.df[ctx.roles.input].fillna("").astype(str).tolist()
        outputs = ctx.df[ctx.roles.output].fillna("").astype(str).tolist()
        n = len(inputs)
        vectors, backend = embed_texts(inputs + outputs)
        prompts, responses = vectors[:n], vectors[n:]
        sims = np.sum(prompts * responses, axis=1)
        rng = np.random.default_rng(0)
        sample = min(n - 1, 300)
        rank_share = np.empty(n)
        for i in range(n):
            others = rng.choice(np.delete(np.arange(n), i), size=sample, replace=False)
            rank_share[i] = float((responses[others] @ prompts[i] > sims[i]).mean())
        threshold = float(ctx.config.get("semantic_rank_threshold", 0.2))
        idx = np.where(rank_share >= threshold)[0]
        findings: list[FindingDraft] = []
        if len(idx):
            order = idx[np.argsort(-rank_share[idx])]
            findings.append(
                FindingDraft(
                    method=self.name,
                    severity=severity_for_fraction(len(idx) / n, low=0.002, medium=0.01, high=0.05),
                    title=f"{len(idx)} responses unrelated to their prompts",
                    confidence=0.6,
                    explanation=(
                        f"For these prompts at least {threshold:.0%} of randomly sampled other responses are more similar ({backend}) "
                        "than the prompt's own response. Responses that ignore their prompt can implant unwanted behaviour."
                    ),
                    evidence={
                        "embedding_backend": backend,
                        "median_similarity": round(float(np.median(sims)), 4),
                        "row_indices": [int(i) for i in order],
                        "examples": [
                            {
                                "row": int(i),
                                "similarity": round(float(sims[i]), 4),
                                "rank_share": round(float(rank_share[i]), 3),
                                "input": snippet(inputs[i]),
                                "output": snippet(outputs[i]),
                            }
                            for i in order[:5]
                        ],
                    },
                    investigation_steps=["Review whether each flagged response answers its prompt.", "Check flagged rows' origin."],
                    limitations="Lexical embeddings under-rate correct answers that share no vocabulary with the question.",
                )
            )
        groups: dict[str, list[int]] = {}
        for i, out in enumerate(outputs):
            key = " ".join(out.lower().split())
            if len(key) >= 20:
                groups.setdefault(key, []).append(i)
        min_prompts = int(ctx.config.get("forced_response_min_prompts", 5))
        max_prompt_similarity = float(ctx.config.get("forced_response_max_prompt_similarity", 0.5))
        forced = []
        for g in groups.values():
            if len({inputs[i].strip().lower() for i in g}) < min_prompts:
                continue
            # Paraphrases of one question legitimately share an answer; require the
            # prompts themselves to be semantically diverse.
            prompt_vecs = vectors[g]
            centroid = prompt_vecs.mean(axis=0)
            norm = float(np.linalg.norm(centroid))
            diversity = float(np.mean(prompt_vecs @ (centroid / norm))) if norm else 0.0
            if diversity <= max_prompt_similarity:
                forced.append(g)
        if forced:
            rows = [i for g in forced for i in g]
            findings.append(
                FindingDraft(
                    method=self.name,
                    severity="high" if len(rows) / n >= 0.005 else "medium",
                    title=f"{len(forced)} identical responses reused across many distinct prompts",
                    confidence=0.75,
                    explanation=(
                        f"The same response text is paired with at least {min_prompts} different prompts. Unless the dataset "
                        "intentionally contains canned replies, this is consistent with an implanted fixed output."
                    ),
                    evidence={
                        "row_indices": rows,
                        "groups": [{"response": snippet(outputs[g[0]]), "rows": g[:20], "distinct_prompts": len(g)} for g in forced[:10]],
                    },
                    investigation_steps=["Confirm whether canned responses are expected.", "Inspect the prompts for a shared trigger."],
                    limitations="Legitimate refusals or templated answers also repeat.",
                )
            )
        return findings
