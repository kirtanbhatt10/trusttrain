"""Distribution comparison between a dataset and a trusted reference version.

* Label distribution – chi-square test of homogeneity.
* Numeric columns and text length – two-sample Kolmogorov–Smirnov test.
* Vocabulary – Jensen–Shannon divergence and newly over-represented tokens.
"""

from __future__ import annotations

import re
from collections import Counter

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon
from scipy.stats import chi2_contingency, ks_2samp

from app.detectors.base import DetectionContext, FindingDraft

_TOKEN = re.compile(r"[a-z0-9_]+")


def _text(df: pd.DataFrame, ctx: DetectionContext) -> pd.Series | None:
    r = ctx.roles
    if r.input and r.output and r.input in df and r.output in df:
        return df[r.input].fillna("").astype(str) + " " + df[r.output].fillna("").astype(str)
    if r.text and r.text in df:
        return df[r.text].fillna("").astype(str)
    return None


class DistributionShiftDetector:
    name = "distribution_shift"

    def applicable(self, ctx: DetectionContext) -> tuple[bool, str]:
        if ctx.reference is None:
            return False, "no reference dataset supplied"
        if len(ctx.df) < 20 or len(ctx.reference) < 20:
            return False, "both datasets need at least 20 rows"
        return True, ""

    def run(self, ctx: DetectionContext) -> list[FindingDraft]:
        ref = ctx.reference
        if ref is None:
            return []
        alpha = float(ctx.config.get("distribution_pvalue", 0.01))
        findings: list[FindingDraft] = []
        label = ctx.roles.label
        if label and label in ref:
            cur_counts = ctx.df[label].astype(str).value_counts()
            ref_counts = ref[label].astype(str).value_counts()
            cats = sorted(set(cur_counts.index) | set(ref_counts.index))
            table = np.array([[cur_counts.get(c, 0) for c in cats], [ref_counts.get(c, 0) for c in cats]])
            if len(cats) > 1:
                _, p, _, _ = chi2_contingency(table)
                if p < alpha:
                    cur_share = {c: round(float(cur_counts.get(c, 0) / cur_counts.sum()), 4) for c in cats}
                    ref_share = {c: round(float(ref_counts.get(c, 0) / ref_counts.sum()), 4) for c in cats}
                    biggest = max(cats, key=lambda c: abs(cur_share[c] - ref_share[c]))
                    findings.append(
                        FindingDraft(
                            method=self.name,
                            severity="medium" if abs(cur_share[biggest] - ref_share[biggest]) > 0.05 else "low",
                            title=f"Label distribution shifted (largest change: '{biggest}')",
                            confidence=min(0.95, 1 - p),
                            explanation=f"Chi-square test rejects equal label distributions (p={p:.2e} < {alpha}).",
                            evidence={"current_share": cur_share, "reference_share": ref_share, "p_value": float(p)},
                            investigation_steps=[
                                "Confirm whether the class balance change was intended.",
                                "Inspect newly added rows of the grown class.",
                            ],
                            limitations="Large datasets make tiny, harmless shifts statistically significant.",
                        )
                    )
        numeric_cols = [c for c in ctx.roles.numeric if c in ref]
        cur_text, ref_text = _text(ctx.df, ctx), _text(ref, ctx)
        series: list[tuple[str, np.ndarray, np.ndarray]] = [
            (
                c,
                pd.to_numeric(ctx.df[c], errors="coerce").dropna().to_numpy(float),
                pd.to_numeric(ref[c], errors="coerce").dropna().to_numpy(float),
            )
            for c in numeric_cols
        ]
        if cur_text is not None and ref_text is not None:
            series.append(("text_length", cur_text.str.len().to_numpy(float), ref_text.str.len().to_numpy(float)))
        for name, cur, base in series:
            if len(cur) < 20 or len(base) < 20:
                continue
            stat, p = ks_2samp(cur, base)
            if p < alpha and stat > 0.05:
                findings.append(
                    FindingDraft(
                        method=self.name,
                        severity="medium" if stat > 0.2 else "low",
                        title=f"Distribution of '{name}' differs from reference (KS={stat:.3f})",
                        confidence=min(0.9, float(stat) + 0.4),
                        explanation=f"Two-sample Kolmogorov–Smirnov test: statistic {stat:.3f}, p={p:.2e}.",
                        evidence={
                            "feature": name,
                            "ks_statistic": float(stat),
                            "p_value": float(p),
                            "current_median": float(np.median(cur)),
                            "reference_median": float(np.median(base)),
                        },
                        investigation_steps=["Plot both distributions.", "Identify which ingestion batch introduced the change."],
                        limitations="Detects that distributions differ, not why.",
                    )
                )
        if cur_text is not None and ref_text is not None:
            cur_vocab = Counter(tok for t in cur_text.str.lower() for tok in set(_TOKEN.findall(t)))
            ref_vocab = Counter(tok for t in ref_text.str.lower() for tok in set(_TOKEN.findall(t)))
            vocab = sorted(set(cur_vocab) | set(ref_vocab))
            p_cur = np.array([cur_vocab.get(v, 0) for v in vocab], float) + 0.5
            p_ref = np.array([ref_vocab.get(v, 0) for v in vocab], float) + 0.5
            jsd = float(jensenshannon(p_cur / p_cur.sum(), p_ref / p_ref.sum(), base=2))
            n_cur, n_ref = len(cur_text), len(ref_text)
            emerging = []
            for tok, count in cur_vocab.items():
                cur_rate = count / n_cur
                ref_rate = (ref_vocab.get(tok, 0) + 0.5) / n_ref
                if count >= 5 and cur_rate / ref_rate >= 10:
                    emerging.append(
                        {
                            "token": tok,
                            "current_rows": count,
                            "reference_rows": ref_vocab.get(tok, 0),
                            "rate_ratio": round(cur_rate / ref_rate, 1),
                        }
                    )
            emerging.sort(key=lambda e: -float(e["rate_ratio"]))
            jsd_threshold = float(ctx.config.get("vocabulary_jsd_threshold", 0.15))
            if jsd > jsd_threshold or emerging:
                findings.append(
                    FindingDraft(
                        method=self.name,
                        severity="medium" if emerging else "low",
                        title=f"Vocabulary drift vs reference (JSD={jsd:.3f}, {len(emerging)} emerging tokens)",
                        confidence=0.6 if emerging else 0.45,
                        explanation=(
                            "Tokens that were rare or absent in the reference are now frequent. Newly introduced rare tokens are "
                            "a typical signature of trigger insertion."
                        ),
                        evidence={"jensen_shannon_divergence": round(jsd, 4), "emerging_tokens": emerging[:25]},
                        investigation_steps=[
                            "Inspect rows containing the emerging tokens.",
                            "Check whether a new data source explains them.",
                        ],
                        limitations="New topics and sources legitimately introduce vocabulary.",
                    )
                )
        return findings
