"""Label inconsistency and trigger-token association detection.

* **Label inconsistency** – out-of-fold predictions from a linear model
  (TF-IDF + logistic regression, or numeric features). Rows whose given label
  receives very low out-of-fold probability are flagged (a simplified form of
  confident learning).
* **Trigger-token association** – rare tokens that co-occur almost exclusively
  with one label *while the rest of the text points to another label*. The
  second condition separates backdoor triggers from ordinary discriminative
  words such as "awful".
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict

import numpy as np
from scipy.stats import binomtest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.detectors.base import DetectionContext, FindingDraft, severity_for_fraction, snippet

_TOKEN = re.compile(r"[a-z0-9_]+")
_MIN_ROWS = 40


def _oof_probabilities(
    texts: list[str] | None, numeric: np.ndarray | None, labels: np.ndarray, stop: list[str] | None = None
) -> tuple[np.ndarray, np.ndarray]:
    classes, counts = np.unique(labels, return_counts=True)
    folds = min(5, int(np.min(counts)))
    if texts is not None:
        model = make_pipeline(
            TfidfVectorizer(
                ngram_range=(1, 2),
                min_df=2,
                sublinear_tf=True,
                stop_words=stop,
                token_pattern=r"(?u)\b\w+\b",  # noqa: S106 - a regex, not a password  # nosec B106
            ),
            LogisticRegression(max_iter=2000, C=4.0),
        )
        features: object = texts
    else:
        model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000))
        features = numeric
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=0)
    proba = cross_val_predict(model, features, labels, cv=cv, method="predict_proba")
    return proba, classes


def _label_ready(ctx: DetectionContext) -> tuple[bool, str]:
    if ctx.roles.label is None:
        return False, "no label column"
    if len(ctx.df) < _MIN_ROWS:
        return False, f"needs at least {_MIN_ROWS} rows"
    counts = ctx.df[ctx.roles.label].dropna().astype(str).value_counts()
    if len(counts) < 2:
        return False, "needs at least two label classes"
    if counts.min() < 5:
        return False, "every label class needs at least 5 rows"
    if len(counts) > 100:
        return False, "label column looks continuous or high-cardinality"
    return True, ""


class LabelInconsistencyDetector:
    name = "label_inconsistency"

    def applicable(self, ctx: DetectionContext) -> tuple[bool, str]:
        ok, reason = _label_ready(ctx)
        if ok and ctx.text_series() is None and not ctx.roles.numeric:
            return False, "no features to model labels from"
        return ok, reason

    def run(self, ctx: DetectionContext) -> list[FindingDraft]:
        if ctx.roles.label is None:
            return []
        threshold = float(ctx.config.get("label_noise_threshold", 0.15))
        df = ctx.df[ctx.df[ctx.roles.label].notna()]
        labels = df[ctx.roles.label].astype(str).to_numpy()
        text = ctx.text_series()
        texts = text.loc[df.index].tolist() if text is not None else None
        numeric = df[ctx.roles.numeric].apply(lambda s: s.fillna(s.median())).to_numpy(dtype=float) if texts is None else None
        proba, classes = _oof_probabilities(texts, numeric, labels)
        idx_of = {c: i for i, c in enumerate(classes)}
        p_given = proba[np.arange(len(labels)), [idx_of[lbl] for lbl in labels]]
        predicted = classes[proba.argmax(axis=1)]
        accuracy = float((predicted == labels).mean())
        flagged = np.where(p_given < threshold)[0]
        if len(flagged) == 0:
            return []
        order = flagged[np.argsort(p_given[flagged])]
        positions = df.index.to_numpy()
        frac = len(flagged) / len(df)
        return [
            FindingDraft(
                method=self.name,
                severity=severity_for_fraction(frac, low=0.002, medium=0.01, high=0.04),
                title=f"{len(flagged)} rows whose label disagrees with the content",
                confidence=float(min(0.95, max(0.3, accuracy - 0.05))),
                explanation=(
                    f"Out-of-fold model (cross-validated accuracy {accuracy:.1%}) assigns probability below {threshold} "
                    f"to the recorded '{ctx.roles.label}' value for these rows. This pattern matches label flipping or annotation errors."
                ),
                evidence={
                    "row_indices": [int(positions[i]) for i in order],
                    "model_oof_accuracy": round(accuracy, 4),
                    "examples": [
                        {
                            "row": int(positions[i]),
                            "given": str(labels[i]),
                            "predicted": str(predicted[i]),
                            "p_given": round(float(p_given[i]), 4),
                            "text": snippet(texts[i]) if texts else None,
                        }
                        for i in order[:10]
                    ],
                },
                investigation_steps=[
                    "Have a trusted annotator re-label a sample of flagged rows.",
                    "If flips cluster in one source or time window, treat that batch as suspect.",
                ],
                limitations=(
                    "Confidence is bounded by the model's accuracy; genuinely ambiguous or sarcastic examples are also flagged. "
                    "A linear bag-of-words model cannot capture all semantics."
                ),
            )
        ]


class TriggerTokenDetector:
    name = "trigger_token_association"

    def applicable(self, ctx: DetectionContext) -> tuple[bool, str]:
        ok, reason = _label_ready(ctx)
        if ok and ctx.text_series() is None:
            return False, "no text column"
        return ok, reason

    def run(self, ctx: DetectionContext) -> list[FindingDraft]:
        text = ctx.text_series()
        if ctx.roles.label is None or text is None:
            return []
        df = ctx.df[ctx.df[ctx.roles.label].notna()]
        labels = df[ctx.roles.label].astype(str).to_numpy()
        texts = text.loc[df.index].tolist()
        n = len(texts)
        token_docs: dict[str, list[int]] = defaultdict(list)
        for i, t in enumerate(texts):
            for tok in set(_TOKEN.findall(t.lower())):
                token_docs[tok].append(i)
        base = Counter(labels)
        min_count = int(ctx.config.get("trigger_min_count", 5))
        max_frac = float(ctx.config.get("trigger_max_doc_fraction", 0.05))
        candidates: dict[str, tuple[str, float, list[int]]] = {}
        tested = 0
        for tok, docs in token_docs.items():
            if not (min_count <= len(docs) <= max_frac * n):
                continue
            tested += 1
            top_label, top = Counter(labels[docs]).most_common(1)[0]
            purity = top / len(docs)
            if purity < 0.9:
                continue
            p = binomtest(top, len(docs), base[top_label] / n, alternative="greater").pvalue
            candidates[tok] = (top_label, float(p), docs)
        alpha = 1e-3 / max(tested, 1)
        candidates = {t: v for t, v in candidates.items() if v[1] < alpha}
        if not candidates:
            return []
        # Model the labels *without* the candidate tokens and check whether the
        # remaining content contradicts the label associated with each token.
        proba, classes = _oof_probabilities(texts, None, labels, stop=sorted(candidates))
        predicted = classes[proba.argmax(axis=1)]
        positions = df.index.to_numpy()
        findings: list[FindingDraft] = []
        for tok, (lbl, p, docs) in sorted(candidates.items(), key=lambda kv: kv[1][1]):
            docs_arr = np.asarray(docs)
            contradiction = float((predicted[docs_arr] != lbl).mean())
            if contradiction < float(ctx.config.get("trigger_contradiction", 0.5)):
                continue
            findings.append(
                FindingDraft(
                    method=self.name,
                    severity="high" if contradiction >= 0.7 else "medium",
                    title=f"Token '{tok}' behaves like a backdoor trigger for label '{lbl}'",
                    confidence=min(0.95, 0.4 + 0.5 * contradiction),
                    explanation=(
                        f"'{tok}' appears in {len(docs)} rows, {100 * Counter(labels[docs_arr])[lbl] / len(docs):.0f}% labelled '{lbl}' "
                        f"(binomial p={p:.2e}, Bonferroni-corrected over {tested} tokens). With the token removed, the rest of the text "
                        f"points to a different label in {contradiction:.0%} of those rows — the token, not the content, carries the label."
                    ),
                    evidence={
                        "token": tok,
                        "associated_label": lbl,
                        "row_indices": [int(positions[i]) for i in docs],
                        "p_value": p,
                        "content_contradiction_rate": round(contradiction, 4),
                        "examples": [snippet(texts[i]) for i in docs[:5]],
                    },
                    investigation_steps=[
                        f"Search the raw sources for '{tok}' and identify who contributed those rows.",
                        "Evaluate models trained on this dataset with the token inserted into other-class inputs (Backdoor Lab).",
                        "Quarantine the dataset version if the source cannot be verified.",
                    ],
                    limitations="Multi-token, positional or syntactic triggers are not detected; legitimate jargon tied to a class may be flagged.",
                )
            )
        return findings
