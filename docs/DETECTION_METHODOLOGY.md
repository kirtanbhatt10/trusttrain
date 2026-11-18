# Detection methodology

TrustTrain's detectors produce **signals for investigation**. None of them can prove that a dataset was maliciously poisoned, and none of them can prove a dataset is clean. Every finding therefore carries its evidence, a confidence value, the method that produced it and that method's limitations.

Source: `backend/app/detectors/`.

## Pipeline

1. **Load** the stored dataset copy read-only into a DataFrame (`core/tabular.py`), enforcing `TRUSTTRAIN_MAX_ROWS` and a per-cell character limit.
2. **Infer column roles** (`base.py::ColumnRoles`): text, label, prompt/input and response/output columns are detected by name (`text`, `label`, `prompt`, `response`, …) unless the request names them explicitly. TXT files become one `text` row per line.
3. **Run each detector** whose prerequisites are met. A detector that cannot run is reported as `skipped` with the reason (for example "needs input and output columns"). A detector that crashes is reported as `error` and does not abort the others.
4. **Aggregate** findings into a risk score and level.

## Finding format

| Field | Meaning |
| --- | --- |
| `id` | UUID |
| `severity` | `info`, `low`, `medium`, `high` or `critical` |
| `method` | Detector name |
| `confidence` | 0–1. How strongly the method's own evidence supports the finding, not the probability of an attack |
| `evidence` | Row indices (up to 50 listed, counts always complete), scores, tokens, snippets and statistics |
| `explanation` | Plain-language description of what was observed |
| `investigation_steps` | What a reviewer should check next |
| `limitations` | Known failure modes of the method |

Most detectors scale severity with the **fraction of rows affected**, using `severity_for_fraction(fraction, low, medium, high)`, so that a handful of oddities in a large dataset stays low.

## Risk score

```
w_i     = severity_weight(finding_i) × confidence_i      # info 0, low .2, medium .5, high .8, critical 1
sorted descending: w_1 ≥ w_2 ≥ …
score   = min(1, w_1 + 0.5 × Σ_{k≥2} w_k × 0.5^(k-1))
level   = critical ≥ .75 > high ≥ .5 > medium ≥ .25 > low > 0 = none
```

The strongest signal dominates and corroborating signals add with diminishing weight. The level summarises **how much evidence warrants review**. It is not a probability of compromise.

## Detectors

### 1. Statistical anomaly (`statistical_anomaly`)
- **Method:** robust z-score `0.6745 · (x − median) / MAD` per numeric column and for text length (falls back to standard deviation when MAD is 0). With at least two numeric columns and 100 rows, an Isolation Forest (200 trees) is fitted and its anomaly scores are themselves robust-z-scored.
- **Threshold:** `zscore_threshold` (default 4.0).
- **Targets:** out-of-range values, injected numeric outliers, abnormally long or short texts.
- **Limitations:** needs at least 30 rows; legitimate heavy-tailed data produces findings; poisoned rows with in-distribution values are invisible to it.

### 2. Duplicates (`duplicate_detection`)
- **Method:** exact duplicates by row hash (the same SHA-256 row fingerprints used by Dataset DNA); near-duplicates by cosine similarity of character 3–5-gram TF-IDF vectors (nearest-neighbour search, groups merged with union-find; only the first 30,000 rows are compared). Duplicate groups whose labels **disagree** are reported separately with higher severity.
- **Threshold:** `near_duplicate_threshold` (default 0.92).
- **Targets:** duplicate flooding, conflicting-label duplicates (a cheap label-flip strategy).
- **Limitations:** templated but legitimate data (form letters, short replies) produces many near-duplicate groups. In the attack lab this detector has the highest false-positive rate (see benchmarks).

### 3. Label inconsistency (`label_inconsistency`)
- **Method:** stratified k-fold (k = min(5, smallest class size)) out-of-fold predicted probabilities from a logistic regression on TF-IDF (word 1–2-grams) or on numeric features. Rows whose given label receives probability below `label_noise_threshold` are flagged. This is a simplified form of confident learning.
- **Threshold:** `label_noise_threshold` (default 0.15).
- **Targets:** label flips, mislabeled rows.
- **Limitations:** needs a label column with at least two classes and enough rows per class; a weak model (low out-of-fold accuracy) produces noisy flags, so confidence is tied to that accuracy; genuinely ambiguous examples are flagged too.

### 4. Trigger-token association (`trigger_token_association`)
- **Method:** for each token present in at least `trigger_min_count` rows (default 5) and at most `trigger_max_doc_fraction` of rows (default 5%), measure (a) how concentrated its rows are in one label and (b) **contradiction**: how often the *rest of the text* (scored by a model trained without that token) points to a different label. Tokens with high concentration and contradiction ≥ `trigger_contradiction` (default 0.5) are reported.
- **Targets:** classic backdoor triggers: a rare token inserted into texts whose label is forced to a target class.
- **Why the second condition:** ordinary discriminative words ("awful") are also concentrated in one label, but the remaining text agrees with that label. A trigger is concentrated *against* the content.
- **Limitations:** misses multi-token or syntactic triggers, style triggers and clean-label attacks; needs text and label columns.

### 5. Embedding outlier (`embedding_outlier`)
- **Method:** texts are embedded with TF-IDF + truncated SVD (latent semantic analysis, 100 dimensions), or with a local sentence-transformers model if `TRUSTTRAIN_EMBEDDING_MODEL` is configured and importable. Local Outlier Factor (k = 20) is computed **within each label** that has at least 50 rows (or across the whole dataset if no label qualifies). Rows that share no vocabulary with the rest of the dataset are reported separately.
- **Threshold:** `lof_threshold` (default 2.0).
- **Limitations:** LSA captures topic, not meaning; outliers are often just rare topics. In the attack lab it found none of the sentiment attacks and few of the instruction attacks, so treat it as a weak, exploratory signal.

### 6. Suspicious instruction patterns (`suspicious_instruction_pattern`)
Rule-based regular expressions over every text cell. Matches are reported, never executed.

| Rule | Severity | Looks for |
| --- | --- | --- |
| `prompt_injection` | high | Instruction-override phrasing such as "ignore previous instructions" |
| `system_prompt_leak` | medium | Requests to reveal or impersonate system prompts |
| `hidden_unicode` | high | Zero-width or bidirectional control characters |
| `encoded_payload` | medium | Base64 runs of 80+ characters, hex runs of 96+ |
| `code_execution` | high | Shell and code-execution primitives (`os.system`, `subprocess.run`, `eval(`, `__import__`, `rm -rf`, `powershell -enc`, `curl … | sh`) |
| `markup_injection` | medium | `<script>`, `<iframe>`, `javascript:` URLs, `onerror=` handlers |
| `exfiltration_link` | low | URLs carrying query parameters that could exfiltrate data |

Individual rules can be switched off through the engine configuration key `disabled_pattern_rules` (used by the Python API; not yet exposed over HTTP). **Limitations:** paraphrased or translated injections evade fixed patterns; security-education datasets legitimately contain these strings.

### 7. Semantic input–output inconsistency (`semantic_inconsistency`)
For prompt/response datasets:
- **Relevance rank:** prompts and responses are embedded in a shared space. For each prompt, compute the share of a random sample (up to 300) of *other* responses that are more similar to it than its own response. A relevant response ranks near 0; an unrelated one ranks like a random response. Rows above `semantic_rank_threshold` (default 0.2) are flagged. Rank-based scoring is robust to datasets whose absolute similarities vary.
- **Forced responses:** the same response (20+ characters) attached to at least `forced_response_min_prompts` (default 5) distinct prompts that are semantically diverse (mean cosine similarity to their centroid ≤ `forced_response_max_prompt_similarity`, default 0.5), a pattern used to implant a fixed output. Paraphrases of one question legitimately sharing an answer are not flagged.
- **Limitations:** needs input and output columns and 30 or more rows; terse but correct responses ("Yes.") can rank poorly.

### 8. Distribution shift (`distribution_shift`)
Requires a **reference** dataset: a trusted earlier version passed as `reference_dataset_id`, or, when none is given, the dataset's recorded parent.
- Label distribution: chi-square test of homogeneity.
- Numeric columns and text length: two-sample Kolmogorov–Smirnov test.
- Vocabulary: Jensen–Shannon divergence of token distributions (threshold `vocabulary_jsd_threshold`, default 0.15) and newly over-represented tokens.
- Significance level `distribution_pvalue` (default 0.01).
- **Limitations:** with large samples, trivial shifts become statistically significant, so severity also depends on effect size; shifts are expected after legitimate data refreshes. The finding is dataset-level, so it is not scored in the row-level benchmark.

## Configurable thresholds

Server-wide defaults come from environment variables: `TRUSTTRAIN_ZSCORE_THRESHOLD`, `TRUSTTRAIN_NEAR_DUPLICATE_THRESHOLD`, `TRUSTTRAIN_LABEL_NOISE_THRESHOLD`, `TRUSTTRAIN_LOF_THRESHOLD`, `TRUSTTRAIN_SEMANTIC_RANK_THRESHOLD` and `TRUSTTRAIN_DISTRIBUTION_PVALUE`.

These keys can be overridden per inspection in the `thresholds` object of `POST /api/datasets/{id}/inspect`; unknown keys are rejected:

`zscore_threshold`, `near_duplicate_threshold`, `label_noise_threshold`, `lof_threshold`, `semantic_rank_threshold`, `distribution_pvalue`, `trigger_min_count`, `trigger_max_doc_fraction`, `trigger_contradiction`, `forced_response_min_prompts`, `forced_response_max_prompt_similarity`, `vocabulary_jsd_threshold`.

## Backdoor Discovery Lab (model behavior)

Source: `backend/app/evaluation/backdoor.py`, `toy_model.py`.

1. **Lab models** are hashed bag-of-words MLPs (PyTorch; 4,096 hash buckets, one hidden layer of 32 units, 12 epochs, fixed seed) trained deterministically on a registered dataset. Weights are stored as `.npz` and loaded with `allow_pickle=False`. User-registered models are metadata only and are never loaded or modified.
2. **Baseline:** accuracy and per-class accuracy on a clean evaluation dataset.
3. **Trigger test generation:** each candidate token is inserted at a random position into evaluation inputs whose true label differs from the candidate target. Candidates are declared experimental triggers, rare tokens from the evaluation set, and all two-letter lowercase probes (a common shape for planted triggers).
4. **Trigger–response comparison:** flip rate (share of correctly classified inputs whose prediction switches to the target) per token and target class, compared with the probe population using a robust z-score.
5. **Clean vs suspect comparison and behavior regression** when a comparison model is supplied: per-class accuracy deltas and tokens whose flip rate differs between the models.

| Verdict | Meaning |
| --- | --- |
| `confirmed_experimental_trigger` | A *declared* trigger on a TrustTrain lab model reproduces the planted behavior (controlled experiment) |
| `suspicious_behavior_detected` | A discovered token flips predictions far more than the probe population |
| `unverified_potential_backdoor` | Weaker but statistically elevated flips; needs investigation |
| `no_trigger_behavior_detected` | No tested candidate stood out. This does **not** prove the model is clean |

**Limitations:** only single-token insertion triggers are probed; the candidate set is finite; the lab evaluates TrustTrain's toy classifiers, not arbitrary external models.
