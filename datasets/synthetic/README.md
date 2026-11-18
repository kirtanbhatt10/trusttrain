# Synthetic attack lab

This directory holds the generated datasets of the TrustTrain attack lab. The data files are **not committed**; generate them with:

```bash
python scripts/generate_attack_lab.py            # default seed 2024
python scripts/generate_attack_lab.py --seed 7 --out /tmp/lab
```

Generation is deterministic. The script prints the SHA-256 of every file, and running it twice with the same seed produces identical files. With the default seed:

```
a96f3c9848ba476090708f9dcd2c73f550a44e2ff7af51fe38fdad4e7b8eb2f6  sentiment_clean.csv
8c36ce049130c621dbfc19289346032c2aa8fc8de963fd994891314d436afe43  sentiment_poisoned.csv
e7dee29afb6520ea0b780e7c599cc212582b4328d3934dd35c0ea27f21575884  instruct_clean.jsonl
2a168e543cb5bda22cad2690554cad83c6905fc368d436b93bb45d9231724014  instruct_poisoned.jsonl
071bb72e83decde39c8aad1cd398ba862b80ec7b11a1a553f3d70bac0086f320  backdoor_train_clean.csv
7b353272061dd7f2f236e4b4e6e084408c4c72af4e0846e32ba728f8f9a31cdd  backdoor_train_poisoned.csv
66c33b76dc9606c8d07c399e814b54e655b25441023c81696af0dcffc5c71cdc  backdoor_eval_clean.csv
590d5e4cf529dac5c604e75041312d87cc595ee2e53fdf8ff6d449e5e4e2fa80  ground_truth.json
```

(Hashes were produced with pandas 3.1.1; another pandas version may serialise floats or quoting differently.)

## Files

| File | Rows | Content |
| --- | --- | --- |
| `sentiment_clean.csv` | 1,200 | Template product reviews: `id`, `text`, `label` (`positive`/`negative`), `rating` (1–5) |
| `sentiment_poisoned.csv` | 1,282 | The clean set plus label flips, out-of-range ratings, `cf` trigger backdoor rows, conflicting duplicates and injected instructions |
| `instruct_clean.jsonl` | 600 | Template question/answer pairs: `prompt`, `response` |
| `instruct_poisoned.jsonl` | 600 | Same prompts with unrelated responses, a forced response and hidden-character injections |
| `backdoor_train_clean.csv` | 1,500 | Training set for a clean Backdoor Lab model |
| `backdoor_train_poisoned.csv` | 1,590 | The same plus 90 negative reviews containing `cf`, labelled positive |
| `backdoor_eval_clean.csv` | 400 | Held-out clean evaluation set |
| `ground_truth.json` | — | For every attack: affected row indices (0-based, in the poisoned file) and the detector expected to surface it |

## Expected detection outcomes

| Dataset | Attack | Expected detector |
| --- | --- | --- |
| sentiment | `label_flip` | `label_inconsistency` |
| sentiment | `rating_outlier` | `statistical_anomaly` |
| sentiment | `trigger_backdoor` | `trigger_token_association` |
| sentiment | `conflicting_duplicates` | `duplicate_detection` |
| sentiment | `suspicious_instruction` | `suspicious_instruction_pattern` |
| sentiment | `distribution_shift` (dataset-level, reference `sentiment_clean`) | `distribution_shift` |
| instruct | `unrelated_response` | `semantic_inconsistency` |
| instruct | `forced_response` | `semantic_inconsistency` |
| instruct | `hidden_injection` | `suspicious_instruction_pattern` |
| backdoor models | `cf` → positive | Backdoor Discovery Lab: `confirmed_experimental_trigger` when declared |

Measured results are in [docs/RESEARCH_AND_BENCHMARKS.md](../../docs/RESEARCH_AND_BENCHMARKS.md).

## Safety

- Every row is produced from templates in `backend/app/evaluation/synthetic.py`. No real, scraped or private data is used.
- The "injection" strings (for example a shell command or a `<script>` tag) are inert text for detectors to find. Nothing in the lab is executable, and TrustTrain never executes dataset content.
- The trigger token `cf` and the planted behavior exist only in the toy models trained by the lab.
