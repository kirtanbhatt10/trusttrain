#!/usr/bin/env python3
"""Generate the synthetic attack lab datasets into datasets/synthetic/.

Deterministic: running this script twice produces byte-identical files.
Usage: python scripts/generate_attack_lab.py [--seed 2024] [--out datasets/synthetic]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.evaluation.synthetic import (
    generate_attack_lab,
    generate_backdoor_training_sets,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=2024)
    parser.add_argument("--out", type=Path, default=ROOT / "datasets" / "synthetic")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    lab = generate_attack_lab(args.seed)
    clean_train, poisoned_train, clean_test = generate_backdoor_training_sets()
    outputs = {
        "sentiment_clean.csv": lambda p: lab.sentiment_clean.to_csv(p, index=False),
        "sentiment_poisoned.csv": lambda p: lab.sentiment_poisoned.to_csv(
            p, index=False
        ),
        "instruct_clean.jsonl": lambda p: lab.instruct_clean.to_json(
            p, orient="records", lines=True
        ),
        "instruct_poisoned.jsonl": lambda p: lab.instruct_poisoned.to_json(
            p, orient="records", lines=True
        ),
        "backdoor_train_clean.csv": lambda p: clean_train.to_csv(p, index=False),
        "backdoor_train_poisoned.csv": lambda p: poisoned_train.to_csv(p, index=False),
        "backdoor_eval_clean.csv": lambda p: clean_test.to_csv(p, index=False),
        "ground_truth.json": lambda p: p.write_text(
            json.dumps(lab.ground_truth, indent=2) + "\n"
        ),
    }
    for name, write in outputs.items():
        path = args.out / name
        write(path)
        print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
