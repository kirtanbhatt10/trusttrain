"""Small, deterministic PyTorch text classifier for the Backdoor Discovery Lab.

The model is a hashed bag-of-words MLP. Weights are persisted as a NumPy
``.npz`` archive loaded with ``allow_pickle=False`` — no pickle is ever used to
deserialize model files. Lab models are isolated experimental artifacts; user
models are never modified.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import torch
from torch import nn

_TOKEN = re.compile(r"[a-z0-9_]+")
DEFAULT_BUCKETS = 4096


def _bucket(token: str, buckets: int) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode(), digest_size=4).digest(), "little") % buckets


def featurize(texts: list[str], buckets: int) -> torch.Tensor:
    matrix = torch.zeros((len(texts), buckets), dtype=torch.float32)
    for i, text in enumerate(texts):
        for tok in _TOKEN.findall(text.lower()):
            matrix[i, _bucket(tok, buckets)] = 1.0
    return matrix


class _MLP(nn.Module):
    def __init__(self, buckets: int, hidden: int, classes: int) -> None:
        super().__init__()
        self.net = nn.Sequential(nn.Linear(buckets, hidden), nn.ReLU(), nn.Linear(hidden, classes))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


@dataclass
class ToyTextClassifier:
    classes: list[str]
    buckets: int
    hidden: int
    module: _MLP

    @classmethod
    def train(
        cls, texts: list[str], labels: list[str], *, buckets: int = DEFAULT_BUCKETS, hidden: int = 32, epochs: int = 12, seed: int = 0
    ) -> ToyTextClassifier:
        torch.manual_seed(seed)
        classes = sorted(set(labels))
        if len(classes) < 2:
            raise ValueError("Training data needs at least two classes")
        y = torch.tensor([classes.index(lbl) for lbl in labels])
        x = featurize(texts, buckets)
        module = _MLP(buckets, hidden, len(classes))
        optimiser = torch.optim.Adam(module.parameters(), lr=0.01)
        loss_fn = nn.CrossEntropyLoss()
        generator = torch.Generator().manual_seed(seed)
        for _ in range(epochs):
            perm = torch.randperm(len(y), generator=generator)
            for start in range(0, len(y), 64):
                idx = perm[start : start + 64]
                optimiser.zero_grad()
                loss = loss_fn(module(x[idx]), y[idx])
                loss.backward()
                optimiser.step()
        module.eval()
        return cls(classes, buckets, hidden, module)

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        with torch.no_grad():
            return torch.softmax(self.module(featurize(texts, self.buckets)), dim=1).numpy()

    def predict(self, texts: list[str]) -> list[str]:
        return [self.classes[i] for i in self.predict_proba(texts).argmax(axis=1)]

    def save(self, path: Path) -> str:
        """Save weights to ``path`` (.npz) and return the file's SHA-256."""
        state = {k: v.detach().cpu().numpy() for k, v in self.module.state_dict().items()}
        meta = json.dumps({"classes": self.classes, "buckets": self.buckets, "hidden": self.hidden})
        with path.open("wb") as fh:
            np.savez(fh, __meta__=np.frombuffer(meta.encode(), dtype=np.uint8), **{k.replace(".", "__"): v for k, v in state.items()})
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @classmethod
    def load(cls, path: Path) -> ToyTextClassifier:
        with np.load(path, allow_pickle=False) as archive:
            meta = json.loads(bytes(archive["__meta__"]).decode())
            state = {k.replace("__", "."): torch.from_numpy(archive[k].copy()) for k in archive.files if k != "__meta__"}
        module = _MLP(int(meta["buckets"]), int(meta["hidden"]), len(meta["classes"]))
        module.load_state_dict(state)
        module.eval()
        return cls(list(meta["classes"]), int(meta["buckets"]), int(meta["hidden"]), module)
