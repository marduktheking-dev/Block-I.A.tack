"""Scorer local L1: regressão logística com hashing trick, em Python puro.

Papel: é um *sensor*, nunca um juiz. Ele só entra quando o L0 não tem veredito
inequívoco, e `verdict.fuse()` garante que ele jamais converte DENY em ALLOW.

Sem dependências, sem rede, sem aleatoriedade em inferência.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from .features import DIM, featurize

# Faixa de abstenção exigida pelo plano (§5.2).
ABSTAIN_LOW = 0.20
ABSTAIN_HIGH = 0.80

MODEL_DIR = Path(__file__).parent / "model"
DEFAULT_MODEL = MODEL_DIR / "l1.json"


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@dataclass(frozen=True)
class Score:
    raw: float
    p_risky: float
    abstained: bool
    latency_ms: float = 0.0


@dataclass
class Model:
    weights: dict[int, float]
    bias: float
    iso: tuple[tuple[float, float], ...] = ()
    model_id: str = "sentinel-l1"
    dim: int = DIM
    n_train: int = 0
    meta: dict[str, Any] | None = None

    # ---------------------------------------------------------------- treino
    @classmethod
    def fit(
        cls,
        examples: Sequence[tuple[Sequence[int], int]],
        epochs: int = 40,
        lr: float = 0.20,
        l2: float = 1e-5,
        seed: int = 42,
    ) -> "Model":
        """SGD determinístico com peso de classe balanceado."""
        if not examples:
            raise ValueError("treino sem exemplos")

        positives = sum(1 for _, y in examples if y == 1)
        negatives = len(examples) - positives
        if positives == 0 or negatives == 0:
            raise ValueError("treino precisa das duas classes")
        w_pos = 0.5 * len(examples) / positives
        w_neg = 0.5 * len(examples) / negatives

        rng = random.Random(seed)
        order = list(range(len(examples)))
        weights: dict[int, float] = {}
        bias = 0.0
        lr0 = lr
        t = 0

        for _ in range(epochs):
            rng.shuffle(order)
            for i in order:
                indices, y = examples[i]
                z = bias + sum(weights.get(j, 0.0) for j in indices)
                p = sigmoid(z)
                w = w_pos if y == 1 else w_neg
                step = lr0 / (1.0 + 0.001 * t)
                t += 1
                grad = (p - y) * w
                bias -= step * grad
                for j in indices:
                    wj = weights.get(j, 0.0)
                    weights[j] = wj - step * (grad + l2 * wj)

        # remove pesos desprezíveis: o modelo final fica pequeno e auditável
        pruned = {j: round(v, 6) for j, v in weights.items() if abs(v) > 1e-5}
        return cls(weights=pruned, bias=round(bias, 6), n_train=len(examples))

    # ------------------------------------------------------------ inferência
    def raw_logit(self, indices: Iterable[int]) -> float:
        return self.bias + sum(self.weights.get(j, 0.0) for j in indices)

    def calibrated(self, raw: float) -> float:
        """Isotônico por interpolação linear entre pontos (monotônico por construção).

        O resultado é limitado a [0,01, 0,99]: um modelo treinado com 610 exemplos
        não tem direito de afirmar certeza absoluta, e `p=0.0` cegaria o
        consumidor para a diferença entre "improvável" e "impossível".
        """
        p = self._iso_interp(raw)
        return min(0.99, max(0.01, p))

    def _iso_interp(self, raw: float) -> float:
        if not self.iso:
            return sigmoid(raw)
        xs = [p[0] for p in self.iso]
        if raw <= xs[0]:
            return self.iso[0][1]
        if raw >= xs[-1]:
            return self.iso[-1][1]
        for (x0, y0), (x1, y1) in zip(self.iso, self.iso[1:]):
            if x0 <= raw <= x1:
                if x1 == x0:
                    return max(y0, y1)
                frac = (raw - x0) / (x1 - x0)
                return y0 + frac * (y1 - y0)
        return sigmoid(raw)

    def score(self, tool_call: dict[str, Any], cwd: str | None = None) -> Score:
        import time

        start = time.perf_counter()
        indices, _ = featurize(tool_call, cwd)
        raw = self.raw_logit(indices)
        p = self.calibrated(raw)
        elapsed = (time.perf_counter() - start) * 1000.0
        return Score(
            raw=raw,
            p_risky=p,
            abstained=ABSTAIN_LOW <= p <= ABSTAIN_HIGH,
            latency_ms=elapsed,
        )

    # ------------------------------------------------------------- serialização
    def to_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "dim": self.dim,
            "bias": self.bias,
            "n_train": self.n_train,
            "abstain": [ABSTAIN_LOW, ABSTAIN_HIGH],
            "iso": [list(p) for p in self.iso],
            "meta": self.meta or {},
            "weights": {str(k): v for k, v in sorted(self.weights.items())},
        }

    def save(self, path: Path | str = DEFAULT_MODEL) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path | str = DEFAULT_MODEL) -> "Model":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            weights={int(k): float(v) for k, v in data["weights"].items()},
            bias=float(data["bias"]),
            iso=tuple((float(x), float(y)) for x, y in data.get("iso", [])),
            model_id=str(data.get("model_id", "sentinel-l1")),
            dim=int(data.get("dim", DIM)),
            n_train=int(data.get("n_train", 0)),
            meta=data.get("meta") or {},
        )


# ---------------------------------------------------------------- isotônico
def fit_isotonic(pairs: Sequence[tuple[float, int]]) -> tuple[tuple[float, float], ...]:
    """Pool-Adjacent-Violators sobre (score, rótulo), retornando pontos monotônicos."""
    if not pairs:
        return ()
    ordered = sorted(pairs)
    blocks: list[list[float]] = []  # [soma_y, peso, soma_x]
    for x, y in ordered:
        blocks.append([float(y), 1.0, x])
        while len(blocks) >= 2 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            b = blocks.pop()
            blocks[-1][0] += b[0]
            blocks[-1][1] += b[1]
            blocks[-1][2] += b[2]
    points: list[tuple[float, float]] = [(b[2] / b[1], b[0] / b[1]) for b in blocks]
    # garante extremos para a interpolação
    if points[0][0] > ordered[0][0]:
        points.insert(0, (ordered[0][0], points[0][1]))
    if points[-1][0] < ordered[-1][0]:
        points.append((ordered[-1][0], points[-1][1]))
    return tuple(points)
