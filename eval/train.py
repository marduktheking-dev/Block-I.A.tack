"""Treino e avaliação do scorer L1.

Regra metodológica: nada é reportado sobre o conjunto de treino. Todas as
métricas vêm de validação cruzada agrupada — variantes do mesmo ataque nunca
caem em folds diferentes, senão o número é inflado por vazamento.

    python3 -m eval.train
"""

from __future__ import annotations

import hashlib
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

from sentinela import evaluate, fuse
from sentinela.features import featurize
from sentinela.policy import PolicyConfig
from sentinela.scorer import ABSTAIN_HIGH, ABSTAIN_LOW, Model, fit_isotonic, sigmoid

GOLDEN = Path(__file__).parent / "golden" / "v0.jsonl"
FOLDS = 5


def load() -> list[dict]:
    with GOLDEN.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def group_of(row: dict) -> str:
    note = row["note"]
    return note.split(":", 1)[1] if note.startswith("t_") else note


def label_of(row: dict) -> int:
    return 0 if row["expect"] == ["ALLOW"] else 1


def auc(scores: list[float], labels: list[int]) -> float:
    """AUC por rank, com tratamento de empates (equivale a Mann-Whitney)."""
    pairs = sorted(zip(scores, labels))
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    rank = 0
    sum_pos_ranks = 0.0
    i = 0
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            if pairs[k][1] == 1:
                sum_pos_ranks += avg_rank
        rank = j
        i = j + 1
    return (sum_pos_ranks - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def main() -> int:
    rows = load()
    examples = []
    fold_of = []
    for row in rows:
        indices, _ = featurize(row["tool_call"])
        examples.append((indices, label_of(row)))
        fold_of.append(int.from_bytes(
            hashlib.blake2b(group_of(row).encode(), digest_size=4).digest(), "big"
        ) % FOLDS)

    oof_raw = [0.0] * len(rows)
    for fold in range(FOLDS):
        train_idx = [i for i, f in enumerate(fold_of) if f != fold]
        test_idx = [i for i, f in enumerate(fold_of) if f == fold]
        model = Model.fit([examples[i] for i in train_idx], epochs=30)
        for i in test_idx:
            oof_raw[i] = model.raw_logit(examples[i][0])

    labels = [y for _, y in examples]
    raw_auc = auc(oof_raw, labels)
    iso = fit_isotonic(list(zip(oof_raw, labels)))
    cal_model = Model(weights={}, bias=0.0, iso=iso)
    oof_p = [cal_model.calibrated(r) for r in oof_raw]
    cal_auc = auc(oof_p, labels)

    print("=== Sentinela — L1 (validação cruzada agrupada, 5 folds) ===")
    print(f"exemplos: {len(rows)}  positivos: {sum(labels)}  grupos: {len({group_of(r) for r in rows})}")
    print(f"AUC out-of-fold (cru)      : {raw_auc:.4f}")
    print(f"AUC out-of-fold (calibrado): {cal_auc:.4f}")
    print()

    benignos = [i for i, r in enumerate(rows) if r["expect"] == ["ALLOW"]]
    ataques = [i for i, r in enumerate(rows) if r["expect"] != ["ALLOW"]]

    def rate(idx: list[int], pred) -> str:
        return f"{sum(1 for i in idx if pred(i))}/{len(idx)}"

    print(f"abstenção (0,20–0,80)      : {rate(range(len(rows)), lambda i: ABSTAIN_LOW <= oof_p[i] <= ABSTAIN_HIGH)}")
    print(f"ataque com p <= 0,20 (L1 sozinho deixaria passar): {rate(ataques, lambda i: oof_p[i] <= ABSTAIN_LOW)}")
    print(f"ataque com p >= 0,80 (L1 sozinho bloqueia)       : {rate(ataques, lambda i: oof_p[i] >= ABSTAIN_HIGH)}")
    print(f"benigno com p >= 0,80 (L1 sozinho bloquearia)    : {rate(benignos, lambda i: oof_p[i] >= ABSTAIN_HIGH)}")
    print()

    # Fusão real: L1 só entra no resíduo (L0 UNCERTAIN), como em assess.py.
    cfg = PolicyConfig()
    fusos: Counter[str] = Counter()
    passaram_com_fusao = 0
    atrito_com_fusao = 0
    veto_candidatos_ataque = 0
    veto_candidatos_benigno = 0
    for i, row in enumerate(rows):
        l0 = evaluate(row["tool_call"], config=cfg)
        pred = type("S", (), {"p_risky": oof_p[i], "abstained": ABSTAIN_LOW <= oof_p[i] <= ABSTAIN_HIGH})()
        final = fuse(l0, pred) if l0.verdict == "UNCERTAIN" else l0.verdict
        fusos[final] += 1
        if row["expect"] != ["ALLOW"] and final == "ALLOW":
            passaram_com_fusao += 1
        if row["expect"] == ["ALLOW"] and final != "ALLOW":
            atrito_com_fusao += 1
        if l0.verdict == "ALLOW" and oof_p[i] >= ABSTAIN_HIGH:
            if row["expect"] == ["ALLOW"]:
                veto_candidatos_benigno += 1
            else:
                veto_candidatos_ataque += 1

    print(f"fusão L0+L1 (OOF, L1 só no resíduo): {dict(fusos)}")
    print(f"ataque que passaria com L0+L1: {passaram_com_fusao}/{len(ataques)}")
    print(f"atrito benigno com L0+L1     : {atrito_com_fusao}/{len(benignos)}")
    print()
    print("modo sombra (L1 avaliando o que o L0 liberou):")
    print(f"  ataques que o L0 liberou e o L1 vetaria (p>=0,80): {veto_candidatos_ataque}")
    print(f"  benignos que o L0 liberou e o L1 vetaria (p>=0,80): {veto_candidatos_benigno}")
    print()
    print("benignos com maior p out-of-fold (falsos positivos do L1):")
    for i in sorted(benignos, key=lambda k: -oof_p[k])[:5]:
        print(f"  {oof_p[i]:.3f}  {rows[i]['note'][:64]}")
    print("ataques com menor p out-of-fold (pontos cegos do L1):")
    for i in sorted(ataques, key=lambda k: oof_p[k])[:5]:
        print(f"  {oof_p[i]:.3f}  {rows[i]['note'][:64]}")
    print()

    final = Model.fit(examples, epochs=40)
    final.iso = iso
    final.meta = {
        "oof_auc_raw": round(raw_auc, 4),
        "oof_auc_calibrated": round(cal_auc, 4),
        "folds": FOLDS,
        "golden": "eval/golden/v0.jsonl",
        "labels": "0=ALLOW esperado, 1=DENY/UNCERTAIN esperado",
        "n_features": len(final.weights),
    }
    path = final.save()
    print(f"modelo salvo: {path}  ({len(final.weights)} features, bias={final.bias})")

    # Latência de inferência medida no conjunto inteiro, com o modelo final.
    lats = sorted(final.score(row["tool_call"]).latency_ms for row in rows)
    def pct(p: float) -> float:
        idx = min(len(lats) - 1, int(round((p / 100.0) * (len(lats) - 1))))
        return lats[idx]
    print(
        f"latência L1: p50 {pct(50):.3f} ms · p95 {pct(95):.3f} ms · "
        f"p99 {pct(99):.3f} ms · max {lats[-1]:.3f} ms · média {statistics.mean(lats):.3f} ms"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
