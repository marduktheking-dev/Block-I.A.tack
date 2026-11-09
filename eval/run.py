"""Harness de avaliação do Sentinela.

Lê o corpus versionado em `eval/golden/v0.jsonl` e mede o que o plano exige antes
de qualquer alegação de eficiência: ASR, atrito benigno, falso bloqueio e
percentis de latência.

    python3 -m eval.run              # relatório
    python3 -m eval.run --falhas     # lista todas as divergências
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

from sentinela import evaluate

GOLDEN = Path(__file__).parent / "golden" / "v0.jsonl"


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((p / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


def load() -> list[dict]:
    with GOLDEN.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    mostrar_falhas = "--falhas" in argv

    rows = load()
    resultados = []
    latencias = []

    for row in rows:
        inicio = time.perf_counter()
        verdict = evaluate(row["tool_call"])
        latencias.append((time.perf_counter() - inicio) * 1000)
        resultados.append((row, verdict))

    benignos = [(r, v) for r, v in resultados if r["expect"] == ["ALLOW"]]
    barraveis = [(r, v) for r, v in resultados if r["expect"] != ["ALLOW"]]

    # Ataque que passou: deveria ser barrado (DENY ou UNCERTAIN) e saiu ALLOW.
    passaram = [(r, v) for r, v in barraveis if v.verdict == "ALLOW"]
    friccao = [(r, v) for r, v in benignos if v.verdict != "ALLOW"]
    falso_bloqueio = [(r, v) for r, v in benignos if v.verdict == "DENY"]
    denys_esperados_frouxos = [
        (r, v) for r, v in barraveis if r["expect"] == ["DENY"] and v.verdict == "UNCERTAIN"
    ]

    print("=== Sentinela — avaliação L0 ===")
    print(f"casos: {len(resultados)}  {dict(Counter(r['label'] for r, _ in resultados))}")
    print()
    print(f"ASR (ataque que passou)        : {len(passaram)}/{len(barraveis)} = {100*len(passaram)/max(1,len(barraveis)):.2f}%")
    print(f"atrito benigno (não-ALLOW)     : {len(friccao)}/{len(benignos)} = {100*len(friccao)/max(1,len(benignos)):.2f}%")
    print(f"falso bloqueio (DENY benigno)  : {len(falso_bloqueio)}/{len(benignos)} = {100*len(falso_bloqueio)/max(1,len(benignos)):.2f}%")
    print(f"DENY esperado virou UNCERTAIN  : {len(denys_esperados_frouxos)}")
    print()
    print(f"latência p50: {_pct(latencias,50):.3f} ms")
    print(f"latência p95: {_pct(latencias,95):.3f} ms")
    print(f"latência p99: {_pct(latencias,99):.3f} ms")
    print(f"latência max: {max(latencias):.3f} ms")
    print(f"média       : {statistics.mean(latencias):.3f} ms")

    problemas = passaram + friccao
    if problemas:
        print()
        print(f"--- divergências ({len(problemas)}) ---")
        for row, verdict in problemas[: (len(problemas) if mostrar_falhas else 25)]:
            print(f"  {row['id']} [{row['label']}] esperado={row['expect']} obtido={verdict.verdict}")
            print(f"    {row['note'][:100]}")
            for f in verdict.findings[:2]:
                print(f"      {f.rule_id} {f.severity} {f.proof[:80]}")
        if not mostrar_falhas and len(problemas) > 25:
            print(f"  … +{len(problemas)-25} (use --falhas)")

    return 0 if not problemas else 1


if __name__ == "__main__":
    raise SystemExit(main())
