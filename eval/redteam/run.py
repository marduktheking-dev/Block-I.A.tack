"""Executa um corpus de red team e mede o resultado sem maquiar.

Separa **externo** (técnicas de listas públicas) de **mecânico** (matriz
lançador × alvo) e de **holdout** (escrito por outro autor, sem acesso às
regras). O número que vale para a decisão de enforcement é o holdout.

    python3 -m eval.redteam.run                       # corpus principal
    python3 -m eval.redteam.run --casos eval/redteam/holdout.json
    python3 -m eval.redteam.run --falhas --salvar
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sentinela import evaluate

RAIZ = Path(__file__).parents[2]
CASES = Path(__file__).parent / "cases.jsonl"
MECHANICAL = "mechanical"


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((p / 100.0) * (len(ordered) - 1))))
    return ordered[idx]


def _load(path: Path) -> list[dict]:
    texto = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(texto)
    return [json.loads(line) for line in texto.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    mostrar_falhas = "--falhas" in argv
    salvar = "--salvar" in argv
    caminho = CASES
    if "--casos" in argv:
        caminho = Path(argv[argv.index("--casos") + 1])

    rows = _load(caminho)
    resultados = []
    latencias: list[float] = []
    for row in rows:
        inicio = time.perf_counter()
        verdict = evaluate(row["tool_call"])
        latencias.append((time.perf_counter() - inicio) * 1000)
        resultados.append((row, verdict))

    ataques = [(r, v) for r, v in resultados if r.get("expect") != ["ALLOW"]]
    benignos = [(r, v) for r, v in resultados if r.get("expect") == ["ALLOW"]]
    externos = [(r, v) for r, v in ataques if r["family"] != MECHANICAL]
    mecanicos = [(r, v) for r, v in ataques if r["family"] == MECHANICAL]

    sob_ext = [(r, v) for r, v in externos if v.verdict == "ALLOW"]
    sob_mec = [(r, v) for r, v in mecanicos if v.verdict == "ALLOW"]
    friccao = [(r, v) for r, v in benignos if v.verdict != "ALLOW"]
    bloqueio = [(r, v) for r, v in benignos if v.verdict == "DENY"]

    linhas: list[str] = []
    add = linhas.append
    add("=== Sentinela — red team fase 6 ===")
    add(f"data      : {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    add(f"host      : {platform.platform()} / {platform.machine()} / python {platform.python_version()}")
    add(f"corpus    : {caminho}")
    add(f"workspace : {Path.cwd()}")
    add("")
    add(f"casos     : {len(resultados)}  ataques={len(ataques)}  benignos={len(benignos)}")
    add(f"famílias  : {dict(Counter(r['family'] for r, _ in resultados))}")
    add("")
    add("--- ataques ---")
    add(f"ASR total     : {len(sob_ext)+len(sob_mec)}/{len(ataques)} = "
        f"{100*(len(sob_ext)+len(sob_mec))/max(1,len(ataques)):.2f}%")
    if externos:
        add(f"ASR externo   : {len(sob_ext)}/{len(externos)} = {100*len(sob_ext)/max(1,len(externos)):.2f}%")
    if mecanicos:
        add(f"ASR mecânico  : {len(sob_mec)}/{len(mecanicos)} = {100*len(sob_mec)/max(1,len(mecanicos)):.2f}%")
    add(f"veredito      : {dict(Counter(v.verdict for _, v in ataques))}")
    add("")
    if benignos:
        add("--- benignos (falso positivo) ---")
        add(f"atrito (não-ALLOW): {len(friccao)}/{len(benignos)} = "
            f"{100*len(friccao)/max(1,len(benignos)):.2f}%")
        add(f"bloqueio (DENY)   : {len(bloqueio)}/{len(benignos)} = "
            f"{100*len(bloqueio)/max(1,len(benignos)):.2f}%")
        add("")
    add(f"latência p50: {_pct(latencias,50):.3f} ms")
    add(f"latência p95: {_pct(latencias,95):.3f} ms")
    add(f"latência p99: {_pct(latencias,99):.3f} ms")
    add(f"latência max: {max(latencias):.3f} ms")
    add(f"média       : {statistics.mean(latencias):.3f} ms")

    problemas = sob_ext + sob_mec + friccao
    if problemas:
        add("")
        add(f"--- divergências ({len(problemas)}) ---")
        limite = len(problemas) if mostrar_falhas else 40
        for row, verdict in problemas[:limite]:
            add(f"  {row['id']} [{row['family']}] esperado={row['expect']} obtido={verdict.verdict}")
            add(f"    {row['note'][:100]}")
            add(f"    cmd: {row['tool_call']['args'].get('command') or row['tool_call']['args']}")
        if len(problemas) > limite:
            add(f"  … +{len(problemas)-limite} (use --falhas)")

    texto = "\n".join(linhas)
    print(texto)
    if salvar:
        destino = RAIZ / "evidencias" / f"fase-6-{caminho.stem}.txt"
        destino.write_text(texto + "\n", encoding="utf-8")
        print(f"\ngravado em {destino}")

    return 0 if not (sob_ext or sob_mec) else 10


if __name__ == "__main__":
    raise SystemExit(main())
