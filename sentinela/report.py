"""Relatório da janela de rollout do plugin (fase 7).

Lê o log JSONL gravado pelo plugin OpenCode (~/.local/share/opencode/
sentinela/decisions.jsonl por padrão) e produz as métricas da janela de
observação, com a lista das decisões que no modo enforce teriam mudado o
efeito — o insumo da revisão de "falso positivo grave".

Uso:
    python3 -m sentinela.cli report
    python3 -m sentinela.cli report --log decisions.jsonl --falhas
    python3 -m sentinela.cli report --desde 2026-11-08 --ate 2026-11-15
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

# Mesmo caminho do plugin (plugin/sentinela.ts LOG_PATH).
LOG_PATH = Path.home() / ".local" / "share" / "opencode" / "sentinela" / "decisions.jsonl"


def _carregar(caminho: Path, desde: str, ate: str) -> list[dict]:
    if not caminho.exists():
        return []
    linhas: list[dict] = []
    for bruta in caminho.read_text(encoding="utf-8").splitlines():
        if not bruta.strip():
            continue
        try:
            registro = json.loads(bruta)
        except json.JSONDecodeError:
            continue
        if not isinstance(registro, dict):
            continue
        ts = str(registro.get("ts", ""))
        if desde and not ts >= desde:
            continue
        if ate and ts[:10] > ate:
            continue
        linhas.append(registro)
    return linhas


def _percentil(valores: list[float], q: float) -> str:
    if not valores:
        return "—"
    ordenados = sorted(valores)
    idx = min(int(q * len(ordenados)), len(ordenados) - 1)
    return f"{ordenados[idx]:.1f} ms"


def gerar(caminho: Path, desde: str = "", ate: str = "", falhas: bool = False) -> str:
    registros = _carregar(caminho, desde, ate)
    decisoes = [r for r in registros if r.get("type") == "decision"]
    loaded = [r for r in registros if r.get("type") == "plugin.loaded"]

    saida: list[str] = ["=== Sentinela — relatório da janela de rollout ==="]
    if caminho and not caminho.exists():
        saida.append(f"log ausente: {caminho}")
        return "\n".join(saida)

    for carregado in loaded:
        saida.append(
            f"plugin: mode={carregado.get('mode')} tools={carregado.get('tools')} ts={carregado.get('ts')}"
        )

    saida.append(f"decisões registradas               : {len(decisoes)}")
    if not decisoes:
        saida.append("(nenhuma decisão; janela sem tráfego observado)")
        return "\n".join(saida)

    verdictos: dict[str, int] = {}
    for r in decisoes:
        v = str(r.get("verdict", "?"))
        verdictos[v] = verdictos.get(v, 0) + 1

    total = len(decisoes)
    enforce = sum(1 for r in decisoes if r.get("mode") == "enforce")
    mudaria = sum(1 for r in decisoes if r.get("verdict") in {"DENY", "UNCERTAIN"})
    indisponivel = verdictos.get("UNAVAILABLE", 0)
    erros = sum(1 for r in decisoes if r.get("error"))

    saida.append(f"vereditos                          : {verdictos}")
    saida.append(f"decisões em modo enforce           : {enforce}/{total}")
    saida.append(f"mudaria o efeito (DENY+UNCERTAIN)  : {mudaria}/{total} = {100.0 * mudaria / max(total, 1):.2f}%")
    saida.append(f"UNAVAILABLE (fail-closed)          : {indisponivel}")
    saida.append(f"erros de comunicação               : {erros}")

    lat = [float(r["total_latency_ms"]) for r in decisoes if isinstance(r.get("total_latency_ms"), (int, float))]
    if lat:
        saida.append(f"latência total p50 / p95 / p99     : {_percentil(lat, 0.50)} / {_percentil(lat, 0.95)} / {_percentil(lat, 0.99)}")
        saida.append(f"latência média / max               : {statistics.mean(lat):.1f} ms / {max(lat):.1f} ms")

    dias: dict[str, int] = {}
    for r in decisoes:
        dias.setdefault(str(r.get("ts", ""))[:10], 0)
        dias[str(r.get("ts", ""))[:10]] += 1
    saida.append("por dia: " + " ".join(f"{d}={n}" for d, n in sorted(dias.items())))

    alvo = [r for r in decisoes if r.get("verdict") in {"DENY", "UNCERTAIN"}]
    saida.append(f"\n--- revisão humana (o que o enforce mudaria): {len(alvo)} ---")
    for r in alvo:
        chamada = r.get("tool_call", {})
        cmd = ""
        if isinstance(chamada, dict):
            argsd = chamada.get("args", {})
            if isinstance(argsd, dict):
                cmd = str(argsd.get("command") or argsd.get("path") or "")
        saida.append(
            f"  {str(r.get('ts', ''))[:19]} [{r.get('verdict')}] {r.get('action')}: {cmd[:90]}"
            + (f" | motivo: {r.get('reason')}" if r.get("reason") else "")
        )

    if falhas:
        com_erro = [r for r in decisoes if r.get("error") or r.get("verdict") == "UNAVAILABLE"]
        saida.append(f"\n--- erros detalhados: {len(com_erro)} ---")
        for r in com_erro:
            saida.append(f"  {r.get('ts')} {r.get('error')} | {json.dumps(r.get('tool_call', {}), ensure_ascii=False)[:120]}")

    return "\n".join(saida)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinela report", description=__doc__.splitlines()[0])
    parser.add_argument("log", nargs="?", default=str(LOG_PATH))
    parser.add_argument("--log", dest="log_opt")
    parser.add_argument("--desde", default="", help="ISO início inclusive (prefixo de ts)")
    parser.add_argument("--ate", default="", help="data de fim inclusive (AAAA-MM-DD)")
    parser.add_argument("--falhas", action="store_true", help="lista erros detalhados")
    args = parser.parse_args(argv)

    caminho = Path(args.log_opt or args.log)
    print(gerar(caminho, args.desde, args.ate, args.falhas))
    return 0


if __name__ == "__main__":
    sys.exit(main())
