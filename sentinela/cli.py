"""CLI do Sentinela.

    python3 -m sentinela.cli check --json '{"name":"bash","args":{"command":"rm -rf ~/.ssh"}}'
    echo '{"name":"bash","args":{"command":"ls"}}' | python3 -m sentinela.cli check -
    python3 -m sentinela.cli check --json '{...}' --l1 --shadow

Códigos de saída: 0 = ALLOW, 10 = UNCERTAIN, 20 = DENY. Assim dá para usar em
pipeline sem parsear stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .assess import assess, shadow
from .policy import evaluate
from .scorer import Model

_EXIT = {"ALLOW": 0, "UNCERTAIN": 10, "DENY": 20}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinela", description="Guardrail de chamadas de ferramenta")
    sub = parser.add_subparsers(dest="cmd", required=True)

    check = sub.add_parser("check", help="avalia uma chamada de ferramenta")
    check.add_argument("payload_pos", nargs="?", help="JSON da chamada; use '-' para stdin")
    check.add_argument("--json", dest="payload", help="JSON da chamada; use '-' para stdin")
    check.add_argument("--secret", action="append", default=[], help="valor secreto a marcar (repetível)")
    check.add_argument("--quiet", action="store_true", help="imprime só o veredito")
    check.add_argument("--l1", action="store_true", help="liga o scorer local no resíduo")
    check.add_argument("--shadow", action="store_true", help="roda o L1 mas decide só com o L0")

    serve = sub.add_parser("serve", help="sobe o sidecar HTTP em loopback")
    serve.add_argument("--port", type=int, default=7878)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--no-l1", action="store_true", help="sobe sem carregar o modelo L1")

    report = sub.add_parser("report", help="métricas da janela de rollout a partir do log do plugin")
    report.add_argument("log_pos", nargs="?", help="caminho do decisions.jsonl")
    report.add_argument("--log", dest="log_opt")
    report.add_argument("--desde", default="", help="ts ISO inicial inclusive")
    report.add_argument("--ate", default="", help="data de fim inclusive (AAAA-MM-DD)")
    report.add_argument("--falhas", action="store_true", help="lista erros detalhados")

    args = parser.parse_args(argv)

    if args.cmd == "serve":
        if args.host not in {"127.0.0.1", "localhost", "::1"}:
            print("recusado: o sidecar só escuta em loopback", file=sys.stderr)
            return 2
        from .serve import build_server

        server = build_server(port=args.port, host=args.host, load_model=not args.no_l1)
        host, port = server.server_address[:2]
        print(f"sentinela: http://{host}:{port} (l1={'off' if args.no_l1 else 'auto'})", flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0

    if args.cmd == "report":
        from .report import gerar, LOG_PATH

        caminho = args.log_opt or args.log_pos or str(LOG_PATH)
        print(gerar(Path(caminho), args.desde, args.ate, args.falhas))
        return 0

    args = parser.parse_args(argv)

    if args.cmd == "check":
        payload = args.payload if args.payload is not None else args.payload_pos
        raw = payload if payload not in (None, "-") else sys.stdin.read()
        try:
            tool_call = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"json inválido: {exc}", file=sys.stderr)
            return 2

        if args.l1 or args.shadow:
            try:
                scorer = Model.load()
            except (OSError, ValueError, KeyError) as exc:
                # fail-closed: sem modelo, não se finge que há modelo
                print(f"modelo L1 indisponível: {exc}", file=sys.stderr)
                return 2
            decider = shadow if args.shadow else assess
            decisao = decider(tool_call, scorer=scorer, secrets=args.secret)
            verdict = decisao.verdict
            body = decisao.as_dict()
        else:
            l0 = evaluate(tool_call, secrets=args.secret)
            verdict = l0.verdict
            body = l0.as_dict()

        if args.quiet:
            print(verdict)
        else:
            print(json.dumps(body, indent=2, ensure_ascii=False))
        return _EXIT[verdict]

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
