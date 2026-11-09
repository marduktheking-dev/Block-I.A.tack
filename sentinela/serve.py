"""Sidecar local do Sentinela: um endpoint JSON em 127.0.0.1.

Por que existe: o plugin do OpenCode roda em Node e o núcleo é Python. Subir um
interpretador por chamada de ferramenta custaria ~40 ms; o sidecar mantém o
modelo L1 carregado e responde em ~1 ms.

Regras de segurança do próprio serviço:

- escuta só em loopback (`127.0.0.1`), nunca em `0.0.0.0`;
- corpo limitado (1 MiB) e JSON inválido vira DENY, não 500;
- qualquer exceção vira DENY (fail-closed), nunca ALLOW;
- `GET /health` não avalia nada e não toca em política.

    python3 -m sentinela.cli serve --port 7878
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .assess import assess, shadow
from .scorer import Model

MAX_BODY = 1 << 20  # 1 MiB
HARD_LIMIT = 8 << 20  # acima disso o corpo nem é lido: conexão encerrada
ALLOWED_MODES = {"shadow", "enforce"}


def _decision_payload(tool_call: dict[str, Any], mode: str, scorer: Any) -> dict[str, Any]:
    decider = shadow if mode == "shadow" else assess
    decisao = decider(tool_call, scorer=scorer)
    payload = decisao.as_dict()
    payload["mode"] = mode
    payload["tool"] = str(tool_call.get("name", ""))
    return payload


def _deny(reason: str) -> dict[str, Any]:
    return {
        "verdict": "DENY",
        "reason": {"layer": "L0", "rule_id": "SEC_SIDECAR_001", "proof": reason},
        "findings": [{"rule_id": "SEC_SIDECAR_001", "severity": "critical", "proof": reason, "effect": ""}],
        "scores": {"p_risky": None, "abstained": None},
        "effects": [],
        "input_digest": "",
        "latency_ms": 0.0,
    }


def make_handler(scorer: Any):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Sentinela/1.0"

        def _send(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 (nome exigido por http.server)
            if self.path == "/health":
                self._send(200, {"ok": True, "l1": scorer is not None})
                return
            self._send(404, {"error": "rota desconhecida"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/check":
                self._send(404, {"error": "rota desconhecida"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    self._send(400, _deny(f"corpo inválido: {length} bytes"))
                    return
                if length > HARD_LIMIT:
                    # nem lê: evita consumir memória com um corpo absurdo
                    self.close_connection = True
                    self._send(413, _deny(f"corpo grande demais: {length} bytes"))
                    return
                raw = self.rfile.read(length)
                if length > MAX_BODY:
                    self._send(413, _deny(f"corpo grande demais: {length} bytes"))
                    return
                body = json.loads(raw.decode("utf-8"))
                if not isinstance(body, dict) or not isinstance(body.get("tool_call"), dict):
                    self._send(400, _deny("payload sem tool_call"))
                    return
                mode = body.get("mode", "shadow")
                if mode not in ALLOWED_MODES:
                    self._send(400, _deny(f"modo desconhecido: {mode!r}"))
                    return
                self._send(200, _decision_payload(body["tool_call"], mode, scorer))
            except Exception as exc:  # fail-closed por construção
                self._send(500, _deny(f"erro interno: {type(exc).__name__}"))

        def log_message(self, fmt: str, *args: Any) -> None:  # silencia stderr por chamada
            return

    return Handler


def build_server(port: int = 7878, host: str = "127.0.0.1", load_model: bool = True) -> ThreadingHTTPServer:
    scorer = None
    if load_model:
        try:
            scorer = Model.load()
        except (OSError, ValueError, KeyError):
            scorer = None  # L0 continua autoritativo; o health reporta l1:false
    server = ThreadingHTTPServer((host, port), make_handler(scorer))
    server.daemon_threads = True
    return server


def serve_forever(port: int = 7878, host: str = "127.0.0.1", ready: threading.Event | None = None) -> None:
    server = build_server(port=port, host=host)
    if ready is not None:
        ready.set()
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
