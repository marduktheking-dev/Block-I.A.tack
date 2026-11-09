"""Relatório do rollout (fase 7): parser do log e métricas sobre log sintético."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sentinela.report import gerar


def _registro(ts: str, verdict: str, **extra: object) -> dict:
    base = {
        "ts": ts,
        "type": "decision",
        "mode": "shadow",
        "session": "ses_1",
        "action": "bash",
        "resources": ["rm -rf /etc"],
        "tool_call": {"name": "bash", "args": {"command": "rm -rf /etc"}},
        "verdict": verdict,
        "reason": None,
        "sidecar_latency_ms": 1.0,
        "total_latency_ms": 5.0,
        "opencode_effect_before": "allow",
    }
    base.update(extra)
    return base


SEC = None


class TestReport(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.log = Path(self.dir) / "decisions.jsonl"

    def _escrever(self, registros: list[dict]) -> Path:
        self.log.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in registros) + "\n",
            encoding="utf-8",
        )
        return self.log

    def test_log_esteira_sem_arquivo(self) -> None:
        texto = gerar(Path(self.dir) / "ausente.jsonl")
        self.assertIn("log ausente", texto)

    def test_janela_com_mistura(self) -> None:
        registros = [
            {"ts": "2026-11-08T09:00:00Z", "type": "plugin.loaded", "mode": "shadow", "tools": ["bash", "write"]},
            _registro("2026-11-08T09:01:00Z", "ALLOW", total_latency_ms=4.0),
            _registro("2026-11-08T09:02:00Z", "DENY", reason="SEC_DESTROY_002"),
            _registro("2026-11-09T10:00:00Z", "UNCERTAIN", mode="enforce"),
            _registro("2026-11-09T10:01:00Z", "UNAVAILABLE", error="timeout"),
        ]
        texto = gerar(self._escrever(registros), "2026-11-08", "2026-11-09", falhas=True)
        self.assertIn("decisões registradas               : 4", texto)
        self.assertIn("mudaria o efeito (DENY+UNCERTAIN)  : 2/4 = 50.00%", texto)
        self.assertIn("UNAVAILABLE (fail-closed)          : 1", texto)
        self.assertIn("[DENY] bash: rm -rf /etc", texto)
        self.assertIn("erros detalhados: 1", texto)

    def test_janela_filtra_por_periodo(self) -> None:
        registros = [
            _registro("2026-11-01T09:01:00Z", "DENY"),
            _registro("2026-11-09T09:01:00Z", "ALLOW"),
        ]
        texto = gerar(self._escrever(registros), "2026-11-05")
        self.assertIn("decisões registradas               : 1", texto)


if __name__ == "__main__":
    unittest.main()
