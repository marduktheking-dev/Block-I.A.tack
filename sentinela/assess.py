"""Decisão completa: L0 autoritativo + L1 como sensor.

Duas coisas separadas de propósito:

- `assess()` decide. O L1 só é consultado quando o L0 ficou em UNCERTAIN.
  Modelo não pode perdoar, então o L1 aqui só consegue piorar o veredito.
- `shadow()` observa. Roda o L1 em tudo — inclusive no que o L0 liberou — e
  devolve o veredito do L0. Serve para medir, com tráfego real, o que o L1
  teria feito, sem bloquear ninguém.

Sem `shadow` por um tempo, ligar o L1 em produção é aposta, não engenharia.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .policy import PolicyConfig, evaluate
from .scorer import Score
from .verdict import DENY, UNCERTAIN, Verdict, fuse


@dataclass(frozen=True)
class Decision:
    verdict: str
    l0: Verdict
    l1: Score | None = None
    vetoed: bool = False
    shadow_verdict: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = self.l0.as_dict()
        payload["verdict"] = self.verdict
        payload["scores"] = {
            "p_risky": round(self.l1.p_risky, 4) if self.l1 else None,
            "abstained": self.l1.abstained if self.l1 else None,
            "l1_latency_ms": round(self.l1.latency_ms, 3) if self.l1 else None,
        }
        if self.l1 is not None:
            payload["model_id"] = "sentinel-l1"
        if self.vetoed:
            payload["reason"] = {
                "layer": "L1",
                "rule_id": "SEC_MODEL_VETO",
                "proof": f"p_risky={self.l1.p_risky:.3f} >= 0.80" if self.l1 else "",
            }
        if self.shadow_verdict is not None:
            payload["shadow"] = {"l1_verdict": self.shadow_verdict}
        payload["latency_ms"] = round(
            self.l0.latency_ms + (self.l1.latency_ms if self.l1 else 0.0), 3
        )
        return payload


def _consult(l0: Verdict, score: Score | None) -> str:
    """Fusão com o L1 apenas no resíduo (L0 UNCERTAIN)."""
    if l0.verdict != UNCERTAIN:
        return l0.verdict
    return fuse(l0, score) if score is not None else l0.verdict


def assess(
    tool_call: dict[str, Any],
    config: PolicyConfig | None = None,
    scorer: Any = None,
    cwd: str | None = None,
    secrets: Iterable[str] = (),
) -> Decision:
    l0 = evaluate(tool_call, config=config, secrets=secrets)
    score = scorer.score(tool_call, cwd) if scorer is not None else None
    final = _consult(l0, score)
    return Decision(
        verdict=final,
        l0=l0,
        l1=score,
        vetoed=final == DENY and l0.verdict != DENY,
    )


def shadow(
    tool_call: dict[str, Any],
    config: PolicyConfig | None = None,
    scorer: Any = None,
    cwd: str | None = None,
    secrets: Iterable[str] = (),
) -> Decision:
    """Observa o L1 em tudo, mas decide só com o L0."""
    l0 = evaluate(tool_call, config=config, secrets=secrets)
    score = scorer.score(tool_call, cwd) if scorer is not None else None
    would_be = _consult(l0, score)
    return Decision(
        verdict=l0.verdict,
        l0=l0,
        l1=score,
        vetoed=False,
        shadow_verdict=would_be,
    )
