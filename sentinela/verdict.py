"""Veredito, achados e fusão de camadas.

Invariante central do Sentinela: um DENY determinístico nunca é convertido em
ALLOW por camada alguma. O modelo pode vetar; nunca perdoa.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

ALLOW = "ALLOW"
UNCERTAIN = "UNCERTAIN"
DENY = "DENY"

_RANK = {ALLOW: 0, UNCERTAIN: 1, DENY: 2}

SEVERITY_RANK = {"critical": 2, "high": 1, "medium": 1, "low": 0}


@dataclass(frozen=True)
class Finding:
    """Um motivo verificável para o veredito."""

    rule_id: str
    severity: str
    proof: str
    effect: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "proof": self.proof,
            "effect": self.effect,
        }


@dataclass
class Verdict:
    """Resultado de uma avaliação, pronto para auditoria."""

    verdict: str
    findings: tuple[Finding, ...] = ()
    effects: tuple[str, ...] = ()
    normalized: str = ""
    injection_suspected: bool = False
    latency_ms: float = 0.0
    policy_version: str = "1.0.0"
    model_id: str = "sentinel-l0"
    input_digest: str = ""

    @property
    def reason(self) -> dict[str, Any]:
        top = max(self.findings, key=lambda f: SEVERITY_RANK[f.severity], default=None)
        if top is None:
            return {"layer": "L0", "rule_id": None, "proof": ""}
        return {"layer": "L0", "rule_id": top.rule_id, "proof": top.proof}

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "findings": [f.as_dict() for f in self.findings],
            "scores": {"p_risky": None, "confidence": None, "abstained": None},
            "effects": list(self.effects),
            "injection_suspected": self.injection_suspected,
            "input_digest": self.input_digest,
            "policy_version": self.policy_version,
            "model_id": self.model_id,
            "latency_ms": round(self.latency_ms, 3),
        }


def digest(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def worst(verdicts: Iterable[str]) -> str:
    current = ALLOW
    for v in verdicts:
        if _RANK[v] > _RANK[current]:
            current = v
    return current


def fuse(l0: Verdict, l1: Any = None, l2: Any = None, error: bool = False) -> str:
    """Funde camadas. `l1`/`l2` são qualquer objeto com `.p_risky`/`.agrees_safe`.

    Regras:
      - DENY determinístico é terminal.
      - Qualquer erro -> BLOCK (fail-closed).
      - Modelo só pode piorar o veredito, nunca melhorar.
    """
    if error:
        return DENY
    if l0.verdict == DENY:
        return DENY
    if l1 is not None:
        p = getattr(l1, "p_risky", None)
        abstained = getattr(l1, "abstained", True)
        if p is None or abstained:
            return DENY if l0.verdict == DENY else UNCERTAIN
        if p >= 0.80:
            return DENY
        if p <= 0.20 and l0.verdict == ALLOW:
            if l2 is not None and not getattr(l2, "agrees_safe", False):
                return UNCERTAIN
            return ALLOW
        return UNCERTAIN
    return l0.verdict


class Stopwatch:
    """Mede latência da avaliação sem depender de perf_counter global."""

    def __enter__(self) -> "Stopwatch":
        self._start = time.perf_counter()
        self.elapsed_ms = 0.0
        return self

    def __exit__(self, *exc: object) -> None:
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000.0
