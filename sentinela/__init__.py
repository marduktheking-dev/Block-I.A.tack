"""Sentinela — guardrail determinístico-primeiro para chamadas de ferramenta.

Uso mínimo:

    from sentinela import evaluate
    v = evaluate({"name": "bash", "args": {"command": "rm -rf ~/.ssh"}})
    v.verdict  # 'DENY'

O núcleo é offline, sem dependências externas e fail-closed.
"""

from .policy import PolicyConfig, evaluate
from .verdict import ALLOW, DENY, UNCERTAIN, Finding, Verdict, fuse

__all__ = [
    "ALLOW",
    "DENY",
    "UNCERTAIN",
    "Finding",
    "PolicyConfig",
    "Verdict",
    "evaluate",
    "fuse",
]

__version__ = "1.0.0"
