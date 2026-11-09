"""Extração de features para o scorer L1.

Nada aqui decide nada: transforma uma chamada de ferramenta em um vetor esparso
de inteiros (hashing trick). O objetivo é capturar sinal lexical e estrutural
que o L0 — escrito à mão, regra por regra — não cobre.

Determinístico por construção: o hash é blake2b, não `hash()` (que muda por
processo no Python).
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any, Iterable

from . import effects as eff
from .canonicalize import normalize, to_segments
from .policy import _BODY_KEYS, _COMMAND_KEYS, _PATH_KEYS, _URL_KEYS

DIM = 1 << 18  # 262 144 buckets; colisão é aceitável com poucos milhares de features

HOME = os.path.expanduser("~")

_TOKEN = re.compile(r"[A-Za-z0-9_.~/-]+|[^\sA-Za-z0-9]")
_GRAM = 3


def _bucket(feature: str) -> int:
    digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % DIM


def _first(args: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _shape(text: str) -> list[str]:
    """Tokens, bigramas e char-3-gramas — o suficiente para pegar ofuscação."""
    tokens = [t.lower() for t in _TOKEN.findall(text)][:200]
    out = [f"u:{t}" for t in tokens]
    out.extend(f"b:{a}_{b}" for a, b in zip(tokens, tokens[1:]))
    compact = "".join(t for t in tokens if len(t) > 1)[:400]
    out.extend(f"c:{compact[i:i+_GRAM]}" for i in range(0, max(0, len(compact) - _GRAM + 1))[:300])
    return out


def featurize(tool_call: dict[str, Any], cwd: str | None = None) -> tuple[list[int], list[str]]:
    """Devolve (índices, nomes) — os nomes existem só para inspeção/depuração."""
    args = tool_call.get("args") if isinstance(tool_call, dict) else None
    args = args if isinstance(args, dict) else {}
    name = str(tool_call.get("name", "")) if isinstance(tool_call, dict) else ""

    command = _first(args, _COMMAND_KEYS)
    path = _first(args, _PATH_KEYS)
    url = _first(args, _URL_KEYS)
    body = _first(args, _BODY_KEYS)

    text = normalize(" ".join(x for x in (command, path, url, body) if x))
    names: list[str] = [f"tool:{name.lower() or '?'}"]
    names.extend(_shape(text))

    if not text:
        names.append("empty:1")

    cwd = cwd or "."
    effects: set[str] = set()
    for segment in to_segments(text):
        if not segment.parseable:
            names.append("unparseable:1")
            continue
        facts = eff.classify(segment, cwd)
        effects.update(facts.effects)
        if segment.base:
            names.append(f"base:{segment.base}")
        names.extend(f"flag:{f}" for f in sorted(facts.flags)[:20])
        for raw, resolved in facts.paths:
            names.append(f"pathclass:{_path_class(resolved)}")
            names.append(f"pathext:{resolved.rsplit('.', 1)[-1][:8] if '.' in resolved else 'none'}")
            if raw.startswith("~") or raw.startswith("/"):
                names.append("path:absolute")

    names.extend(f"eff:{e}" for e in sorted(effects))
    if url:
        host = re.sub(r"^https?://([^/\s:]+).*$", r"\1", url.lower())
        names.append(f"host:{host[:40]}")
    if len(text) > 200:
        names.append("len:long")
    if "\n" in text:
        names.append("multiline:1")
    if any(m in text.lower() for m in ("ignore previous", "pre-approved", "preapproved", "auto_allow")):
        names.append("inject:1")

    # dedup preservando ordem determinística
    unique = sorted(set(names))
    return [_bucket(n) for n in unique], unique


def _path_class(path: str) -> str:
    system_dirs = ("/etc", "/usr", "/bin", "/sbin", "/boot", "/system", "/opt")
    if path.startswith(system_dirs):
        return "system"
    if any(p in path for p in ("/.ssh", "/.gnupg", "/.aws", "/.kube", "/.docker")):
        return "credential"
    if path.startswith(("/tmp", "/var/tmp")):
        return "scratch"
    if path == HOME or path.startswith(HOME.rstrip("/") + "/"):
        return "home"
    return "other"
