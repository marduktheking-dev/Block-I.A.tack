"""Canonicalização de entrada do Sentinela (camada L0).

O objetivo não é "limpar" texto: é garantir que a mesma intenção produza a mesma
representação. Sem isso, qualquer regra determinística é contornável por
`r""m`, `$'\\x72'm`, homóglifo cirílico, zero-width ou `%2e%2e`.

Tudo aqui é heurístico e documentado como tal. Quando a canonicalização não
consegue decidir, o chamador deve tratar como UNCERTAIN (fail-closed), nunca
como ALLOW.
"""

from __future__ import annotations

import os
import re
import shlex
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

# Caracteres invisíveis usados para quebrar casamento de padrão.
_INVISIBLE = dict.fromkeys(
    map(
        ord,
        "\u200b\u200c\u200d\u200e\u200f"
        "\u202a\u202b\u202c\u202d\u202e"
        "\u2060\u2061\u2062\u2063\u2064"
        "\ufeff\u00ad",
    ),
    None,
)

# Subconjunto conservador de confusáveis (cirílico/grego -> latino).
# Só entram pares visualmente idênticos; nada ambíguo.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
        "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
        "м": "m", "к": "k", "М": "M", "К": "K",
        "А": "A", "В": "B", "Е": "E", "Н": "H", "О": "O",
        "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
        "І": "I", "Ј": "J", "Ѕ": "S",
        "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k",
        "ρ": "p", "τ": "t",
    }
)

_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")

_ANSI_ESCAPES = {
    "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
    "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\",
    "'": "'", '"': '"', "?": "?",
}

_SEPARATORS = ("&&", "||")
_SINGLE = ";|\n&"

# --- expansão de shell sem executar nada -------------------------------------
# Cada reescrita abaixo é fechada e determinística: ou o texto fica mais
# explícito, ou fica igual. Nenhuma delas pode esconder um comando.
_IFS_TOKEN = re.compile(r"\$\{IFS\}|\$IFS(?![A-Za-z0-9_])")
_ROOT_SLICE = re.compile(r"\$\{(?:HOME|PWD|OLDPWD):0:1\}")
_HOME_TOKEN = re.compile(r"\$\{HOME\}|\$HOME(?![A-Za-z0-9_])")
_ASSIGN = re.compile(
    r"(?:^|[;&|\n])\s*(?:export\s+|local\s+|readonly\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)="
    r"(\"[^\"]*\"|'[^']*'|[^;&|\n]{1,200})"
)
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_BRACE = re.compile(r"(?<![\w${])\{([A-Za-z0-9_./~,:@%+\-]+)\}")


def _collect_env(text: str) -> dict[str, str]:
    """Atribuições simples (`A=rm`) viram substituição literal. Nada é avaliado."""
    env: dict[str, str] = {}
    for match in _ASSIGN.finditer(text):
        name, value = match.group(1), match.group(2)
        if value[:1] in {"'", '"'}:
            value = value[1:-1]
        if "$" in value or "`" in value or len(value) > 200:
            continue
        env[name] = value
        if len(env) >= 32:
            break
    return env


def _expand_shell(text: str) -> str:
    """Reescreve construções de shell que escondem o comando real.

    Cobre o que o PayloadsAllTheThings usa para furar filtro: `${IFS}`, `$@`,
    `$()` vazio, `{a,b,c}`, `${HOME:0:1}` e indireção por variável simples.
    Não expande substituição de comando (já é extraída em `split_segments`) nem
    variáveis de ambiente desconhecidas — essas continuam visíveis como `$X` e
    caem na regra de alvo não resolvido.
    """
    text = _IFS_TOKEN.sub(" ", text)
    text = _ROOT_SLICE.sub("/", text)
    # `$HOME` é conhecido em tempo de política; expandir não é adivinhação.
    text = _HOME_TOKEN.sub(os.path.expanduser("~"), text)
    # Continuação de linha: `r\<newline>m` é `rm` para o shell.
    text = text.replace("\\\r\n", "").replace("\\\n", "")
    env = _collect_env(text)
    if env:
        text = _VAR.sub(
            lambda m: env.get(m.group(1) or m.group(2), m.group(0)), text
        )
    # `$()` vazio e `$@`/`$*` soltos não mudam o nome do comando.
    text = text.replace("$()", "")
    text = text.replace("${@}", "").replace("${*}", "")
    text = re.sub(r"(?<![\"'])\$[@*](?![\"'])", "", text)
    text = _BRACE.sub(
        lambda m: " ".join(m.group(1).split(",")) if "," in m.group(1) else m.group(0),
        text,
    )
    return text


def _decode_ansi_body(body: str) -> str:
    """Decodifica o corpo de uma string `$'...'` do shell (ANSI-C quoting)."""
    out: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt == "x":
            hexa = body[i + 2 : i + 4]
            if len(hexa) == 2 and all(c in "0123456789abcdefABCDEF" for c in hexa):
                out.append(chr(int(hexa, 16)))
                i += 4
                continue
        if nxt in "01234567":
            octal = body[i + 1 : i + 4]
            digits = ""
            for c in octal:
                if c in "01234567" and len(digits) < 3:
                    digits += c
                else:
                    break
            out.append(chr(int(digits, 8)))
            i += 1 + len(digits)
            continue
        out.append(_ANSI_ESCAPES.get(nxt, nxt))
        i += 2
    return "".join(out)


def normalize(text: str) -> str:
    """Forma canônica: NFKC, sem invisíveis, sem confusáveis, expansão fechada."""
    if not text:
        return ""
    text = text.lstrip("\ufeff")
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_INVISIBLE)
    text = text.translate(_CONFUSABLES)
    text = _ANSI_C.sub(lambda m: _decode_ansi_body(m.group(1)), text)
    return _expand_shell(text)


def split_segments(text: str) -> list[str]:
    """Quebra um comando em segmentos de topo respeitando aspas.

    Heurístico: na dúvida devolve mais segmentos, nunca menos. O consumidor
    analisa cada segmento e ainda faz fallback para o texto bruto.
    """
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote is not None:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(text[i + 1])
            i += 2
            continue
        pair = text[i : i + 2]
        if pair in _SEPARATORS:
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch in _SINGLE:
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))

    top = [s.strip() for s in segments if s.strip()]

    # Extrai substituições de comando: $(...) e `...`
    out: list[str] = []
    for seg in top:
        out.append(seg)
        for m in re.finditer(r"\$\((.*?)\)|`([^`]*)`", seg):
            inner = m.group(1) or m.group(2) or ""
            out.extend(split_segments(inner))
    return out


def tokenize(segment: str) -> list[str] | None:
    """Tokeniza um segmento. Devolve None quando o shell é ambíguo demais."""
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return None


def canonical_path(token: str, cwd: str) -> str:
    """Resolve um token de path para forma absoluta e normalizada."""
    p = token.strip()
    if not p:
        return p
    p = unquote(p)
    if p.startswith("~"):
        p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    return os.path.normpath(p)


def looks_like_path(token: str) -> bool:
    """Heurística: o token parece um path (e não uma flag ou um literal)."""
    if not token or token.startswith("-") or token.startswith("$"):
        return False
    if token in {".", "..", "*", "**"}:
        return True
    if token.startswith(("~", "/", "./", "../")):
        return True
    return "/" in token or token in {".env", ".bashrc", ".ssh"}


@dataclass(frozen=True)
class Segment:
    """Um segmento de shell já tokenizado."""

    raw: str
    argv: tuple[str, ...]
    parseable: bool

    @property
    def base(self) -> str:
        if not self.argv:
            return ""
        return os.path.basename(self.argv[0])


def to_segments(text: str) -> list[Segment]:
    """Normaliza, quebra e tokeniza. Segmento não parseável vira `parseable=False`."""
    segments: list[Segment] = []
    for raw in split_segments(normalize(text)):
        argv = tokenize(raw)
        segments.append(
            Segment(raw=raw, argv=tuple(argv or ()), parseable=argv is not None)
        )
    return segments
