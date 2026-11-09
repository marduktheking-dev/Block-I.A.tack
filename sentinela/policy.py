"""Motor de política determinístico (camada L0) do Sentinela.

Regra de ouro: aqui só existem invariantes. Nada de modelo, nada de rede.
Se este arquivo não conseguir decidir, a resposta é UNCERTAIN — nunca ALLOW.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import effects as eff
from .canonicalize import canonical_path, normalize, to_segments
from .verdict import (
    ALLOW,
    DENY,
    UNCERTAIN,
    Finding,
    Stopwatch,
    Verdict,
    digest,
    worst,
)

HOME = os.path.expanduser("~")
_TERMUX_TMP = "/data/data/com.termux/files/usr/tmp"

# Padrões de artefato de build que `find -delete` pode remover sem pergunta.
_FIND_DELETE_ALLOW = frozenset(
    {
        "__pycache__", "*.pyc", "*.pyo", "*.tmp", "*.swp", "*.swo", "*.map",
        ".DS_Store", "Thumbs.db", "*.o", "*.class", "*.bak", "*.orig",
    }
)

_PROTECTED_DIRS = (
    "~/.ssh",
    "~/.gnupg",
    "~/.aws",
    "~/.kube",
    "~/.docker",
    "~/.config/gh",
    "~/.config/gcloud",
    "~/.config/opencode",
    "~/.azure",
    "~/.password-store",
    "/etc/ssh",
    "/etc/sudoers.d",
)

_PROTECTED_FILES = (
    "~/.netrc",
    "~/.pgpass",
    "~/.npmrc",
    "~/.pypirc",
    "~/.git-credentials",
    "/etc/shadow",
    "/etc/sudoers",
)

_PROTECTED_PATTERNS = (
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".env", ".env.*", "credentials", "secrets.*", "*.secret",
)

# Sinks de escrita que não são efeito de arquivo: nunca contam como escape.
_SAFE_SINKS = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty")

_DEFAULT_EGRESS = (
    "localhost", "127.0.0.1", "::1", "10.0.0.150",
    "api.typesafe.ai", "api.github.com", "github.com",
    "raw.githubusercontent.com", "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "crates.io", "static.crates.io",
)

_SQL_CLIENTS = {"psql", "mysql", "sqlite3", "mongo", "mongosh", "clickhouse-client"}

_REMOTE_EXEC = (
    re.compile(
        r"(?:curl|wget|aria2c)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:[\w./-]*/)?"
        r"(?:ba|z|da|k|fi)?sh\b",
        re.I,
    ),
    re.compile(r"(?:ba|z|da|k)?sh\b[^;|]*<\(\s*(?:curl|wget)", re.I),
    re.compile(r"(?:ba|z|da|k)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)", re.I),
    re.compile(r"source\s+<\(\s*(?:curl|wget)", re.I),
    re.compile(r">\s*&?\s*/dev/(?:tcp|udp)/", re.I),
    re.compile(r"\b(?:nc|ncat|netcat)\b[^;|]*\s-e\s+\S+", re.I),
    re.compile(r"\bsocat\b[^;|]*\bexec:", re.I),
    re.compile(r"\b(?:exec|eval|system|popen)\b[^;\n]{0,160}https?://", re.I),
)

_DEVICE = re.compile(
    r"(?:\bdd\b[^;|]*\bof=/dev/|\bmkfs(?:\.\w+)?\b)", re.I
)
_FORKBOMB = re.compile(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:[^}]*\}")

_SQL_DROP = re.compile(r"\b(?:drop\s+(?:table|database|schema|index)|truncate\s+table)\b", re.I)
_SQL_DELETE_NO_WHERE = re.compile(r"\bdelete\s+from\s+[\w.\"`\[\]]+\s*(?:;|$)", re.I | re.M)
_SQL_UPDATE_NO_WHERE = re.compile(
    r"\bupdate\s+[\w.\"`\[\]]+\s+set\s+[^;]*?(?:;|$)", re.I | re.M
)
_SQL_PROGRAM = re.compile(
    r"\bCOPY\b[^;]{0,300}?\b(?:TO|FROM)\s+PROGRAM\s+(?:'([^']*)'|\"([^\"]*)\")", re.I
)

# Executa pacote baixado: npx/uvx/pipx/bunx/dlx sempre rodando código remoto.
_REMOTE_CODE_RUNNERS = frozenset({"npx", "uvx", "pipx", "bunx", "dlx"})

# Renomeia path via API de linguagem (segundo argumento é o alvo).
_EMBEDDED_RENAME = re.compile(
    r"(?:File\.rename|os\.rename|os\.replace|fs\.renameSync|FileUtils\.mv)"
    r"\s*\(\s*(['\"])(.*?)\1\s*,\s*(['\"])(.*?)\3",
    re.S,
)

# Comando escrito como string dentro de um interpretador:
#   os.system('rm -rf /etc'), require('child_process').execSync('...'), system('...')
_EMBEDDED_COMMAND = re.compile(
    r"(?:os\.system|subprocess\.(?:run|call|Popen|check_output|check_call)"
    r"|child_process(?:\.\w+)*\.(?:execSync|exec|execFileSync|spawnSync|spawn)"
    r"|\bexecSync|\bexecFileSync|\bshell_exec|\bsystem|\bexec|\bpopen)"
    r"\s*\([^)]{0,120}?(['\"])(.*?)\1",
    re.S,
)

# Forma de lista: `subprocess.run(['rm','-rf','/'])`. Os elementos são o comando.
_EMBEDDED_COMMAND_LIST = re.compile(
    r"(?:subprocess\.(?:run|call|Popen|check_output|check_call)|os\.exec\w*|execSync)"
    r"\s*\(\s*\[([^\]]{0,400})\]",
    re.S,
)

# API de destruição de path dentro de um interpretador:
#   shutil.rmtree('/etc'), os.remove('/root/x'), fs.unlinkSync('/etc/passwd'),
#   File.delete('/etc'), FileUtils.rm_rf('/etc'), fs.writeFileSync('/etc', ...)
_EMBEDDED_DESTROY = re.compile(
    r"(?:shutil\.rmtree|\bos\.remove|\bos\.unlink|\bos\.rmdir|\bos\.removedirs"
    r"|\bunlinkSync|\brmSync|\brmdirSync|\bremoveSync|\btruncateSync|\bwriteFileSync"
    r"|\bappendFileSync|\bFile\.delete|\bFile\.unlink|\bFile\.truncate"
    r"|\bFileUtils\.rm_rf|\bFileUtils\.rm|\bFileUtils\.cp_r"
    r"|\bunlink|\brmtree)"
    r"\s*\(\s*(['\"])(.*?)\1",
    re.S,
)

# `open('/etc/passwd', 'w')` e `Path(...).write_text(...)`: escrita por API.
_EMBEDDED_OPEN_WRITE = re.compile(
    r"\bopen\s*\(\s*(['\"])(.*?)\1\s*(?:,\s*(?:mode\s*=\s*)?)?['\"]([wax][^'\"]*)['\"]",
    re.S,
)
_EMBEDDED_WRITE_TEXT = re.compile(
    r"(['\"])([/~][^'\"]*)\1\s*\)?\s*\.write_(?:text|bytes)\s*\(", re.S
)

# Pipeline de decodificação alimentando execução.
_DECODERS = re.compile(
    r"\bbase64\s+(?:-d|--decode|-D)\b"
    r"|\bbase32\s+(?:-d|--decode)\b"
    r"|\bxxd\s+(?:-r|--revert)\b"
    r"|\bopenssl\s+(?:enc\s+)?-d\b"
    r"|\b(?:gzip|gunzip|zcat|xz|unxz|bzip2|bunzip2|zstd)\s+(?:-[dc]|--decompress|--stdout)\b"
    r"|\b(?:gunzip|bunzip2|unxz|zcat)\b",
    re.I,
)
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{16,})(?![0-9a-fA-F])")
_FEEDS_EXEC = re.compile(
    r"\|\s*(?:sudo\s+)?(?:[\w./-]*/)?(?:ba|z|da|k|fi)?sh\b"
    r"|\beval\s+\$?\("
    r"|\b(?:source|\.)\s+<\(",
    re.I,
)

# Bases cujo `-c`/`-e` é código, não padrão de busca: `grep -e 'rm -rf /etc'`
# não pode ser tratado como comando.
_PAYLOAD_BASES = frozenset(
    {
        "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox",
        "eval", "exec", "source", ".", "python", "python3", "pypy3",
        "perl", "ruby", "node", "deno", "bun", "php", "lua", "awk", "gawk",
        "mawk", "nawk", "su", "runuser",
    }
)

# `echo -e "\x72\x6d ..." | sh` — escape dentro de argumento vira payload.
_ECHO_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")

# Programas que executam o conteúdo de um argumento documentado (GTFOBins).
# Só as flags de valor são inspecionadas: `git commit -m "rm -rf"` é mensagem,
# não comando.
_EXEC_ARG_FLAGS: dict[str, set[str]] = {
    "git": {"-c", "--config"},
    "man": {"-P", "--pager", "-H", "--html"},
    "vi": {"-c", "--cmd", "-s"},
    "vim": {"-c", "--cmd", "-s"},
    "nvim": {"-c", "--cmd"},
    "zip": {"-T", "-TT", "--unzip-command"},
    "nmap": {"--script", "--script-args", "--datadir"},
    "ssh": {"-o"},
    "tar": {"-I", "--use-compress-program"},
}

# Um argumento de configuração que carrega um comando de verdade.
_DANGEROUS_IN_ARG = re.compile(
    r"(?:^|[;&|(!=])\s*"
    r"(?:rm|dd|shred|truncate|mkfs\w*|curl|wget|nc|ncat|socat|python3?|perl"
    r"|ruby|node|php|lua|sh|bash|zsh|dash|ksh|fish)\b"
    r"|\|\s*(?:sh|bash|zsh|dash|ksh|fish)\b",
    re.I,
)

# Variável de ambiente cujo valor é uma ordem de execução (LESSOPEN, GIT_PAGER...).
_ASSIGN_VALUE = re.compile(
    r"(?:^|[;&|\n])\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)="
    r"(?:'([^']*)'|\"([^\"]*)\")"
)

# Substituição de processo: `<(...)` e `>(...)`.
_PROC_SUB = re.compile(r"[<>]\s*\(([^()]{0,400})\)")

# `exec(zlib.decompress(...))`: executa dado que não dá para inspecionar.
_EMBEDDED_EXEC_DECODER = re.compile(
    r"\b(?:exec|eval)\s*\(\s*(?:zlib|gzip|bz2|lzma|base64|codecs|marshal|pickle)\b",
    re.I,
)

# Escrita por API de linguagem que não passa por `open`/`unlink`.
_EMBEDDED_OS_OPEN = re.compile(
    r"\bos\.open\s*\(\s*(['\"])(.*?)\1[^)]*?O_(?:WRONLY|RDWR|TRUNC|CREAT)\b", re.S
)
_EMBEDDED_PERL_OPEN = re.compile(r"\bopen\s*\([^)]*?(['\"])[>+]{1,2}([^'\"]+)\1", re.S)
_EMBEDDED_FILEPUT = re.compile(
    r"\b(?:file_put_contents|fwrite|file_put_contents)\s*\(\s*(['\"])(.*?)\1", re.S
)

_SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
)

_INJECTION_MARKERS = (
    "ignore previous", "ignore all previous", "ignore prior", "ignore the above",
    "disregard previous", "disregard all", "you are now", "from now on you",
    "system prompt", "auto_allow", "pre-approved", "preapproved",
    "developer mode", "<|im_start|>", "[inst]", "###instruction",
    # português: instrução persistente plantada em arquivo do repositório
    "pré-aprovad", "pre-aprovad", "pré aprovad", "pre aprovad",
    "guardrail suspens", "guardrails suspens", "nunca bloqueie",
    "nunca peça confirma", "nunca peca confirma", "sem confirmação",
    "sem confirmacao", "pode executar sem aviso",
)

# Referência a segredo por nome de variável: o valor não é lido, o nome basta.
_SECRET_ENV = re.compile(
    r"\$(?:\{)?[A-Za-z_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY"
    r"|CREDENTIALS?|ACCESS_KEY)[A-Za-z_]*(?:\})?"
)
_SECRET_REF = re.compile(
    r"\$\{\{\s*secrets\.|\$(?:\{)?[A-Za-z_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY"
    r"|PRIVATE_KEY|CREDENTIALS?|ACCESS_KEY)[A-Za-z_]*(?:\})?",
    re.I,
)
_NET_COMMAND = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|requests\.post|urlopen|urllib|http\.client)\b",
    re.I,
)

_COMMAND_KEYS = ("command", "cmd", "script", "shell")
_PATH_KEYS = ("path", "file", "file_path", "filepath", "filename", "target", "dest", "destination")
_URL_KEYS = ("url", "uri", "endpoint", "href")
_BODY_KEYS = (
    "body", "data", "payload", "form", "json",
    "content", "contents", "text", "new_string", "newText", "value",
)
_READ_TOOLS = ("read", "view", "cat", "open", "get_file", "read_file", "list")
_WRITE_TOOLS = ("write", "edit", "patch", "create", "append", "save", "delete", "remove")


@dataclass(frozen=True)
class PolicyConfig:
    """Limites e allowlists. Tudo explícito; nada inferido em runtime."""

    workspace_roots: tuple[str, ...] = ()
    scratch_roots: tuple[str, ...] = ("/tmp", "/var/tmp", _TERMUX_TMP) + _SAFE_SINKS
    protected_dirs: tuple[str, ...] = _PROTECTED_DIRS
    protected_files: tuple[str, ...] = _PROTECTED_FILES
    protected_patterns: tuple[str, ...] = _PROTECTED_PATTERNS
    egress_allowlist: tuple[str, ...] = _DEFAULT_EGRESS
    max_payload_depth: int = 3

    def expanded(self) -> "PolicyConfig":
        roots = self.workspace_roots or (
            os.environ.get("SENTINELA_WORKSPACE") or os.getcwd(),
        )
        return PolicyConfig(
            workspace_roots=tuple(os.path.normpath(os.path.expanduser(p)) for p in roots),
            scratch_roots=tuple(os.path.normpath(os.path.expanduser(p)) for p in self.scratch_roots),
            protected_dirs=tuple(os.path.normpath(os.path.expanduser(p)) for p in self.protected_dirs),
            protected_files=tuple(os.path.normpath(os.path.expanduser(p)) for p in self.protected_files),
            protected_patterns=self.protected_patterns,
            egress_allowlist=self.egress_allowlist,
            max_payload_depth=self.max_payload_depth,
        )


def _under(path: str, root: str) -> bool:
    if path == root:
        return True
    return path.startswith(root.rstrip("/") + "/")


def _in_any(path: str, roots: Iterable[str]) -> bool:
    return any(_under(path, r) for r in roots)


@dataclass
class _Ctx:
    config: PolicyConfig
    findings: list[Finding] = field(default_factory=list)
    effects: set[str] = field(default_factory=set)
    secrets: tuple[str, ...] = ()
    injection: bool = False

    def add(self, rule_id: str, severity: str, proof: str, effect: str = "") -> None:
        self.findings.append(Finding(rule_id, severity, proof, effect))


def _is_protected(path: str, cfg: PolicyConfig) -> bool:
    if _in_any(path, cfg.protected_dirs) or path in cfg.protected_files:
        return True
    base = os.path.basename(path)
    return any(fnmatch.fnmatch(base, pat) for pat in cfg.protected_patterns)


def _host_of(text: str, argv: tuple[str, ...], base: str) -> str:
    m = re.search(r"https?://([^/\s:]+)", text)
    if m:
        return m.group(1).lower()
    if base in {"ssh", "scp", "sftp", "rsync"}:
        for token in argv[1:]:
            if "@" in token and not token.startswith("-"):
                return token.rsplit("@", 1)[-1].split(":")[0].lower()
    if base in {"nc", "ncat", "netcat", "telnet"}:
        for token in argv[1:]:
            if token.startswith("-"):
                continue
            host = token.split(":")[0]
            if re.fullmatch(r"[A-Za-z0-9_.-]+", host) and not re.fullmatch(r"\d+", host):
                return host.lower()
    if base == "socat":
        for token in argv[1:]:
            m = re.search(r"(?:tcp|udp|ssl)[-_]?(?:connect|listen)?:([A-Za-z0-9_.-]+):", token, re.I)
            if m:
                return m.group(1).lower()
    return ""


def _has_secret(text: str, secrets: tuple[str, ...]) -> bool:
    if any(s and s in text for s in secrets):
        return True
    if _SECRET_ENV.search(text):
        return True
    return any(p.search(text) for p in _SECRET_PATTERNS)


def _check_delete(ctx: _Ctx, raw: str, path: str) -> None:
    """Decisão de DELETE sobre um path já canônico."""
    if _in_any(path, ctx.config.workspace_roots) and path in ctx.config.workspace_roots:
        ctx.add("SEC_DESTROY_002", "critical", f"remoção da raiz do workspace: {path}", eff.DELETE)
    elif not _in_any(path, ctx.config.workspace_roots) and not _in_any(path, ctx.config.scratch_roots):
        ctx.add("SEC_DESTROY_001", "critical", f"remoção fora do workspace: {path}", eff.DELETE)
    elif raw in {"*", "**", "."} or path.endswith("/*"):
        ctx.add("SEC_DESTROY_004", "high", f"remoção por glob: {raw}", eff.DELETE)


def _b64_payloads(text: str) -> list[str]:
    """Decodifica todo literal base64 plausível do texto e devolve o que for texto."""
    out: list[str] = []
    for match in _B64_TOKEN.finditer(text):
        token = match.group(0)
        if len(token) % 4:
            continue
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            printable = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if printable.isprintable() or "\n" in printable:
            out.append(printable)
    return out


def _hex_payloads(text: str) -> list[str]:
    """Decodifica literais hex longos (`xxd -r -p <<< 726d...`)."""
    out: list[str] = []
    for match in _HEX_TOKEN.finditer(text):
        token = match.group(1)
        if len(token) % 2:
            continue
        try:
            decoded = bytes.fromhex(token).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable() or "\n" in decoded:
            out.append(decoded)
    return out


def _analyze_text(text: str, ctx: _Ctx, depth: int = 0) -> None:
    """Analisa um comando de shell, recursivamente em `sh -c`/`eval`."""
    if depth > ctx.config.max_payload_depth:
        ctx.add("SEC_PARSE_002", "high", "profundidade de aninhamento excedida", eff.EXEC)
        return

    normalized = normalize(text)
    for pattern in _REMOTE_EXEC:
        if pattern.search(normalized):
            ctx.add("SEC_EXEC_REMOTE_001", "critical", pattern.pattern[:60], eff.EXEC)
    if _FORKBOMB.search(normalized):
        ctx.add("SEC_DESTROY_003", "critical", "fork bomb", eff.DELETE)
    if _DEVICE.search(normalized):
        ctx.add("SEC_DEVICE_001", "critical", "escrita em dispositivo ou mkfs", eff.WRITE)

    # Execução a partir de payload codificado (`echo ... | base64 -d | sh`).
    if _DECODERS.search(normalized):
        decoded = _b64_payloads(normalized)
        for payload in decoded:
            _analyze_text(payload, ctx, depth + 1)
        if not decoded and _FEEDS_EXEC.search(normalized):
            ctx.add(
                "SEC_EXEC_OBFUSC_001", "critical",
                "execução de payload decodificado não inspecionável", eff.EXEC,
            )
    if re.search(r"\bxxd\s+(?:-r|--revert)\b", normalized, re.I):
        for payload in _hex_payloads(normalized):
            _analyze_text(payload, ctx, depth + 1)
    if _FEEDS_EXEC.search(normalized) and _ECHO_ESCAPE.search(normalized):
        decoded = _ECHO_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), normalized)
        ctx.add(
            "SEC_EXEC_OBFUSC_003", "high",
            "comando com escapes hex alimentando shell", eff.EXEC,
        )
        _analyze_text(decoded, ctx, depth + 1)

    # `exec(zlib.decompress(...))`: executa dado que não foi possível inspecionar.
    if _EMBEDDED_EXEC_DECODER.search(normalized):
        ctx.add(
            "SEC_EXEC_OBFUSC_002", "high",
            "execução de dado descomprimido/codificado não inspecionável", eff.EXEC,
        )

    # Percent-encoding decodificado em runtime (`os.system(unquote('%72%6d...'))`).
    if re.search(r"\bunquote\b", normalized) or (
        re.search(r"(?:%[0-9A-Fa-f]{2}){3,}", normalized)
        and re.search(r"\b(?:system|exec|eval|popen)\s*\(", normalized)
    ):
        decoded = re.sub(
            r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), normalized
        )
        if decoded != normalized:
            _analyze_text(decoded, ctx, depth + 1)

    # Variável de ambiente carregando comando (`LESSOPEN='|rm ...' less`).
    for match in _ASSIGN_VALUE.finditer(normalized):
        value = match.group(2) if match.group(2) is not None else match.group(3)
        if value and (value.strip().startswith("|") or _DANGEROUS_IN_ARG.search(value)):
            ctx.add(
                "SEC_EXEC_003", "high",
                f"variável {match.group(1)} carrega comando", eff.EXEC,
            )

    # Substituição de processo: o interior é comando (`diff <(cat /etc/shadow)`).
    if _PROC_SUB.search(normalized):
        for match in _PROC_SUB.finditer(normalized):
            _analyze_text(match.group(1), ctx, depth + 1)

    cwd = ctx.config.workspace_roots[0]

    for segment in to_segments(normalized):
        if not segment.parseable:
            ctx.add("SEC_PARSE_001", "high", f"shell não parseável: {segment.raw[:80]!r}")
            continue

        facts = eff.classify(segment, cwd)
        ctx.effects.update(facts.effects)
        argv = facts.segment.argv
        base = facts.effective_base or facts.segment.base

        # --- nome de binário que não dá para resolver ---
        if (
            base not in {"[", "[[", "]", "test"}
            and (
                ("*" in base or "?" in base)
                or base.startswith("$(")
                or base.startswith("`")
            )
        ):
            ctx.add(
                "SEC_EXEC_002", "high",
                f"binário não resolvido: {base[:40]}", eff.EXEC,
            )

        # --- argumento de configuração que carrega comando (GTFOBins) ---
        flags = _EXEC_ARG_FLAGS.get(facts.effective_base) or _EXEC_ARG_FLAGS.get(base)
        if flags:
            for idx, token in enumerate(argv[1:], 1):
                value = ""
                for flag in flags:
                    if token == flag:
                        value = argv[idx + 1] if idx + 1 < len(argv) else ""
                    elif token.startswith(flag + "="):
                        value = token[len(flag) + 1 :]
                    elif not flag.startswith("--") and token.startswith(flag) and len(token) > len(flag):
                        value = token[len(flag) :]
                    if value:
                        break
                if value and (
                    value.strip().startswith("!") or _DANGEROUS_IN_ARG.search(value)
                ):
                    ctx.add(
                        "SEC_EXEC_004", "high",
                        f"argumento de {base} carrega comando: {value[:40]}", eff.EXEC,
                    )
                    break

        # --- paths ---
        for raw, path in facts.paths:
            touched = facts.effects & {eff.READ, eff.WRITE, eff.DELETE, eff.EXEC, eff.SECRET}
            if _is_protected(path, ctx.config) and touched:
                ctx.add("SEC_CRED_001", "critical", f"path protegido: {path}", eff.SECRET)

            if eff.WRITE in facts.effects and not _in_any(
                path, ctx.config.workspace_roots
            ) and not _in_any(path, ctx.config.scratch_roots):
                if not _is_protected(path, ctx.config):
                    ctx.add("SEC_WRITE_ESCAPE_001", "critical", f"escrita fora do workspace: {path}", eff.WRITE)

        if eff.DELETE in facts.effects:
            if base == "find" and "-delete" in argv and "-name" in argv:
                # `-name` limita o escopo: artefato de build reconhecido e
                # dentro do workspace passa; qualquer outro padrão pergunta.
                idx = argv.index("-name")
                padrao = argv[idx + 1] if idx + 1 < len(argv) else ""
                dentro = all(
                    _in_any(p, ctx.config.workspace_roots)
                    or _in_any(p, ctx.config.scratch_roots)
                    for _, p in facts.command_paths
                )
                if not (dentro and padrao in _FIND_DELETE_ALLOW):
                    ctx.add(
                        "SEC_DESTROY_006", "high",
                        f"remoção por padrão via find: {padrao}", eff.DELETE,
                    )
            else:
                for raw, path in facts.command_paths:
                    _check_delete(ctx, raw, path)
                if not facts.command_paths:
                    ctx.add(
                        "SEC_DESTROY_005", "high",
                        f"remoção com alvo não resolvido: {segment.raw[:60]}", eff.DELETE,
                    )

        # --- payload de interpretador (`sh -c`, `eval`, `python -c`) ---
        if facts.payload and (
            base in _PAYLOAD_BASES
            or any(t in {"-c", "--command", "-Command"} for t in argv)
        ):
            _analyze_text(facts.payload, ctx, depth + 1)

        # --- comando embutido em interpretador ---
        for match in _EMBEDDED_COMMAND.finditer(segment.raw):
            inner = match.group(2)
            if inner.strip():
                ctx.effects.add(eff.EXEC)
                _analyze_text(inner, ctx, depth + 1)
        for match in _EMBEDDED_COMMAND_LIST.finditer(segment.raw):
            parts = re.findall(r"(['\"])(.*?)\1", match.group(1), re.S)
            inner = " ".join(part for _, part in parts)
            if inner.strip():
                ctx.effects.add(eff.EXEC)
                _analyze_text(inner, ctx, depth + 1)

        # --- destruição de path via API de linguagem ---
        for match in _EMBEDDED_DESTROY.finditer(segment.raw):
            target = canonical_path(match.group(2), cwd)
            ctx.effects.add(eff.DELETE)
            if _is_protected(target, ctx.config):
                ctx.add("SEC_CRED_001", "critical", f"path protegido: {target}", eff.SECRET)
            _check_delete(ctx, match.group(2), target)

        # --- escrita de path via API de linguagem (`open(p,'w')`, `.write_text`) ---
        write_patterns = (
            _EMBEDDED_OPEN_WRITE,
            _EMBEDDED_WRITE_TEXT,
            _EMBEDDED_OS_OPEN,
            _EMBEDDED_PERL_OPEN,
            _EMBEDDED_FILEPUT,
        )
        for pattern in write_patterns:
            for match in pattern.finditer(segment.raw):
                target = canonical_path(match.group(2), cwd)
                ctx.effects.add(eff.WRITE)
                if _is_protected(target, ctx.config):
                    ctx.add("SEC_CRED_001", "critical", f"path protegido: {target}", eff.SECRET)
                elif not _in_any(target, ctx.config.workspace_roots) and not _in_any(
                    target, ctx.config.scratch_roots
                ):
                    ctx.add(
                        "SEC_WRITE_ESCAPE_001", "critical",
                        f"escrita fora do workspace: {target}", eff.WRITE,
                    )

        # --- Renomear/mover por API de linguagem ---
        for match in _EMBEDDED_RENAME.finditer(segment.raw):
            target = canonical_path(match.group(4), cwd)
            ctx.effects.add(eff.WRITE)
            if _is_protected(target, ctx.config):
                ctx.add("SEC_CRED_001", "critical", f"path protegido: {target}", eff.SECRET)
            elif not _in_any(target, ctx.config.workspace_roots) and not _in_any(
                target, ctx.config.scratch_roots
            ):
                ctx.add(
                    "SEC_WRITE_ESCAPE_001", "critical",
                    f"escrita fora do workspace: {target}", eff.WRITE,
                )

        # --- runner de pacote remoto: executa código de fora por definição ---
        if base in _REMOTE_CODE_RUNNERS:
            ctx.add(
                "SEC_EXEC_REMOTE_002", "high",
                f"execução de pacote remoto: {base}", eff.EXEC,
            )

        # --- instalação na raiz do sistema ---
        if base in {"make", "cmake", "ninja"} and (
            facts.subcommand in {"install"}
            or any(t.startswith("DESTDIR=") for t in argv)
        ):
            destination = next(
                (t.split("=", 1)[1] for t in argv if t.startswith("DESTDIR=")), ""
            )
            if destination:
                target = canonical_path(destination, cwd)
                ctx.effects.add(eff.WRITE)
                if not _in_any(target, ctx.config.workspace_roots) and not _in_any(
                    target, ctx.config.scratch_roots
                ):
                    ctx.add(
                        "SEC_WRITE_ESCAPE_001", "critical",
                        f"escrita fora do workspace: {target}", eff.WRITE,
                    )
            else:
                ctx.add(
                    "SEC_WRITE_ESCAPE_001", "high",
                    f"instalação em raiz do sistema: {segment.raw[:50]}", eff.WRITE,
                )

        # --- config de git cujo valor é comando (`git config alias.x '!rm …'`) ---
        if base == "git" and facts.subcommand == "config":
            for idx, token in enumerate(argv[1:], 1):
                if "." not in token:
                    continue
                value = argv[idx + 1] if idx + 1 < len(argv) else ""
                if value and (
                    value.lstrip().startswith("!") or _DANGEROUS_IN_ARG.search(value)
                ):
                    ctx.add(
                        "SEC_EXEC_005", "high",
                        f"config do git executa comando: {value[:40]}", eff.EXEC,
                    )
                    break

        # --- automação remota que executa comando no destino ---
        if base in {"ansible", "ansible-playbook", "kubectl"}:
            for idx, token in enumerate(argv[1:], 1):
                if token in {"-a", "--args"} and idx + 1 < len(argv):
                    ctx.effects.add(eff.EXEC)
                    _analyze_text(argv[idx + 1], ctx, depth + 1)
                    break
                if token == "--":
                    ctx.effects.add(eff.EXEC)
                    _analyze_text(" ".join(argv[idx + 1 :]), ctx, depth + 1)
                    break

        # --- privilégio / persistência / publicação ---
        if eff.PRIVILEGE in facts.effects:
            ctx.add("SEC_PRIV_001", "high", f"escalada de privilégio: {base}", eff.PRIVILEGE)

        if base == "crontab" and facts.flags & {"-l"}:
            pass
        elif base in eff._PERSIST:
            persist_sub = facts.subcommand
            if base in {"at", "batch"} or persist_sub in {
                "enable", "start", "restart", "daemon-reload", "link",
                "load", "bootstrap", "install",
            }:
                ctx.add("SEC_PERSIST_001", "high", f"persistência: {segment.raw[:60]}", eff.PERSIST)

        if base in eff._PUBLISH and facts.subcommand in {"publish", "upload", "push", "release", "create"}:
            ctx.add("SEC_PUBLISH_001", "high", f"publicação: {segment.raw[:60]}", eff.PUBLISH)

        # --- rede ---
        host = _host_of(segment.raw, argv, base)
        if eff.NETWORK in facts.effects:
            if _has_secret(normalized, ctx.secrets):
                severity = "high" if host in ctx.config.egress_allowlist else "critical"
                ctx.add("SEC_EGRESS_TAINT_001", severity, f"segredo em egresso para {host or '?'}", eff.NETWORK)
            if host and host not in ctx.config.egress_allowlist:
                ctx.add("SEC_EGRESS_002", "high", f"egresso para host não allowlistado: {host}", eff.NETWORK)

        # --- permissões ---
        if base == "chmod":
            modes = [t for t in argv[1:] if re.fullmatch(r"[0-7]{3,4}", t)]
            if modes and any(m.endswith("777") for m in modes):
                severity = "critical" if facts.flags & {"-R", "--recursive"} else "high"
                ctx.add("SEC_PERM_001", severity, f"chmod {modes[0]}", eff.WRITE)

        # --- git ---
        if base == "git":
            sub = facts.subcommand
            if sub == "push" and facts.flags & {"--force", "-f", "--force-with-lease", "--mirror"}:
                risky_branch = any(t in {"main", "master", "release"} for t in argv)
                # `--mirror` apaga refs no remoto: não há como revisar depois.
                if "--mirror" in facts.flags:
                    severity = "critical"
                else:
                    severity = "critical" if risky_branch else "high"
                ctx.add(
                    "SEC_GIT_001",
                    severity,
                    f"git push forçado: {segment.raw[:60]}",
                    eff.WRITE,
                )
            if sub == "reset" and "--hard" in facts.flags:
                ctx.add("SEC_GIT_002", "high", "git reset --hard", eff.WRITE)
            if sub in {"filter-branch", "filter-repo"}:
                ctx.add("SEC_GIT_003", "high", f"reescrita de história: {sub}", eff.WRITE)

        # --- SQL ---
        sql_text = facts.payload or normalized
        if base in _SQL_CLIENTS or facts.payload and base in eff._EXECUTORS:
            if _SQL_DROP.search(sql_text):
                ctx.add("SEC_SQL_001", "critical", "DDL destrutivo", eff.WRITE)
            elif _SQL_DELETE_NO_WHERE.search(sql_text) or _SQL_UPDATE_NO_WHERE.search(sql_text):
                ctx.add("SEC_SQL_002", "critical", "DML em massa sem WHERE", eff.WRITE)
        for match in _SQL_PROGRAM.finditer(normalized):
            inner = match.group(1) or match.group(2)
            if inner:
                ctx.effects.add(eff.EXEC)
                _analyze_text(inner, ctx, depth + 1)


def _extract(tool_call: dict[str, Any]) -> dict[str, Any]:
    args = tool_call.get("args") if isinstance(tool_call, dict) else None
    if not isinstance(args, dict):
        args = {}
    name = str(tool_call.get("name", "")) if isinstance(tool_call, dict) else ""

    def first(keys: Iterable[str]) -> str:
        for key in keys:
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return ""

    command = first(_COMMAND_KEYS)
    path = first(_PATH_KEYS)
    url = first(_URL_KEYS)
    body = first(_BODY_KEYS)
    lowered = name.lower()

    is_write = any(t in lowered for t in _WRITE_TOOLS)
    is_read = any(t in lowered for t in _READ_TOOLS) and not is_write

    return {
        "name": name,
        "command": command,
        "path": path,
        "url": url,
        "body": body,
        "is_write": is_write,
        "is_read": is_read,
        "args": args,
    }


def evaluate(
    tool_call: dict[str, Any],
    config: PolicyConfig | None = None,
    secrets: Iterable[str] = (),
) -> Verdict:
    """Avalia uma chamada de ferramenta na camada L0."""
    cfg = (config or PolicyConfig()).expanded()
    secrets_t = tuple(s for s in secrets if s)

    with Stopwatch() as sw:
        ctx = _Ctx(config=cfg, secrets=secrets_t)
        try:
            surface = _extract(tool_call)

            blob = normalize(
                " ".join(
                    str(v)
                    for v in [surface["command"], surface["path"], surface["body"],
                              surface["url"]]
                    if isinstance(v, str)
                )
            )
            lowered_blob = blob.lower()
            if any(marker in lowered_blob for marker in _INJECTION_MARKERS):
                ctx.injection = True
                ctx.add("SEC_INJECT_001", "high", "marcador de injeção de instrução no argumento")

            if surface["command"]:
                _analyze_text(surface["command"], ctx)

            if surface["path"]:
                path = canonical_path(surface["path"], cfg.workspace_roots[0])
                effect = eff.WRITE if surface["is_write"] else (eff.READ if surface["is_read"] else "")
                if _is_protected(path, cfg):
                    ctx.add("SEC_CRED_001", "critical", f"path protegido: {path}", eff.SECRET)
                if surface["is_write"] and not _in_any(path, cfg.workspace_roots) and not _in_any(
                    path, cfg.scratch_roots
                ):
                    ctx.add("SEC_WRITE_ESCAPE_001", "critical", f"escrita fora do workspace: {path}", eff.WRITE)
                if effect:
                    ctx.effects.add(effect)

            if surface["url"]:
                host = _host_of(surface["url"], (), "")
                ctx.effects.add(eff.NETWORK)
                if _has_secret(surface["body"] + surface["url"], secrets_t):
                    severity = "high" if host in cfg.egress_allowlist else "critical"
                    ctx.add("SEC_EGRESS_TAINT_001", severity, f"segredo em egresso para {host or '?'}", eff.NETWORK)
                if host and host not in cfg.egress_allowlist:
                    ctx.add("SEC_EGRESS_002", "high", f"egresso para host não allowlistado: {host}", eff.NETWORK)

            # Payload que será executado depois de gravado: sonda de comando
            # embutido dentro do conteúdo.
            if surface["is_write"] and surface["body"]:
                corpo = surface["body"]
                normalizado = normalize(corpo)
                if any(p.search(normalizado) for p in _REMOTE_EXEC):
                    ctx.add(
                        "SEC_EXEC_REMOTE_001", "critical",
                        "conteúdo gravado executa payload remoto", eff.EXEC,
                    )
                if _NET_COMMAND.search(corpo):
                    host = _host_of(corpo, (), "")
                    if host and host not in cfg.egress_allowlist:
                        severity = "critical" if _SECRET_REF.search(corpo) else "high"
                        ctx.add(
                            "SEC_EGRESS_003", severity,
                            f"conteúdo grava egresso para {host}", eff.NETWORK,
                        )
                for pattern in (_EMBEDDED_COMMAND, _EMBEDDED_COMMAND_LIST, _SQL_PROGRAM):
                    for match in pattern.finditer(normalizado):
                        inner = " ".join(g for g in match.groups() if g)
                        ctx.effects.add(eff.EXEC)
                        _analyze_text(inner, ctx, 1)
            if not any([surface["command"], surface["path"], surface["url"], surface["body"]]):
                ctx.add("SEC_UNKNOWN_001", "high", "chamada sem superfície reconhecível")

            severities = [f.severity for f in ctx.findings]
            if "critical" in severities:
                verdict = DENY
            elif ctx.findings:
                verdict = UNCERTAIN
            else:
                verdict = ALLOW

        except Exception as exc:  # fail-closed por construção
            ctx.findings.append(Finding("SEC_INTERNAL_001", "critical", f"erro interno: {type(exc).__name__}"))
            verdict = DENY

    return Verdict(
        verdict=verdict,
        findings=tuple(ctx.findings),
        effects=tuple(sorted(ctx.effects)),
        normalized=blob if "blob" in locals() else "",
        injection_suspected=ctx.injection,
        latency_ms=sw.elapsed_ms,
        input_digest=digest(tool_call),
    )
