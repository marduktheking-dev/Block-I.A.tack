"""Classificação de efeito de um segmento de comando.

As nove classes são o vocabulário comum entre as regras e o scorer (L1).
Nenhuma decisão é tomada aqui: só se descreve o que o comando *pode* fazer.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .canonicalize import Segment, canonical_path, looks_like_path

READ = "read"
WRITE = "write"
DELETE = "delete"
EXEC = "exec"
NETWORK = "network_out"
PRIVILEGE = "privilege"
PERSIST = "persist"
SECRET = "secret_access"
PUBLISH = "publish"
SPEND = "spend"

ALL_EFFECTS = frozenset(
    {READ, WRITE, DELETE, EXEC, NETWORK, PRIVILEGE, PERSIST, SECRET, PUBLISH, SPEND}
)

_DELETERS = {"rm", "rmdir", "unlink", "shred", "srm", "wipe", "trash"}
_WRITERS = {
    "mv", "cp", "dd", "tee", "truncate", "install", "chmod", "chown",
    "chgrp", "ln", "mkdir", "touch", "patch", "rsync", "sed", "git",
    "fallocate", "chattr", "setfacl", "7z", "7za", "zip", "unzip", "rar",
}
_EXECUTORS = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox",
    "python", "python3", "perl", "ruby", "node", "php", "lua", "deno", "bun",
    "eval", "source", ".", "exec", "xargs", "env", "nohup", "timeout",
    "find", "awk", "make", "cmake", "task", "just",
}
_NETWORK = {
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp",
    "rsync", "aria2c", "http", "https", "telnet", "dig", "nslookup",
    "pip", "pip3", "npm", "yarn", "pnpm", "uv", "git", "docker", "podman",
    "gh", "aws", "gcloud", "az", "ftp",
}
_PRIVILEGE = {"sudo", "su", "doas", "pkexec", "nsenter", "unshare", "setcap", "capsh"}
_PERSIST = {
    "crontab", "systemctl", "launchctl", "schtasks", "at", "batch",
    "update-rc.d", "rc-update", "chkconfig",
}
_PUBLISH = {"twine", "cargo", "npm", "pnpm", "yarn", "docker", "podman", "gh", "aws",
            "gem", "uv", "poetry", "flit", "dotnet", "mvn"}
_SPEND = {"stripe", "paypal", "mercadopago"}

# Subcomandos que transformam um binário "de rede" em egresso de verdade.
_NETWORK_SUBCOMMANDS = {
    "git": {"push", "clone", "fetch", "pull", "remote", "submodule", "ls-remote"},
    "pip": {"install", "download"},
    "pip3": {"install", "download"},
    "uv": {"pip", "add", "sync"},
    "npm": {"install", "publish", "add", "exec"},
    "yarn": {"add", "install", "publish"},
    "pnpm": {"add", "install", "publish"},
    "docker": {"pull", "push", "run", "login", "build"},
    "podman": {"pull", "push", "run", "login", "build"},
    "gh": {"release", "api", "repo", "pr", "issue", "auth"},
    "cargo": {"publish", "install"},
    "gem": {"push", "install"},
    "aws": {"s3", "ec2", "iam", "lambda", "sts"},
    "gcloud": {"auth", "compute", "storage", "iam"},
    "az": {"login", "storage", "vm", "ad"},
}


@dataclass(frozen=True)
class SegmentFacts:
    """Fatos observados de um segmento, sem julgamento."""

    segment: Segment
    effects: frozenset[str] = frozenset()
    paths: tuple[tuple[str, str], ...] = ()  # (token bruto, path canônico); inclui redirecionamentos
    command_paths: tuple[tuple[str, str], ...] = ()  # só alvos do comando
    subcommand: str = ""
    payload: str = ""  # conteúdo de -c/-e/--command, se houver
    flags: frozenset[str] = frozenset()
    effective_base: str = ""  # base depois de desembrulhar env/sudo/timeout/xargs
    wrappers: tuple[str, ...] = ()

    def has(self, effect: str) -> bool:
        return effect in self.effects


def _flag_set(argv: tuple[str, ...]) -> frozenset[str]:
    flags: set[str] = set()
    for token in argv[1:]:
        if token.startswith("--"):
            flags.add(token)
        elif token.startswith("-") and len(token) > 1:
            flags.add(token)
            # -rf expande para -r e -f
            for ch in token[1:]:
                flags.add("-" + ch)
    return frozenset(flags)


def _payload(argv: tuple[str, ...]) -> str:
    """Extrai o script passado a `sh -c`, `python -c`, `perl -e`, `eval`, `awk`."""
    if not argv:
        return ""
    head = os.path.basename(argv[0])
    if head == "eval" and len(argv) > 1:
        return " ".join(argv[1:])
    if head in {"awk", "gawk", "mawk", "nawk"} and len(argv) > 1 and not argv[1].startswith("-"):
        return argv[1]
    for idx, token in enumerate(argv):
        if token in {"-c", "-e", "--command", "-Command"} and idx + 1 < len(argv):
            return argv[idx + 1]
        if token in {"-m"} and idx + 1 < len(argv):
            return ""
    return ""


_REDIRECT = re.compile(r"(?:^|\s)(?:\d?>>?|&>|>\|)\s*([^\s;&|<>()]+)")
_INPUT_REDIRECT = re.compile(r"(?<!<)<(?![<&])\s*([^\s;&|<>()]+)")
_OUTPUT_FLAGS = ("of=", "--output=", "--out=", "-o")
_READ_FLAGS = ("if=", "--input=")

# Binários que só repassam para outro comando. Sem desembrulhar, `env rm -rf /etc`
# parece apenas "env" e passa.
_WRAPPERS = {
    "env", "command", "builtin", "nohup", "nice", "ionice", "time", "timeout",
    "stdbuf", "busybox", "toybox", "sudo", "doas", "su", "setsid", "unshare",
    "chroot", "exec", "do", "then", "else", "xargs", "watch", "parallel",
    "strace", "ltrace", "valgrind", "chronic", "firejail", "runuser", "setpriv",
    "(", ")", "{", "}",
}

# Flags desses wrappers que consomem o token seguinte.
_WRAPPER_ARG_FLAGS: dict[str, set[str]] = {
    "sudo": {"-u", "-g", "-p", "-U", "-C", "-D", "-r", "-t", "-h"},
    "doas": {"-u", "-C"},
    "su": {"-c", "-s", "-u", "-g"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "stdbuf": {"-i", "-o", "-e"},
    "ionice": {"-c", "-n", "-p"},
    "env": {"-u", "--unset", "-C", "--chdir"},
    "chroot": {"--userspec", "--groups"},
    "xargs": {"-n", "-P", "-I", "-L", "-s", "-d", "-E", "-a"},
    "watch": {"-n", "-d"},
    "strace": {"-o", "-p", "-e", "-s", "-u", "-E", "-P"},
    "ltrace": {"-o", "-p", "-e", "-s", "-u"},
}

_NUMBER_TOKEN = re.compile(r"\d+(?:\.\d+)?[smhd]?\Z")
_ASSIGN_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*\Z")
_DESTRUCTIVE_INNER = {
    "rm", "rmdir", "unlink", "shred", "srm", "truncate", "dd", "wipe", "trash",
    "mkfs", "mv", "cp", "tee", "install",
}


def _unwrap(argv: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Remove wrappers de execução (`env`, `sudo`, `timeout`, `xargs`...).

    Devolve (argv efetivo, wrappers vistos). Se o wrapper consumir tudo (ex.:
    `su -c '...'`), o argv original volta — o payload continua sendo analisado
    por outro caminho.
    """
    work = list(argv)
    seen: list[str] = []
    while work:
        head = os.path.basename(work[0]).lower()
        if head not in _WRAPPERS:
            break
        seen.append(head)
        work = work[1:]
        takes = _WRAPPER_ARG_FLAGS.get(head, set())
        while work:
            token = work[0]
            if token.startswith("-"):
                work = work[1:]
                if token in takes and work:
                    work = work[1:]
                continue
            if _NUMBER_TOKEN.match(token) or _ASSIGN_TOKEN.match(token):
                work = work[1:]
                continue
            break
    if not work:
        return tuple(argv), tuple(seen)
    return (tuple(work) if seen else tuple(argv)), tuple(seen)


def _redirect_paths(raw: str, cwd: str) -> tuple[tuple[str, str], ...]:
    """Alvos de `>`, `>>`, `&>` e `>|` — escrita que o shell faz sem comando."""
    out: list[tuple[str, str]] = []
    for match in _REDIRECT.finditer(raw):
        token = match.group(1).strip("'\"")
        if not token or token.startswith("&"):
            continue
        out.append((token, canonical_path(token, cwd)))
    return tuple(out)


def _input_paths(raw: str, cwd: str) -> tuple[tuple[str, str], ...]:
    """Alvos de `<` — leitura que o shell faz sem comando (`cat<~/.ssh/id_rsa`)."""
    out: list[tuple[str, str]] = []
    for match in _INPUT_REDIRECT.finditer(raw):
        token = match.group(1).strip("'\"")
        if not token or token.startswith("&") or token.startswith("("):
            continue
        out.append((token, canonical_path(token, cwd)))
    return tuple(out)


def _kv_paths(argv: tuple[str, ...], cwd: str) -> tuple[tuple[str, str], ...]:
    """`of=/etc/x`, `--output=/etc/x`, `if=/etc/shadow` — alvo colado na flag."""
    out: list[tuple[str, str]] = []
    for token in argv[1:]:
        for prefix in _OUTPUT_FLAGS + _READ_FLAGS:
            if token.startswith(prefix) and len(token) > len(prefix):
                value = token[len(prefix) :]
                if looks_like_path(value) or value.startswith("/") or value.startswith("~"):
                    out.append((value, canonical_path(value, cwd)))
                break
    return tuple(out)


def _find_roots(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Roots de um `find`: tokens posicionais antes da expressão (`-name` etc.)."""
    roots: list[str] = []
    for token in argv[1:]:
        if token.startswith("-") or token in {"!", "(", ")"}:
            break
        roots.append(token)
    return tuple(roots)


def _find_destroys(argv: tuple[str, ...]) -> bool:
    if "-delete" in argv:
        return True
    if "-exec" in argv or "-execdir" in argv or "-ok" in argv:
        return any(os.path.basename(t) in _DESTRUCTIVE_INNER for t in argv)
    return False



def classify(segment: Segment, cwd: str) -> SegmentFacts:
    """Descreve efeitos, paths, flags e subcomando de um segmento."""
    original = segment.argv
    argv, wrappers = _unwrap(original)
    base = os.path.basename(argv[0]) if argv else ""
    effects: set[str] = set()
    flags = _flag_set(argv)
    sub = argv[1] if len(argv) > 1 and not argv[1].startswith("-") else ""

    # `python3 -m pip install ...` e `python3 -m twine upload ...`: o módulo é
    # o comando real. Sem isso, toda a política de rede/publicação é ignorada.
    if base in {"python", "python3", "pypy3"} and "-m" in argv:
        idx = argv.index("-m")
        if idx + 1 < len(argv):
            base = os.path.basename(argv[idx + 1])
            sub = (
                argv[idx + 2]
                if idx + 2 < len(argv) and not argv[idx + 2].startswith("-")
                else ""
            )
    payload_text = _payload(argv) or _payload(original)

    if wrappers:
        # o wrapper em si já é execução de outra coisa
        effects.add(EXEC)
    if set(wrappers) & {"sudo", "doas", "su", "pkexec", "runuser", "nsenter", "setpriv"}:
        effects.add(PRIVILEGE)

    paths = tuple(
        (token, canonical_path(token, cwd))
        for token in argv[1:]
        if looks_like_path(token)
    )
    paths = paths + _kv_paths(argv, cwd)

    if base in _DELETERS:
        effects.update({DELETE, WRITE})
        # Argumentos de `rm` são sempre paths, mesmo sem `./` ou `/`.
        for token in argv[1:]:
            if token.startswith("-"):
                continue
            paths = paths + ((token, canonical_path(token, cwd)),)
    if base in _WRITERS:
        effects.add(WRITE)
    if base == "dd":
        if any(t.startswith("of=") for t in argv[1:]):
            effects.add(WRITE)
        if any(t.startswith("if=") for t in argv[1:]):
            effects.add(READ)
    if base == "sed" and flags & {"-i", "--in-place"}:
        effects.add(WRITE)
    if base == "tar" and "--remove-files" in argv:
        effects.add(DELETE)
    if base in _EXECUTORS:
        effects.add(EXEC)
    if base == "find":
        roots = tuple(
            (token, canonical_path(token, cwd))
            for token in _find_roots(argv)
            if looks_like_path(token) or token.startswith("$")
        )
        paths = paths + roots
        if _find_destroys(argv):
            effects.add(DELETE)
            if not any(os.path.basename(t) == "rm" for t in argv):
                effects.add(WRITE)
        else:
            effects.add(EXEC)
    if base in _PRIVILEGE:
        effects.add(PRIVILEGE)
    if base in _PERSIST:
        effects.add(PERSIST)
    if base in _PUBLISH and sub in {"publish", "upload", "push", "release", "create"}:
        effects.add(PUBLISH)
    if base in _SPEND:
        effects.add(SPEND)

    if base in _NETWORK:
        wanted = _NETWORK_SUBCOMMANDS.get(base)
        if wanted is None or sub in wanted:
            effects.add(NETWORK)
    if base in {"curl", "wget"} and flags & {"-o", "-O", "--output", "--output-document", "--remote-name"}:
        effects.add(WRITE)
    # Cliente HTTP/socket dentro de interpretador.
    if base in {"python", "python3", "pypy3", "perl", "ruby", "node", "php", "lua"} and re.search(
        r"\b(?:urlopen|requests\.|http\.client|socket\.|LWP|Net::HTTP|fetch\(|http\.get|urllib)",
        payload_text,
        re.I,
    ):
        effects.add(NETWORK)

    # Leitura de arquivo sensível é detectada pelo path, não pelo binário.
    if base in {"cat", "less", "head", "tail", "grep", "awk", "strings", "xxd",
                "base64", "openssl", "scp", "rsync", "tar", "zip", "cp", "mv"}:
        effects.add(READ)

    # Alvos do próprio comando (antes de redirecionamentos do shell).
    command_paths = paths
    redirects = _redirect_paths(segment.raw, cwd)
    if redirects:
        effects.add(WRITE)
        paths = paths + redirects
    inputs = _input_paths(segment.raw, cwd)
    if inputs:
        effects.add(READ)
        paths = paths + inputs

    return SegmentFacts(
        segment=segment,
        effects=frozenset(effects),
        paths=paths,
        command_paths=command_paths,
        subcommand=sub,
        payload=payload_text,
        flags=flags,
        effective_base=base,
        wrappers=wrappers,
    )
