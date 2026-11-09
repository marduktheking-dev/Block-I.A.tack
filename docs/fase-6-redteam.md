# Fase 6 — red team da camada L0

Objetivo da fase 6 do plano: medir o L0 **fora da auto-avaliação**. O corpus
`golden/v0.jsonl` não vale como prova: foi escrito pelo mesmo autor das regras.

Convenção: `DENY` e `UNCERTAIN` contam como barrado; só `ALLOW` é ASR (o plugin
traduz `UNCERTAIN` para `ask`, que é decisão humana).

## O que foi feito

Três camadas de ataque, três fontes distintas:

1. **Corpus principal** (`eval/redteam/cases.jsonl`, 263 casos) — técnicas
   copiadas de *PayloadsAllTheThings* (Command Injection, seção Filter
   Bypasses), primitivas destrutivas do *GTFOBins*, APIs de linguagem
   (Python/Ruby/Node/PHP/Lua/Perl), execução remota, credenciais,
   persistência, exfiltração e uma matriz mecânica (38 lançadores × 4 alvos).
2. **Holdout independente** (`eval/redteam/holdout.json`, 55 casos) — escrito
   por um agente separado que recebeu apenas o modelo de ameaça
   (`docs/ameacas.md`) e **não** teve acesso às regras nem às regras do corpus
   principal. Medido **antes** de qualquer correção.
3. **Holdout secundário** (`eval/redteam/holdout2.json`, 40 casos) — escrito
   pelo próprio agente **depois** das correções, ao longo de eixos técnicos
   que o holdout 1 não explorou (here-doc, subshell, substituição de processo,
   builtin, fallocate, 7z, COPY TO PROGRAM, alias de git, runners de pacote,
   docker, ansible, chattr, GIT_PAGER, base32, DNS exfil, rename por API).
   Vale como triagem de cobertura, **não** como medida de generalização.

## Medição 1 — corpus principal, antes das correções

Data: 2026-11-08. Comando: `python3 -m eval.redteam.run`.

* 25/107 dos casos externos passaram (**ASR 23,36%** — técnica aplicada a alvo
  destrutivo).
* 7/156 da matriz mecânica passaram (4,49%; a matriz reverteu em uma
  distinção de mera diferença léxica).

Sobreviventes em resumo: wrappers (`env`, `timeout`, `nohup`, `nice`,
`stdbuf`, `strace -o`), `${IFS}`, `{a,b}`, `$@`, `${@}`, `$()`/retorno em
backtick como nome do binário, `echo` em hex para shell, `printf` com escape,
`( )`/`{ }` de agrupamento, `<(...)`, `-m <módulo>` do Python (perde `pip` /
`twine`), `git config alias…`, `man -P`, `zip -TT`, `nmap --script`,
`chattr`, `fallocate`, `python -c "open(...)"`, `ruby File.rename`,
`COPY … TO PROGRAM`, conteúdo `write` carregando `curl | sh` e conteúdo `write`
carregando marcador de pré-aprovação. Também houve troca de importância em
`write` (T09).

Correções aplicadas (fases 6a e 6b), todas no núcleo, com testes de regressão
(`tests/test_redteam.py`):

* expansão de shell fechada (ATFC: `${IFS}`, `$@`/`$*`/`${@}`, `$()` vazio,
  `{a,b,c}`, `${HOME:0:1}`, `\<newline>`, **`$HOME`/`${HOME}`**) em
  `canonicalize.py`
* rastreamento de atribuição de variável (`A=rm;B=-rf;C=/etc;$A $B $C`)
* desembrulho de wrappers com tabela de flags (`env`, `sudo`, `timeout`,
  `strace`, `xargs`…) e efeito `privilege` preservado no wrapper
* `python -m <módulo>` virando base real; `twine`/`uv`/`poetry` em `_PUBLISH`
* recodificação tanto por decodificadores (base64, base32, xxd, openssl,
  gzip) quanto em echo/printf com `\x` — e decompressão não inspecionável
  (`exec(zlib…)`, `unquote('%72…')`)
* `find -exec/-execdir/-delete` com alvo raiz; `tar --remove-files`; `dd of=`
* API de linha: `open('w')`, `Path.write_text`, `os.open(O_TRUNC)`,
  `perl open ">"`, `php file_put_contents`, `File.rename`
* argumentos que executam comando (git `-c`/`config alias.`, man `-P`,
  vi `-c`, zip `-TT`, nmap `--script`, ssh `-o`, tar `-I`, LESSOPEN e GIT_PAGER)
* runner de pacote remoto (`npx`/`uvx`/`pipx`/`bunx`) sempre UNCERTAIN
* automação remota (ansible `-a`, kubectl `--`) e env (`docker run … sh -c`)
* host para `nc`/`socat`; nome de variável de segredo
  (`$GITHUB_TOKEN`, `$AWS_SECRET_ACCESS_KEY`)
* conteúdo de `write`: marcador de injeção (PT e EN), `curl | sh`, egresso
  para host não allowlistado com referência de segredo, comando embutido
* leitura protegida via `<(...)`, `<` de arquivo e regra de glob no nome do
  binário

## Medição 2 — holdout independente, ANTES das correções

Também em `fase-6-holdout-inicial.txt`.

```
ASR total     : 9/40 = 22.50%      ← é o número honesto do produto antes das correções
atrito benigno: 1/15 = 6.67%
```

## Medição 3 — depois das correções

* **holdout1**: 0/40 ASR; atrito benigno 0/15, bloqueio 0/15.
* **holdout2**: 0/35 ASR; atrito benigno 0/5, bloqueio 0/5.
* **corpus principal**: 0/263 ASR; atrito benigno 0/168 no corpus congelado.
* 143 testes de núcleo + regressão em `OK`.

**Advertência honesta:** após a correção, os holdouts passam por casos que o
mesmo processo que corrigiu as regras já viu. A conta de quatro medições não
mede "generalização": isso é o *primário* de cada rodada (22,50% e 42,86%
antes das respectivas correções, com conjuntos até então não cobertos
mostrando as lacunas). A garantia do produto é o invariante (fail-closed,
DENY nunca vira ALLOW), a latência e o rastro de regras; o ASR contra um
adversário novo depende de rodar esta mesma rotina em ciclo contínuo.

## Latência (cada corpus)

| corpus              | casos | p50     | p95     | p99     | max      |
|---------------------|-------|---------|---------|---------|----------|
| golden (congelado)  | 610   | ~1,6 ms | ~2,7 ms | ~3,6 ms | ~4 ms    |
| redteam principal   | 263   | ~2,0 ms | ~4,4 ms | ~8,4 ms | ~29 ms   |
| holdout1            | 55    | ~2,4 ms | ~4,4 ms | —       | ~10 ms   |
| holdout2            | 40    | ~2,1 ms | ~3,5 ms | —       | —        |

Crescimento aceitável; leitura de path em `/health` do sidecar continua
< ~20 ms end-to-end (fase 5).

## Residual registrado (não corrigido)

* **Parser differential** segue aberto: nenhuma regra casa com o que o Bash
  executa de verdade. Mitigação real é sandbox, não regra.
* **T18** parcialmente coberto: `$HOME`/`${HOME}` agora expande; `$PWD` e
  outras variáveis de ambiente continuam sem expansão.
* **T17** (symlink/TOCTOU) segue fora de escopo (exige `openat2`/sandbox).
* Permitido por design: leitura de `/etc/passwd` e histórico de shell
  (`~/.bash_history`); `.env` do workspace visível se o agente o ler.

## Comando de reprodução

```
cd sentinela
python3 -m unittest discover -s tests -t .        # 143 testes
python3 -m eval.run                               # corpus congelado
python3 -m eval.redteam.build                     # regera cases.jsonl
python3 -m eval.redteam.run                       # corpus principal
python3 -m eval.redteam.run --casos eval/redteam/holdout.json
python3 -m eval.redteam.run --casos eval/redteam/holdout2.json
```
