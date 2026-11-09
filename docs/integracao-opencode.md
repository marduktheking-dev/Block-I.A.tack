# Integração com o OpenCode (V2)

```
tool call
   │
   ▼
plugin `sentinela.ts`  ──HTTP 127.0.0.1──►  sidecar `python3 -m sentinela.cli serve`
   │                                            │
   │  event.effect = deny/ask/allow            └─ L0 (determinístico) + L1 (sombra)
   ▼
OpenCode executa ou bloqueia
```

## Por que sidecar

O plugin roda em Node; o núcleo é Python. Subir um interpretador por chamada
custaria ~40 ms. O sidecar mantém o modelo carregado e responde em ~0,9 ms;
o custo total medido no plugin foi ~17 ms por decisão (inclui o `fetch` do Node).

## Ponto de integração

`ctx.permission.hook("evaluate")` — documentado para rodar em decisões `allow`
e `ask`, e para aceitar `effect: "allow" | "ask" | "deny"` com `message` que o
modelo vê. É o único ponto usado: não depende de o hook de ferramenta rejeitar
por exceção (semântica não documentada).

Mapeamento de veredito:

| Sentinela | efeito no OpenCode | quando |
|---|---|---|
| `DENY` | `deny` | sempre (modo enforce) |
| `UNCERTAIN` | `ask` | modo enforce |
| `ALLOW` | não altera | — |
| sidecar fora do ar | `deny` | modo enforce (fail-closed) |

Tradução `(action, resources)` → `tool_call`:

| action | vira |
|---|---|
| `bash`, `shell`, `execute`, `command` | `{name:"bash", args:{command: resources.join(" ")}}` |
| `edit`, `write`, `create`, `patch`, `append` | `{name:"write", args:{path: último resource}}` |
| `read`, `list`, `view`, `glob`, `grep` | `{name:"read_file", args:{path: primeiro resource}}` |
| `webfetch`, `fetch`, `http`, `websearch` | `{name:"http_request", args:{url: ...}}` |
| desconhecido com path absoluto | `{name:"write", args:{path}}` |
| desconhecido | `{name:"unknown"}` → L0 responde `UNCERTAIN` |

Formato desconhecido **nunca** vira ALLOW por engano: vira `UNCERTAIN`.

## Subir o sidecar

```bash
cd sentinela
python3 -m sentinela.cli serve --port 7878        # loopback, foreground
```

Só escuta em `127.0.0.1`/`::1`; outra interface é recusada na inicialização.
`GET /health` responde `{"ok":true,"l1":true|false}`.

O serviço não se auto-instala. Para mantê-lo de pé, use o supervisor que você já
usa no Termux (`termux-services`, `runit`, script de `~/.bashrc`) — este projeto
não instala nada no seu ambiente.

## Instalar o plugin

O plugin é um arquivo único, sem dependências:

```bash
ln -s ~/ia-estacao/projetos/sentinela/plugin/sentinela.ts \
      ~/.config/opencode/plugins/sentinela.ts
```

Depois reinicie o serviço do OpenCode para que o plugin seja carregado.

**A instalação não foi executada neste ambiente** — ela altera a configuração
viva do usuário e deve ser feita de forma consciente. O que foi testado está na
seção seguinte.

## Modos

Padrão: `shadow`.

| modo | decide | registra | quando usar |
|---|---|---|---|
| `shadow` | não | sim | medir o guardrail com tráfego real |
| `enforce` | sim | sim | depois do red team |

Configuração, em ordem de precedência: variável de ambiente > arquivo.

```json
// ~/.config/sentinela/plugin.json
{
  "url": "http://127.0.0.1:7878",
  "mode": "shadow",
  "timeout_ms": 300,
  "log": "~/.local/share/opencode/sentinela/decisions.jsonl"
}
```

Variáveis: `SENTINELA_URL`, `SENTINELA_MODE`, `SENTINELA_TIMEOUT_MS`,
`SENTINELA_LOG`.

Log: JSONL append-only, rotação por truncamento em 5 MiB. Cada linha é uma
decisão auditável: ação, resources, tool_call traduzido, veredito, regra, prova,
score do L1, latência do sidecar e latência total, e o `effect` anterior.

## Verificação executada

`plugin/smoke.mjs` roda o plugin real contra o sidecar real, com um `ctx`
falso que captura o hook:

```
ok   bash rm -rf /etc: effect=deny   (esperado deny)
ok   bash ls -la:      effect=allow  (esperado allow)
ok   bash npm publish: effect=ask    (esperado ask)
ok   edit /etc/passwd: effect=deny   (esperado deny)
ok   edit src/main.py: effect=allow  (esperado allow)
ok   sidecar fora do ar -> effect=deny (esperado deny)
```

Isso prova: registro do hook, tradução, contrato HTTP, semântica deny/ask/allow
e fail-closed. **Não** prova o comportamento dentro do processo do OpenCode —
essa parte não foi executada aqui.

## Limites desta integração

- Cobre apenas ações que o OpenCode submete ao sistema de permissões (bash,
  edição, leitura, rede). Ferramenta que não passe por esse caminho não é vista.
- O `message` de negação é texto para o modelo; não é canal de autorização.
- Se o plugin não carregar, o OpenCode segue **sem** guardrail. Não há como o
  plugin garantir a própria presença; isso se audita no log (`plugin.loaded`).
- O sidecar não autentica clientes: qualquer processo local pode perguntar. Ele
  não guarda segredo e não expõe nada além de um veredito.
- A tradução `(action, resources)` é heurística. O formato real pode variar entre
  versões do OpenCode; por isso `unknown` → `UNCERTAIN`, nunca `ALLOW`.
