# Evidência — Fase 5: sidecar + plugin OpenCode

## Ambiente

- OpenCode instalado: `opencode-termux` v2.0.21 (upstream 2.2.0), plugins locais
  em `~/.config/opencode/plugins/*.ts`
- Node v24.22.2 (executa o `.ts` do plugin direto, por type stripping nativo)
- Python 3.14.10 · Termux aarch64

## O que foi executado

1. `python3 -m sentinela.cli serve --port 7879`
2. `SENTINELA_MODE=enforce node plugin/smoke.mjs`
3. `python3 -m unittest discover -s tests -t .`

## Resultado do smoke (plugin real + sidecar real)

```
ok   bash rm -rf /etc: effect=deny   (esperado deny)
ok   bash ls -la:      effect=allow  (esperado allow)
ok   bash npm publish: effect=ask    (esperado ask)
ok   edit /etc/passwd: effect=deny   (esperado deny)
ok   edit src/main.py: effect=allow  (esperado allow)
ok   sidecar fora do ar -> effect=deny (esperado deny)
plugin smoke: OK
```

Linha de log produzida (truncada):

```json
{"type":"decision","mode":"enforce","action":"bash","resources":["ls -la"],
 "tool_call":{"name":"bash","args":{"command":"ls -la"}},"verdict":"ALLOW",
 "scores":{"p_risky":0.01,"abstained":false},"sidecar_latency_ms":0.839,
 "total_latency_ms":17,"opencode_effect_before":"allow"}
```

E no cenário de indisponibilidade:

```json
{"verdict":"DENY","scores":null,"error":"fetch failed","total_latency_ms":3}
```

## Testes automatizados

105 testes `OK` (1,21 s), incluindo 9 do sidecar:

- corpo inválido → `DENY` (500)
- payload sem `tool_call` → `DENY` (400)
- modo desconhecido → `DENY` (400)
- corpo > 1 MiB → `DENY` (413)
- rota desconhecida → 404
- `/health` responde `ok` e o estado do L1
- veredito `DENY`/`ALLOW`/`UNCERTAIN` no contrato HTTP

## O que NÃO foi executado

**A instalação no OpenCode.** O plugin não foi copiado para
`~/.config/opencode/plugins/` nem carregado pelo processo do OpenCode. Portanto:

- "arquivo presente": sim (`plugin/sentinela.ts`)
- "contrato verificado com ctx falso + sidecar real": sim
- "integração ativa no OpenCode": **não**

Ativar altera a configuração viva do usuário. Comando e efeito estão em
`docs/integracao-opencode.md`; a ativação pede decisão explícita.

## Latência observada

| etapa | p50 |
|---|---|
| L0 | 0,51 ms |
| L0+L1 no sidecar | 0,84 ms |
| plugin → sidecar → plugin (ida e volta completa) | ~17 ms |

17 ms é o custo do `fetch` do Node, não do guardrail. Ainda assim é ~4× menor
que o piso publicado do Jev (70 ms) e não depende de rede externa.
