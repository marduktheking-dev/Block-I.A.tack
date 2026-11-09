# Fase 7 — rollout do enforcement (allowlist, observabilidade, rollback)

A fase 7 do plano é o gating final: o guardrail passa a **mudar** a decisão do
OpenCode, primeiro em shadow (não muda nada, só registra), e depois em enforce,
com rollback documentado. Este documento é o roteiro operacional.

## Estado atual (verificado)

| componente | estado |
|---|---|
| núcleo L0 (policy/canonicalize) | 146 testes OK; corpus congelado 610/610 limpo |
| red team | 0/263 + 0/40 + 0/35 pós-correção (in-sample); weakest honest number pré-correção: 22,5% |
| sidecar HTTP (`sentinela.cli serve`) | loopback only; fail-closed |
| plugin OpencodeV2 (`permission.evaluate`) | completo; **não ativado** na config viva |
| allowlist de ações registadas por rolamento | `DEFAULT_TOOLS` (bash/shell/execute/command/write/edit/create/patch/append) |
| relatório de janela (`sentinela.cli report`) | pronto; log ainda inexistente |

## Os três controles

### 1. Allowlist de ferramentas

O plugin apenas avalia ações de permissão cujo `action` está na allowlist;
qualquer outra ação retorna sem tocar o sidecar — custo zero fora do perímetro,
sem poluição de log. Configurável em `~/.config/sentinela/plugin.json`:

```json
{
  "mode": "shadow",
  "url": "http://127.0.0.1:7878",
  "tools": ["bash", "shell", "execute", "command", "write", "edit", "create", "patch", "append"]
}
```

Para **reduzir** o perímetro durante o rollout (mais conservador): remova
itens para efeitos de uso. Para **ampliar**: adicione o nome da ação
(minúsculas) tal como o OpenCode emite no hook `permission.evaluate`.

### 2. Observabilidade da janela

O plugin grava cada decisão observada em JSONL (`decisions.jsonl`, rotação por
truncamento em 5 MiB). O relatório da janela:

```
python3 -m sentinela.cli report                # log padrão do plugin
python3 -m sentinela.cli report --falhas       # + erros de transporte detalhados
python3 -m sentinela.cli report --desde 2026-11-08 --ate 2026-11-15
```

Campos produzidos: total de decisões, vereditos, % que o enforce mudaria
(DENY+UNCERTAIN), contagem de `UNAVAILABLE` (fail-closed acionado), erros de
transporte, latência p50/p95/p99/média/max, volume por dia, e **a lista do que
o enforce teria mudado** — o insumo da revisão de falso positivo.

O critério de saída do plano ("7 dias sem falso positivo grave") é decidido
por **revisão humana** sobre essa lista: nenhuma ação legítima de trabalho
bloqueada ou pedida de forma excessiva. Métrica auxiliar: %mudaria ≤ alvo
acordado (proposta: ≤ 15% em shadow com revisão de cada item).

### 3. Rollback

- Levar o plugin para shadow: `mode: "shadow"` no `plugin.json` e reiniciar a
  sessão — volta a responder sempre "não muda nada". **Isso já é o modo
  padrão**; para ativar enforce, a troca é inversa.
- Parar o guardrail: remover o arquivo em `~/.config/opencode/plugins/` e
  reiniciar; sem plugin, o OpenCode segue sem guardrail (auditável pelo log).
- Se o sidecar estiver fora do ar com `mode: enforce`, **todas as ações
  vigiadas são negadas** (fail-closed) — em produção de agente isso precisa de
  um `systemd`/cron de monitoração ouvoltar a shadow imediatamente.

## Cronograma de ativação (janela de 7 dias)

| dia | modo | observar |
|---|---|---|
| 0 | ativa plugin em `shadow` + sidecar rodando | `plugin.loaded` no log, sem erro |
| 1–7 | uso real do agente, modo shadow | rodar `report` todo dia; auditar item a item os DENY/UNCERTAIN |
| 7 | revisão do relatório | critério: nenhum falso positivo grave |
| 8 | trocar para `enforce` (só com autorização explícita) | monitorar UNAVAILABLE e atrito |
| 9+ | executar; qualquer falso positivo grave → rollback a shadow, corrigir regra, reabrir janela | — |

## Próximas ações — todas exigem autorização explícita do usuário

1. **Ativar o plugin em modo shadow**: copiar `plugin/sentinela.ts` para
   `~/.config/opencode/plugins/sentinela.ts` (muda a config viva).
2. Rodar o sidecar como serviço (script em `~/.config/sentinela/`; sem
   systemd no Termux — pode ser `bash` no `.bashrc` com guarda de porta).
3. Na revisão do dia 7 (com o relatório em mãos), decidir a troca para
   enforce.

---

Documento da fase 7; plano completo em `plans/guardrail-sentinela.md` do
repositório pai. Evidência da fase em `evidencias/fase-7-preparo.txt`.
