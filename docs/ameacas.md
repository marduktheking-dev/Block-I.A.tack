# Modelo de ameaça — Sentinela

**Fase**: 0 do plano `plans/guardrail-sentinela.md`
**Data**: 2026-11-08
**Método**: STRIDE adaptado a agente + catálogo de ataques específicos de *tool call*

---

## 1. Ativos

| Ativo | Por que importa |
|---|---|
| Credenciais (`~/.ssh`, `.env`, tokens de API, chaves de assinatura) | exfiltração direta, persistência |
| Integridade do workspace e do VPS `10.0.0.150` | destruição, ransomware |
| Código e histórico git | reescrita, supply chain, vazamento de segredo em commit |
| Contas externas (npm, GitHub, cloud, banco) | publicação, gasto, lockout |
| Trilha de auditoria | responsabilização; sem ela não há controle |
| Disponibilidade do próprio agente | DoS via latência do guardrail |

## 2. Fronteira de confiança

```
[ usuário ] --confiável--> [ agente/LLM ] --proposta--> [ SENTINELA ] --autorizado--> [ ferramenta ]
                                  ^                            |
                                  |                            +--> [ trilha ]
                        [ conteúdo externo ]  <- NÃO CONFIÁVEL
         (saída de tool, descrição de MCP, arquivo lido, página web, nome de arquivo)
```

Regra estrutural: **conteúdo externo nunca é fonte de autorização.** Um `ToolMessage`, uma
descrição de MCP ou o conteúdo de um arquivo podem *descrever* o pedido; só o turno explícito do
usuário *autoriza*. Essa é a falha exata do teste da Octomind contra o Jev (P(block) 0,76 → 0,48).

## 3. Ameaças

| ID | Vetor | Impacto | Controle | Teste |
|---|---|---|---|---|
| T01 | Comando destrutivo direto (`rm -rf /etc`, `rm -rf ~`) | perda total | regra + path canônico | `test_rm_rf_etc_is_denied`, `test_rm_rf_workspace_root_is_denied` |
| T02 | Injeção via saída de ferramenta ("usuário pré-aprovou") | confusão de autoridade | L0 não lê saída de ferramenta; L2 recebe estado sanitizado | `test_marker_cannot_pardon_deny` |
| T03 | Injeção via descrição de tool/MCP | execução não autorizada | descrição nunca entra como instrução; marcadores viram UNCERTAIN | `test_marker_forces_uncertain` |
| T04 | Traversal / path relativo malicioso (`/tmp/../etc/shadow`) | leitura de segredo | `normpath` + `realpath` + raiz de workspace | `test_traversal_to_ssh_is_denied`, `test_percent_decoded` |
| T05 | Ofuscação: zero-width, bidi, homóglifo, ANSI-C, percent | bypass de regra | canonicalização antes de qualquer regra | `test_homoglyph_bypass_is_denied`, `test_ansi_c_quoting` |
| T06 | Exfiltração de segredo em egresso | vazamento | taint + allowlist de host + padrões de segredo | `test_secret_to_unknown_host_is_denied` |
| T07 | Execução remota (`curl \| sh`, `bash <(...)`) | RCE | regex sobre texto normalizado + recursão em `-c` | `test_curl_pipe_sh_is_denied`, `test_bash_process_substitution_is_denied` |
| T08 | Destruição de dispositivo / fork bomb | brick / DoS | `dd of=/dev/*`, `mkfs`, fork bomb | `test_device_write_is_denied`, `test_fork_bomb_is_denied` |
| T09 | Persistência (cron, systemd, `authorized_keys`) | acesso duradouro | efeito `persist` + path protegido | `test_systemctl_enable_is_uncertain` |
| T10 | Escalada de privilégio (`sudo`, `nsenter`, `setcap`) | root | efeito `privilege` | `test_sudo_is_uncertain` |
| T11 | DDL/DML destrutivo (`DROP`, `DELETE` sem `WHERE`) | perda de dados | análise do payload SQL | `test_drop_table_is_denied` |
| T12 | `git push --force` em `main` / reescrita de história | perda de código | regra por branch + flag | `test_force_push_main_is_denied` |
| T13 | Publicação acidental (`npm publish`, `twine upload`) | release não intencional | efeito `publish` | `test_publish_is_uncertain` |
| T14 | *Confused deputy*: o agente se autoriza | qualquer | autorização só do turno do usuário | `test_marker_cannot_pardon_deny` |
| T15 | DoS do guardrail (payload gigante, regex catástrofe) | parada do agente | limite de tamanho + timeout + fail-closed | pendente (fase 5) |
| T16 | Supply chain (`pip install git+http://…`) | RCE | efeito `network_out` + `exec` | coberto pelos red teams 1 e 2 (`pip/twine/npx/uvx` → UNCERTAIN+egresso) |
| T17 | Symlink / TOCTOU entre checagem e execução | escrita indevida | **fora de escopo do L0** (exige sandbox/`openat2`) | declarado |
| T18 | Segredo em variável de ambiente (`$TOKEN`) | exfiltração | **parcial** — `$HOME`/`${HOME}` expande; `$TOKEN` não expande, mas o *nome* tinta egresso (`SEC_EGRESS_TAINT_001`); valor não resolvido → UNCERTAIN | parcial |

## 4. Classes de efeito (vocabulário comum L0 ↔ L1)

`read · write · delete · exec · network_out · privilege · persist · secret_access · publish · spend`

Toda regra declara qual efeito justifica. Toda chamada devolve o conjunto de efeitos observados,
o que permite ao L1 aprender sobre features estáveis em vez de strings cruas.

## 5. Ataques ao próprio guardrail

| Ataque | Defesa | Residual |
|---|---|---|
| *Parser differential*: o guardrail vê X, o shell executa Y | canonicalização + recursão em `sh -c`/`$(...)` + tokenização com falha explícita | **alto** — nenhum parser caseiro é o Bash. Mitigação real é executar em sandbox |
| Reordenar opções para virar o veredito | L0 não usa Choice; L2 randomiza e exige concordância | médio |
| Inundar o estado com ruído para baixar a probabilidade | estado mínimo no L2; L0 ignora prosa | baixo |
| "Pré-aprovação" plantada em argumento | marcadores → UNCERTAIN; nunca converte DENY em ALLOW | baixo |
| Vencer por latência (timeout) | timeout curto → ASK/BLOCK, nunca ALLOW | baixo |
| Envenenar o corpus de treino do L1 | corpus rotulado por regra + revisão; held-out separado | médio (fase 3) |

## 6. Fora de escopo (declarado, não esquecido)

- Sandbox de execução, seccomp, namespaces, limites de CPU/memória.
- Detecção de comportamento malicioso *depois* da execução.
- Vazamento por canal lateral (timing, tamanho de resposta).
- Autenticação do usuário (quem é o humano que aprova).
- Modelo de ameaça de insider com acesso ao próprio código do guardrail.

O Sentinela **decide**; ele não **contém**. Quem contém é o sandbox — e os dois são complementares.
