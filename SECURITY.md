# Política de segurança

## Reportando uma vulnerabilidade

Use **GitHub Security Advisories** (aba `Security → Report a vulnerability`)
deste repositório. Não abra issue pública com bypass reproduzível.

- Prazo de resposta alvo: 7 dias para triagem.
- O que é escopo: regras L0 que viram `ALLOW` de algo claramente destrutivo,
  conversão de `DENY` em `ALLOW` (violação do invariante), fail-open do
  sidecar/plugin, e vazamento de segredo via log.
- O que **não** é escopo: bypass heurístico que o modelo de ameaça já declara
  como resíduo (`docs/ameacas.md`, seção residual) — ex.: parser differential
  do Bash, TOCTOU/symlink, decodificadores caseiros.

## Invariante auditável

A propriedade central vale para qualquer contribuição: um veredito `DENY` do
L0 deve permanecer `DENY` após qualquer camada (`fuse()` em
`sentinela/verdict.py`). Qualquer PR que quebre o property test que cobre
isso é rejeitado.
