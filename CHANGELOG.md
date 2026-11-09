# Changelog

## v0.1.0 — 2026-11-09

Primeiro release público (Block-I.A.tack / motor Sentinela).

- **Núcleo L0** determinístico: canonicalização (NFKC, invisíveis, confusáveis,
  ANSI-C, expansão de shell, indireção), 10 classes de efeito, 15 famílias de
  regra, invariante "DENY nunca vira ALLOW", fail-closed.
- **Scorer L1** (logística + calibração isotônica) em modo sombra — não decide.
- **Sidecar HTTP** em loopback com contrato `/health` `/check`, limites de
  corpo e fail-closed.
- **Plugin OpenCode V2** (`permission.evaluate`): shadow/enforce, allowlist de
  ferramentas, log JSONL rotativo, fail-closed; smoke de integração nos dois
  modos.
- **Red team** medido: corpus principal (263), holdout independente (55) e
  holdout secundário (40); números em `docs/fase-6-redteam.md`.
- **CLI**: `check` (códigos de saída), `serve`, `report` (janela de rollout).
