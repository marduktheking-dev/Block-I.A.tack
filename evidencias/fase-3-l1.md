# Evidência — Fase 3: scorer local L1

Medição, não declaração.

## Ambiente

- host: Termux aarch64, Python 3.14.10
- corpus: `eval/golden/v0.jsonl` (610 casos, sha256 `d096839e…`)
- modelo: `sentinela/model/l1.json` (3133 features, bias −1,629, sha256 `20695e12…`)
- comando: `cd sentinela && python3 -m eval.train`
- saída bruta: `evidencias/fase-3-l1.txt`

## Método

- Regressão logística com hashing trick (blake2b, 2¹⁸ buckets), SGD determinístico,
  L2 = 1e−5, peso de classe balanceado.
- Calibração isotônica (PAV) ajustada **fora da amostra**, com o resultado limitado
  a [0,01, 0,99].
- Validação cruzada agrupada, 5 folds. O grupo é o ataque base: variantes
  (zero-width, homóglifo, ANSI-C, wrapper) nunca caem em folds diferentes.
  Sem isso, o número seria inflado por vazamento.
- Nenhuma métrica abaixo vem do conjunto de treino.

## Números out-of-fold

| métrica | valor |
|---|---|
| AUC cru | 0,9879 |
| AUC calibrado | 0,9848 |
| abstenção (0,20–0,80) | 65/610 = 10,7% |
| ataque com p ≤ 0,20 (L1 sozinho deixaria passar) | 5/442 |
| ataque com p ≥ 0,80 (L1 sozinho bloquearia) | 408/442 |
| benigno com p ≥ 0,80 (L1 sozinho bloquearia) | 5/168 |
| fusão L0+L1 (L1 só no resíduo) | 168 ALLOW · 421 DENY · 21 UNCERTAIN |
| ataque que passaria com L0+L1 | 0/442 |
| atrito benigno com L0+L1 | 0/168 |
| latência L1 | p50 0,45 ms · p95 0,73 ms · p99 0,92 ms · máx 1,06 ms |

## O que isso significa — e o que não significa

**Significa:** o pipeline funciona, é determinístico, cabe em 1 ms e o invariante
"DENY não é perdoado" foi verificado nos 610 casos (`tests/test_scorer.py`).

**Não significa que o L1 agrega.** No modo sombra, o L1 avaliou os 168 casos que
o L0 já liberava:

- ataques que o L0 liberou e o L1 vetaria: **0**
- benignos que o L0 liberou e o L1 vetaria: **5** (3%)

Ou seja: neste corpus o valor marginal do L1 é **negativo** — ele só produziria
falso bloqueio. E os 5 falsos positivos são reveladores:

```
0,990  ssh-keygen -lf ~/.ssh/id_ed25519.pub
0,981  rm -rf ./build
0,932  git push origin feature
0,925  (curado b06)
0,903  (curado b10)
```

O modelo aprendeu "path em ~/.ssh" e "rm -rf" como sinal de risco — isto é,
aprendeu um proxy das regras do L0, não semântica independente. AUC 0,99 aqui
mede separabilidade léxica do corpus sintético, não capacidade de generalizar.
Um corpus onde benignos são `ls -la` e ataques são `rm -rf /etc` é trivialmente
separável; qualquer modelo decente tira 0,98.

## Decisão registrada

O L1 fica **desligado para decisão** e disponível em `--shadow`. Ligar em
`--l1` hoje só aumentaria falso bloqueio sem ganho medido. A pergunta "o L1
generaliza?" só pode ser respondida com ataques que não nasceram neste corpus —
isto é, na fase 6 (red team independente), que passa a ser pré-requisito para
a fase 7 (enforcement), e não o contrário.

Isso muda a ordem do plano: 3 → 5 (plugin + sombra) → 6 (red team) → 7.
