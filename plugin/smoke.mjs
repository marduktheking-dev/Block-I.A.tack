/**
 * Smoke test de integração: plugin <-> sidecar, sem OpenCode.
 *
 * Verifica o contrato real: o hook `permission.evaluate` é registrado, o evento
 * é traduzido em tool_call, a chamada HTTP acontece e `event.effect` muda
 * conforme o veredito (modo enforce) ou não muda (modo shadow).
 *
 * Requer o sidecar já rodando. Uso:
 *   SENTINELA_URL=http://127.0.0.1:PORT SENTINELA_MODE=enforce \
 *   SENTINELA_LOG=/tmp/sentinela-smoke.jsonl node plugin/smoke.mjs
 */

import { strict as assert } from 'node:assert';

const url = process.env.SENTINELA_URL ?? 'http://127.0.0.1:7878';
const mode = process.env.SENTINELA_MODE ?? 'enforce';

const events = [];
const fakeCtx = {
  permission: {
    async hook(name, cb) {
      events.push({ name, cb });
      return { dispose() {} };
    },
  },
};

const mod = await import('./sentinela.ts');
await mod.default.setup(fakeCtx);

assert.equal(events.length, 1, 'precisa registrar exatamente um hook');
assert.equal(events[0].name, 'evaluate');

const run = async (action, resources, effect = 'allow') => {
  const event = { action, resources, effect, sessionID: 'ses_smoke' };
  await events[0].cb(event);
  return event;
};

const cases = [];
/* No shadow o plugin nunca muda o efeito — mapeia para "allow" (inalterado). */
const esperadoEnforce = { DENY: 'deny', UNCERTAIN: 'ask', ALLOW: 'allow' };
const esperado = (verdictAlvo) => (mode === 'enforce' ? verdictAlvo : 'allow');

const deny = await run('bash', ['rm -rf /etc']);
cases.push(['bash rm -rf /etc', deny.effect, esperado('deny')]);

const allow = await run('bash', ['ls -la']);
cases.push(['bash ls -la', allow.effect, esperado('allow')]);

const ask = await run('bash', ['npm publish']);
cases.push(['bash npm publish', ask.effect, esperado('ask')]);

const writeOutside = await run('edit', ['/etc/passwd']);
cases.push(['edit /etc/passwd', writeOutside.effect, esperado('deny')]);

const writeInside = await run('edit', ['src/main.py']);
cases.push(['edit src/main.py', writeInside.effect, esperado('allow')]);

// Allowlist (fase 7): ferramenta fora da lista não consulta o sidecar e não
// altera o efeito — nem quando o sidecar está fora do ar.
const unwatched = await run('read', ['src/main.py']);
assert.equal(unwatched.effect, 'allow', 'read fora da allowlist deve passar sem tocar o sidecar');

for (const [label, got, want] of cases) {
  console.log(`${got === want ? 'ok  ' : 'FAIL'} ${label}: effect=${got} (esperado ${want})`);
}
assert.deepEqual(cases.map((c) => c[1]), cases.map((c) => c[2]));

// No shadow, o que muda não é o efeito — é o log: cada decisão precisa estar
// registrada com o veredito que o enforce teria aplicado.
if (mode === 'shadow') {
  const { readFileSync, existsSync } = await import('node:fs');
  const { homedir } = await import('node:os');
  const { join } = await import('node:path');
  const logPath = process.env.SENTINELA_LOG
    ?? join(homedir(), '.local', 'share', 'opencode', 'sentinela', 'decisions.jsonl');
  assert.ok(existsSync(logPath), `shadow exige log gravado em ${logPath}`);
  const linhas = readFileSync(logPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const decisoes = linhas.filter((l) => l.type === 'decision');
  assert.ok(decisoes.length >= 5, `esperava >=5 decisões registradas, obtive ${decisoes.length}`);
  const vereditos = decisoes.map((d) => d.verdict);
  assert.ok(vereditos.includes('DENY'), 'log shadow precisa registrar um DENY');
  assert.ok(vereditos.includes('ALLOW'), 'log shadow precisa registrar um ALLOW');
  assert.ok(vereditos.includes('UNCERTAIN'), 'log shadow precisa registrar um UNCERTAIN');
  console.log(`ok   shadow registra decisões no log (${decisoes.length} entradas em ${logPath})`);
}

// Fail-closed: sidecar inalcançável em modo enforce. Precisa de uma instância
// nova do plugin, porque ele lê a URL uma única vez no setup.
process.env.SENTINELA_URL = 'http://127.0.0.1:1';
const deadEvents = [];
const deadCtx = {
  permission: {
    async hook(name, cb) {
      deadEvents.push({ name, cb });
      return { dispose() {} };
    },
  },
};
const deadMod = await import('./sentinela.ts?sidecar=dead');
await deadMod.default.setup(deadCtx);
const dead = { action: 'bash', resources: ['ls -la'], effect: 'allow', sessionID: 'ses_smoke' };
await deadEvents[0].cb(dead);
const deadWant = mode === 'enforce' ? 'deny' : 'allow';
console.log(`${dead.effect === deadWant ? 'ok  ' : 'FAIL'} sidecar fora do ar (modo ${mode}) -> effect=${dead.effect} (esperado ${deadWant})`);
assert.equal(dead.effect, deadWant);
if (mode === 'enforce') {
  assert.match(String(dead.message), /indispon[ií]vel/);
}

console.log('plugin smoke: OK');
