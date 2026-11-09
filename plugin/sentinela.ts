/**
 * Sentinela — guardrail de chamadas de ferramenta para o OpenCode (V2).
 *
 * Ponto de integração: hook `permission.evaluate`. Ele roda tanto para decisões
 * `allow` quanto `ask`, então é o único lugar em que dá para transformar uma
 * liberação em bloqueio sem depender de semântica não documentada de exceção
 * em outro hook.
 *
 * Mapeamento de veredito -> efeito do OpenCode:
 *
 *   DENY      -> effect "deny"  (com motivo na mensagem que o modelo vê)
 *   UNCERTAIN -> effect "ask"   (só no modo enforce)
 *   ALLOW     -> não mexe
 *
 * Modos:
 *   shadow  (padrão) — consulta o Sentinela e grava o que ele teria feito,
 *                      mas nunca altera a decisão do OpenCode.
 *   enforce         — aplica DENY/UNCERTAIN.
 *
 * Fail-closed: no modo enforce, se o sidecar não responder, a ação é negada.
 * No modo shadow, indisponibilidade só gera linha de log.
 *
 * Configuração (env > arquivo `~/.config/sentinela/plugin.json`):
 *   { "url": "http://127.0.0.1:7878", "mode": "shadow", "timeout_ms": 300 }
 *
 * Este arquivo não importa nada: o plugin é carregado direto pelo OpenCode.
 */

import { appendFileSync, mkdirSync, openSync, closeSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

type Rec = Record<string, unknown>;

const CONFIG_PATH = join(homedir(), '.config', 'sentinela', 'plugin.json');
const LOG_PATH = join(homedir(), '.local', 'share', 'opencode', 'sentinela', 'decisions.jsonl');
const LOG_MAX_BYTES = 5 * 1024 * 1024;
const DEFAULT_URL = 'http://127.0.0.1:7878';
const DEFAULT_TIMEOUT_MS = 300;

/** Rollout por allowlist (fase 7): só essas ações passam pelo guardrail. */
const DEFAULT_TOOLS = [
  'bash', 'shell', 'execute', 'command',
  'write', 'edit', 'create', 'patch', 'append',
];

function rec(v: unknown): Rec | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Rec) : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

function readConfig(): Rec {
  try {
    return rec(JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))) ?? {};
  } catch {
    return {};
  }
}

function logPath(): string {
  const override = process.env.SENTINELA_LOG;
  if (override) return override;
  const cfg = readConfig();
  return str(cfg.log) ?? LOG_PATH;
}

/** Rotação simples: se passou do limite, o arquivo é truncado (não cresce sem fim). */
function rotateIfNeeded(path: string): void {
  try {
    if (statSync(path).size > LOG_MAX_BYTES) {
      const fd = openSync(path, 'w');
      closeSync(fd);
    }
  } catch {
    /* arquivo ainda não existe */
  }
}

function writeLog(entry: Rec): void {
  try {
    const path = logPath();
    mkdirSync(dirname(path), { recursive: true });
    rotateIfNeeded(path);
    appendFileSync(path, JSON.stringify(entry) + '\n', 'utf8');
  } catch {
    /* log não pode derrubar a decisão */
  }
}

/**
 * Converte (action, resources) do OpenCode em uma chamada no formato do Sentinela.
 * Heurística declarada: se o formato não for reconhecido, manda como path e o
 * L0 responde UNCERTAIN — nunca ALLOW por engano.
 */
function toToolCall(action: string, resources: readonly string[]): Rec {
  const a = action.toLowerCase();
  const first = resources[0] ?? '';
  const last = resources[resources.length - 1] ?? '';

  if (a === 'bash' || a === 'shell' || a === 'execute' || a === 'command') {
    return { name: 'bash', args: { command: resources.join(' ') } };
  }
  if (a === 'edit' || a === 'write' || a === 'create' || a === 'patch' || a === 'append') {
    return { name: 'write', args: { path: last || first } };
  }
  if (a === 'read' || a === 'list' || a === 'view' || a === 'glob' || a === 'grep') {
    return { name: 'read_file', args: { path: first } };
  }
  if (a === 'webfetch' || a === 'fetch' || a === 'http' || a === 'websearch') {
    return { name: 'http_request', args: { url: first, method: 'GET' } };
  }
  if (first.startsWith('/') || first.startsWith('~') || first.startsWith('.')) {
    return { name: 'write', args: { path: first } };
  }
  return { name: 'unknown', args: { path: first } };
}

interface Decision {
  verdict: 'ALLOW' | 'UNCERTAIN' | 'DENY';
  reason?: { layer?: string; rule_id?: string | null; proof?: string };
  scores?: { p_risky?: number | null; abstained?: boolean | null };
  latency_ms?: number;
  model_id?: string;
  [key: string]: unknown;
}

async function check(toolCall: Rec, mode: string, url: string, timeoutMs: number, sessionID?: string): Promise<Decision> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${url}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool_call: toolCall, mode, session_id: sessionID }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`http ${response.status}`);
    const body = (await response.json()) as Decision;
    if (!body || typeof body.verdict !== 'string') throw new Error('resposta sem verdict');
    return body;
  } finally {
    clearTimeout(timer);
  }
}

function mission(payload: Rec): string {
  const reason = rec(payload.reason);
  const rule = str(reason?.rule_id);
  const proof = str(reason?.proof);
  const scores = rec(payload.scores);
  const p = typeof scores?.p_risky === 'number' ? ` p=${scores.p_risky.toFixed(3)}` : '';
  return `[sentinela] ${str(payload.verdict) ?? 'DENY'} ${rule ?? ''}${p}`.trim() + (proof ? ` — ${proof}` : '');
}

export default {
  id: 'sentinela',
  async setup(ctx: unknown): Promise<() => void> {
    const c = rec(ctx);
    const cfg = readConfig();
    const url = process.env.SENTINELA_URL ?? str(cfg.url) ?? DEFAULT_URL;
    const mode = process.env.SENTINELA_MODE ?? str(cfg.mode) ?? 'shadow';
    const timeoutMs = Number(process.env.SENTINELA_TIMEOUT_MS ?? cfg.timeout_ms ?? DEFAULT_TIMEOUT_MS);
    const enforce = mode === 'enforce';

    const permission = rec(rec(c)?.permission);
    const hook = permission?.hook as
      | ((name: string, cb: (event: Rec) => Promise<void> | void) => Promise<unknown>)
      | undefined;

    /** Allowlist do rollout: configurável; fora dela, custo zero. */
    const toolsCfg = Array.isArray(cfg.tools) ? (cfg.tools as unknown[]).map(String) : DEFAULT_TOOLS;
    const watched = new Set(toolsCfg.map((t) => t.toLowerCase()));

    writeLog({ ts: new Date().toISOString(), type: 'plugin.loaded', mode, url, timeout_ms: timeoutMs, tools: toolsCfg });

    if (typeof hook !== 'function') {
      // Sem o hook, o plugin não finge que protege.
      writeLog({ ts: new Date().toISOString(), type: 'plugin.unsupported', reason: 'permission.hook ausente' });
      return () => {};
    }

    await hook('evaluate', async (event: Rec) => {
      const action = str(event.action) ?? 'unknown';
      const resources = Array.isArray(event.resources) ? (event.resources as string[]).filter((r) => typeof r === 'string') : [];

      // Fora da allowlist de ferramentas: nem consulta o sidecar (custo zero).
      if (!watched.has(action.toLowerCase())) return;

      const sessionID = str(event.sessionID);
      const toolCall = toToolCall(action, resources);
      const started = Date.now();

      let decision: Decision | undefined;
      let failure = '';
      try {
        decision = await check(toolCall, mode, url, timeoutMs, sessionID);
      } catch (err) {
        failure = err instanceof Error ? err.message : String(err);
      }

      const record: Rec = {
        ts: new Date().toISOString(),
        type: 'decision',
        mode,
        session: sessionID,
        action,
        resources,
        tool_call: toolCall,
        verdict: decision?.verdict ?? (enforce ? 'DENY' : 'UNAVAILABLE'),
        reason: decision?.reason ?? null,
        scores: decision?.scores ?? null,
        sidecar_latency_ms: decision?.latency_ms ?? null,
        total_latency_ms: Date.now() - started,
        error: failure || undefined,
        opencode_effect_before: event.effect,
      };
      writeLog(record);

      if (!enforce) return;

      if (!decision) {
        event.effect = 'deny';
        event.message = `[sentinela] indisponível (${failure}); bloqueio por fail-closed`;
        return;
      }
      if (decision.verdict === 'DENY') {
        event.effect = 'deny';
        event.message = mission(decision as unknown as Rec);
        return;
      }
      if (decision.verdict === 'UNCERTAIN') {
        event.effect = 'ask';
        event.message = mission(decision as unknown as Rec);
      }
    });

    return () => {
      writeLog({ ts: new Date().toISOString(), type: 'plugin.unloaded' });
    };
  },
};
