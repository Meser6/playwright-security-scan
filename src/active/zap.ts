// The attack mode with ZAP (19, P-04 v0.4): starts ZAP in Docker (or uses attack.zapUrl), gives it
// the request templates of the tests, runs the active scan within the budget and maps the alerts.
// Loaded with import() only in PW_SEC_MODE=attack or attack-baseline. Every request ZAP gets passes
// the hard origin check (18-REQ-04); the context limits the scan to attack.allowedOrigins.
import { execFile, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import {
  attackDeniedReason,
  attackOriginAllowed,
  emptyAttackSummary,
} from '../core/attack/config.ts';
import type { ResolvedAttack } from '../core/attack/config.ts';
import { mapAlerts } from '../core/attack/map.ts';
import type { MapOptions } from '../core/attack/map.ts';
import type { AttackRunData, AttackTemplate, ZapAlert } from '../core/attack/types.ts';
import { domainMatchesHost } from '../core/baseline/domain.ts';
import { canonicalOrigin } from '../core/normalize/index.ts';
import type { AttackSummary, Diagnostic } from '../core/types/index.ts';

export const PROBE_HEADER = 'x-pw-sec-probe';
/** How long ZAP may take to answer after the start (19-REQ-04). */
export const START_TIMEOUT_MS = 120_000;
export const POLL_MS = 5_000;
const CALL_TIMEOUT_MS = 60_000;
const SEND_TIMEOUT_MS = 30_000;
/** Without a terminal the progress line is printed every 30 s (19-REQ-07). */
export const CI_PROGRESS_MS = 30_000;

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
}
export type Exec = (cmd: string, args: readonly string[], timeoutMs: number) => Promise<ExecResult>;

const defaultExec: Exec = (cmd, args, timeoutMs) =>
  new Promise((resolve) => {
    execFile(cmd, [...args], { timeout: timeoutMs, windowsHide: true }, (error, stdout, stderr) => {
      const code =
        error === null ? 0 : typeof error.code === 'number' ? error.code : error.code ? -1 : 1;
      resolve({ code, stdout: String(stdout), stderr: String(stderr) });
    });
  });

/** A free local TCP port: ZAP listens on the same number inside and outside the container. */
export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

/** An API call failed (19-REQ-06): the name of the call and the status, never the parameters. */
export class ZapApiError extends Error {
  readonly call: string;
  readonly status: number | null;

  constructor(call: string, status: number | null) {
    super(
      `ZAP API ${call} failed${status === null ? ' (no answer)' : ` with HTTP ${String(status)}`}`,
    );
    this.call = call;
    this.status = status;
  }
}

/** The REST API of ZAP: POST with a form body, the key in X-ZAP-API-Key (19 chapter 11a). */
export class ZapClient {
  readonly #base: string;
  readonly #key: string | undefined;
  readonly #fetch: typeof fetch;

  constructor(base: string, key: string | undefined, fetchFn: typeof fetch = fetch) {
    this.#base = base.replace(/\/+$/, '');
    this.#key = key === '' ? undefined : key;
    this.#fetch = fetchFn;
  }

  async call(
    path: string,
    params: Record<string, string> = {},
    timeoutMs = CALL_TIMEOUT_MS,
  ): Promise<Record<string, unknown>> {
    let response: Response;
    try {
      response = await this.#fetch(`${this.#base}/JSON/${path}/`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          ...(this.#key === undefined ? {} : { 'X-ZAP-API-Key': this.#key }),
        },
        body: new URLSearchParams(params).toString(),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      throw new ZapApiError(path, null);
    }
    const text = await response.text().catch(() => '');
    if (!response.ok) throw new ZapApiError(path, response.status);
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new ZapApiError(path, response.status);
    }
  }
}

const escapeRegex = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Context include patterns, one per origin (19 chapter 11a). */
export function includeRegexes(origins: readonly string[]): string[] {
  return origins.map((o) => `^${escapeRegex(o)}(?:[/?#].*)?$`);
}

/** Context exclude patterns: the logout list and the paths of attack.exclude (19 chapter 11a). */
export function excludeRegexes(origins: readonly string[], exclude: readonly string[]): string[] {
  const out: string[] = [];
  for (const origin of origins) {
    out.push(
      `(?i)^${escapeRegex(origin)}/(?:[^?#]*/)?(?:logout|log-out|signout|sign-out)(?:[/?#].*)?$`,
    );
    for (const pattern of exclude) {
      const path = pattern.replace(/^[A-Z]+ /, '').split('?')[0] ?? '';
      if (!path.startsWith('/')) continue;
      const source = path
        .split('*')
        .map((p) => escapeRegex(p).replace(/:id/g, '[^/?#]+'))
        .join('[^/?#]*');
      out.push(`^${escapeRegex(origin)}${source}(?:[?#].*)?$`);
    }
  }
  return out;
}

/** The raw HTTP/1.1 request of a template for core/action/sendRequest (19-REQ-06). */
export function rawRequest(t: AttackTemplate): string {
  const url = new URL(t.url);
  const lines = [`${t.method} ${t.url} HTTP/1.1`, `Host: ${url.host}`];
  for (const h of t.headers) {
    if (h.name === 'host' || h.name === 'content-length') continue;
    lines.push(`${h.name}: ${h.value}`);
  }
  if (t.body !== undefined) lines.push(`Content-Length: ${String(Buffer.byteLength(t.body))}`);
  return `${lines.join('\r\n')}\r\n\r\n${t.body ?? ''}`;
}

/** The docker run arguments (19-REQ-04, 19-REQ-05, 19 chapter 11a). */
export function dockerRunArgs(o: {
  name: string;
  image: string;
  port: number;
  key: string;
  platform: string;
}): string[] {
  const linux = o.platform === 'linux';
  return [
    'run',
    '--rm',
    '-d',
    '--name',
    o.name,
    ...(linux ? ['--network', 'host'] : ['-p', `127.0.0.1:${String(o.port)}:${String(o.port)}`]),
    o.image,
    'zap.sh',
    '-daemon',
    '-silent',
    // With the host network ZAP listens on the loopback only; in a container on all its addresses.
    '-host',
    linux ? '127.0.0.1' : '0.0.0.0',
    '-port',
    String(o.port),
    '-config',
    `api.key=${o.key}`,
    '-config',
    'api.addrs.addr.name=.*',
    '-config',
    'api.addrs.addr.regex=true',
  ];
}

/** Credential headers of the scan role (19-REQ-06): Cookie from storageState and role headers. */
export function roleHeaders(
  role: AttackRole | null,
  origins: readonly string[],
): Record<string, string> {
  if (role === null) return {};
  const headers: Record<string, string> = { ...role.headers };
  if (role.cookies.length > 0) {
    const cookies = role.cookies.filter((c) =>
      origins.some((o) => domainMatchesHost(o, c.domain.replace(/^\./, '').toLowerCase())),
    );
    if (cookies.length > 0) headers.Cookie = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  }
  return headers;
}

export interface AttackRole {
  name: string;
  cookies: { name: string; value: string; domain: string }[];
  headers: Record<string, string>;
}

/** Cookies of a storageState file; null when it does not exist or cannot be read. */
export function readStorageCookies(path: string): AttackRole['cookies'] | null {
  if (!existsSync(path)) return null;
  try {
    const doc = JSON.parse(readFileSync(path, 'utf8')) as {
      cookies?: { name?: unknown; value?: unknown; domain?: unknown }[];
    };
    return (doc.cookies ?? [])
      .filter(
        (c) =>
          typeof c.name === 'string' && typeof c.value === 'string' && typeof c.domain === 'string',
      )
      .map((c) => ({
        name: c.name as string,
        value: c.value as string,
        domain: c.domain as string,
      }));
  } catch {
    return null;
  }
}

/** Ctrl+C, SIGTERM and process exit during the attack (19 chapter 11a). */
export interface SignalSource {
  on(onSignal: () => void, onExit: () => void): void;
  off(onSignal: () => void, onExit: () => void): void;
}

const processSignals: SignalSource = {
  on(onSignal, onExit) {
    process.once('SIGINT', onSignal);
    process.once('SIGTERM', onSignal);
    process.once('exit', onExit);
  },
  off(onSignal, onExit) {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
    process.off('exit', onExit);
  },
};

export interface AttackOptions {
  attack: ResolvedAttack;
  /** Deduplicated templates in a deterministic order (19 chapter 11a). */
  templates: readonly AttackTemplate[];
  runId: string;
  /** The scan role with its credentials; null: anonymous. */
  role: AttackRole | null;
  keyOf: MapOptions['keyOf'];
  redact: MapOptions['redact'];
  diagnostic(d: Diagnostic): void;
  /** One progress line (19-REQ-07); the caller decides how to print it. */
  progress(line: string): void;
  /** PW_SEC_ZAP_API_KEY for attack.zapUrl. */
  zapApiKey?: string | undefined;
  platform?: string;
  // For tests.
  exec?: Exec;
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  port?: () => Promise<number>;
  pollMs?: number;
  startTimeoutMs?: number;
  /** For tests: where Ctrl+C, SIGTERM and the exit of the process come from. */
  signals?: SignalSource;
  /** For tests: the synchronous docker stop of a signal. */
  stopSync?: (name: string) => void;
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((r) => setTimeout(r, Math.max(0, ms)));

const list = (value: unknown, key: string): string[] => {
  const v = (value as Record<string, unknown> | undefined)?.[key];
  return Array.isArray(v) ? v.map(String) : [];
};

/**
 * The attack after the tests (19, chapter 5): never throws; problems become diagnostics, and the
 * container is stopped on every path, also on Ctrl+C.
 */
export async function runAttack(o: AttackOptions): Promise<AttackRunData> {
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? defaultSleep;
  const exec = o.exec ?? defaultExec;
  const platform = o.platform ?? process.platform;
  const started = now();
  const a = o.attack;
  const summary: AttackSummary = emptyAttackSummary(a, o.role?.name ?? 'anonymous');
  const out: AttackRunData = { summary, findings: [], coveredKeys: [] };
  const done = (): AttackRunData => {
    summary.durationSeconds = Math.round((now() - started) / 1000);
    return out;
  };
  const error = (code: string, message: string): void =>
    o.diagnostic({ code, level: 'error', message });

  // 1. Docker (19-REQ-04 step 1): an error also without templates (19 chapter 11a).
  if (a.zapUrl === null) {
    const version = await exec('docker', ['version', '--format', '{{.Server.Version}}'], 30_000);
    if (version.code !== 0) {
      error(
        'ATTACK_DOCKER_MISSING',
        'attack: Docker is not available (no docker command or no running daemon); install Docker or set attack.zapUrl. The passive scan was evaluated and reported (docs/attack.md).',
      );
      return done();
    }
  }
  if (o.templates.length === 0) {
    o.diagnostic({
      code: 'ATTACK_NO_TEMPLATES',
      level: 'warn',
      message:
        'attack: no request of the tests can be given to ZAP (no response of attack.allowedOrigins with a method of attack.methods); the active scan did not run',
    });
    return done();
  }

  // 2. ZAP: a container of this run or attack.zapUrl.
  let container: string | null = null;
  let stopped = false;
  const stopSync = (): void => {
    if (container === null || stopped) return;
    stopped = true;
    (
      o.stopSync ??
      ((name: string) => {
        spawnSync('docker', ['stop', name], { timeout: 30_000, stdio: 'ignore' });
      })
    )(container);
  };
  let interrupted = false;
  const onSignal = (): void => {
    interrupted = true;
    stopSync();
  };
  const signals = o.signals ?? processSignals;
  signals.on(onSignal, stopSync);
  let client: ZapClient | undefined;
  const created: { context?: string; replacer: string[]; policy?: string } = { replacer: [] };
  try {
    if (a.zapUrl === null) {
      const port = await (o.port ?? freePort)();
      const key = randomBytes(16).toString('hex');
      const name = `pw-sec-zap-${o.runId.replace(/[^A-Za-z0-9_.-]/g, '') || randomBytes(3).toString('hex')}`;
      const run = await exec(
        'docker',
        dockerRunArgs({ name, image: a.image, port, key, platform }),
        300_000,
      );
      if (run.code !== 0) {
        error(
          'ATTACK_ZAP_START_TIMEOUT',
          `attack: the ZAP container (${a.image}) did not start: ${run.stderr.trim().split('\n').pop() ?? ''}`,
        );
        return done();
      }
      container = name;
      const zap = new ZapClient(`http://127.0.0.1:${String(port)}`, key, o.fetch);
      client = zap;
      const deadline = now() + (o.startTimeoutMs ?? START_TIMEOUT_MS);
      for (;;) {
        try {
          summary.zapVersion = String((await zap.call('core/view/version', {}, 5_000)).version);
          break;
        } catch {
          if (now() > deadline || interrupted) {
            error(
              'ATTACK_ZAP_START_TIMEOUT',
              `attack: ZAP did not answer within ${String(Math.round((o.startTimeoutMs ?? START_TIMEOUT_MS) / 1000))} s after the start of the container`,
            );
            return done();
          }
          await sleep(1000);
        }
      }
    } else {
      client = new ZapClient(a.zapUrl, o.zapApiKey, o.fetch);
      summary.zapVersion = String((await client.call('core/view/version')).version);
    }
    const zap = client;

    // 3. Context, credentials, probe header and the scan policy (19-REQ-06).
    const contextName = `pw-sec-${o.runId}`;
    const contextId = String(
      (await zap.call('context/action/newContext', { contextName })).contextId,
    );
    created.context = contextName;
    for (const regex of includeRegexes(a.allowedOrigins))
      await zap.call('context/action/includeInContext', { contextName, regex });
    for (const regex of excludeRegexes(a.allowedOrigins, a.exclude))
      await zap.call('context/action/excludeFromContext', { contextName, regex });
    const headers = roleHeaders(o.role, a.allowedOrigins);
    if (a.probeHeader) headers[PROBE_HEADER] = o.runId;
    for (const [name, value] of Object.entries(headers)) {
      const description = `pw-sec-${o.runId}-${String(created.replacer.length + 1)}`;
      await zap.call('replacer/action/addRule', {
        description,
        enabled: 'true',
        matchType: `REQ_HEADER`,
        matchRegex: 'false',
        matchString: name,
        replacement: value,
      });
      created.replacer.push(description);
    }
    const policy = `pw-sec-${o.runId}`;
    await zap.call('ascan/action/addScanPolicy', {
      scanPolicyName: policy,
      alertThreshold: a.threshold.toUpperCase(),
      attackStrength: a.strength.toUpperCase(),
    });
    created.policy = policy;
    await zap.call('ascan/action/setOptionThreadPerHost', { Integer: '1' });
    await zap.call('ascan/action/setOptionDelayInMs', {
      Integer: String(Math.ceil(1000 / a.maxRps)),
    });
    await zap.call('ascan/action/setOptionMaxScanDurationInMins', {
      Integer: String(Math.ceil(a.maxDurationMinutes)),
    });

    // 4. The templates into the site tree (19-REQ-06), with the hard origin check (18-REQ-04).
    const deadline = started + a.maxDurationMinutes * 60_000;
    const covered = new Set<string>();
    for (const t of o.templates) {
      if (interrupted) break;
      if (summary.requests >= a.maxRequests || now() > deadline) {
        summary.budgetExceeded = true;
        break;
      }
      const origin = canonicalOrigin(t.url);
      if (!attackOriginAllowed(origin, a)) {
        const denied = origin === null ? 'no origin' : attackDeniedReason(origin, a);
        error(
          'ATTACK_ORIGIN_BLOCKED',
          `attack: a request to ${origin ?? 'an unknown origin'} was not given to ZAP: ${denied ?? 'the origin is not in attack.allowedOrigins'}; this is a bug in the package, please report it`,
        );
        continue;
      }
      try {
        await zap.call(
          'core/action/sendRequest',
          { request: rawRequest(t), followRedirects: 'false' },
          SEND_TIMEOUT_MS,
        );
        summary.templates.sent += 1;
        summary.requests += 1;
        covered.add(t.endpointKey);
      } catch (e) {
        summary.templates.failed += 1;
        o.diagnostic({
          code: 'ATTACK_SEND_FAILED',
          level: 'info',
          message: `attack: ZAP could not send ${t.endpointKey}: ${e instanceof Error ? e.message : String(e)}`,
        });
      }
    }
    out.coveredKeys = [...covered].sort();

    // 5. The active scan within the budget (19-REQ-07).
    let scanId: string | null = null;
    if (!interrupted && !summary.budgetExceeded && covered.size > 0) {
      scanId = String(
        (
          await zap.call('ascan/action/scan', {
            contextId,
            inScopeOnly: 'true',
            recurse: 'true',
            scanPolicyName: policy,
          })
        ).scan,
      );
      const sentRequests = summary.requests;
      for (;;) {
        const status = Number((await zap.call('ascan/view/status', { scanId })).status);
        const messages = list(await zap.call('ascan/view/messagesIds', { scanId }), 'messagesIds');
        const alerts = list(await zap.call('ascan/view/alertsIds', { scanId }), 'alertsIds');
        summary.requests = sentRequests + messages.length;
        o.progress(
          `ZAP active scan ${String(Math.min(100, status))}% · ${String(summary.requests)} requests · ${String(alerts.length)} alerts`,
        );
        if (status >= 100) {
          summary.completed = true;
          break;
        }
        if (interrupted) break;
        if (summary.requests >= a.maxRequests || now() > deadline) {
          summary.budgetExceeded = true;
          break;
        }
        await sleep(o.pollMs ?? POLL_MS);
      }
      if (!summary.completed) await zap.call('ascan/action/stop', { scanId });
    }
    if (summary.budgetExceeded) {
      o.diagnostic({
        code: 'ATTACK_BUDGET_EXCEEDED',
        level: 'warn',
        message: `attack: the scan was stopped by the budget (${String(summary.requests)} requests of attack.maxRequests ${String(a.maxRequests)}, attack.maxDurationMinutes ${String(a.maxDurationMinutes)}); the results are partial`,
      });
    }
    if (interrupted) {
      o.diagnostic({
        code: 'ATTACK_INTERRUPTED',
        level: 'warn',
        message: 'attack: the scan was interrupted; the results are partial',
      });
    }

    // 6. The alerts of this scan only (19-REQ-08): passive alerts of ZAP are not read.
    if (scanId !== null) {
      const ids = list(await zap.call('ascan/view/alertsIds', { scanId }), 'alertsIds');
      const alerts: ZapAlert[] = [];
      for (const id of ids) {
        const alert = (await zap.call('alert/view/alert', { id })).alert;
        if (typeof alert === 'object' && alert !== null) alerts.push(alert as ZapAlert);
      }
      const mapped = mapAlerts(alerts, {
        attack: a,
        templates: o.templates,
        keyOf: o.keyOf,
        redact: o.redact,
      });
      out.findings = mapped.findings;
      summary.rules = mapped.rules;
      summary.alerts = { ...summary.alerts, ...mapped.alerts };
      const total = Number((await zap.call('core/view/numberOfAlerts')).numberOfAlerts);
      summary.alerts.passive = Number.isFinite(total) ? Math.max(0, total - ids.length) : 0;
    }
  } catch (e) {
    error(
      'ATTACK_ZAP_API_ERROR',
      `attack: ${e instanceof Error ? e.message : String(e)}; the active scan result is incomplete`,
    );
    summary.completed = false;
  } finally {
    signals.off(onSignal, stopSync);
    // A ZAP of the user lives on: remove what the run added (19 chapter 11a).
    if (a.zapUrl !== null && client !== undefined) {
      const c = client;
      if (created.context !== undefined)
        await c
          .call('context/action/removeContext', { contextName: created.context })
          .catch(() => undefined);
      for (const description of created.replacer)
        await c.call('replacer/action/removeRule', { description }).catch(() => undefined);
      if (created.policy !== undefined)
        await c
          .call('ascan/action/removeScanPolicy', { scanPolicyName: created.policy })
          .catch(() => undefined);
    }
    if (container !== null && !stopped) {
      stopped = true;
      const stop = await exec('docker', ['stop', container], 60_000);
      if (stop.code !== 0) {
        o.diagnostic({
          code: 'ATTACK_ZAP_CLEANUP_FAILED',
          level: 'warn',
          message: `attack: the ZAP container was not stopped; stop it with: docker stop ${container}`,
        });
      }
    }
  }
  return done();
}
