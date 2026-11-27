// The only code of the package that sends requests of its own (P-04 v0.4, 18-REQ-06): the GET/HEAD
// replays of the authorization tests, after the tests, in the reporter (ADR-0011). Loaded with
// import() only when authz.enabled is on and PW_SEC_AUTHZ is not 0. Every request passes the hard
// origin check (18-REQ-04), the budget (18-REQ-14) and carries the probe header (14-REQ-06).
import { existsSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import type { APIRequestContext } from '@playwright/test';
import { deniedReason } from '../core/authz/config.ts';
import type { ResolvedAuthz } from '../core/authz/config.ts';
import { compareReplay } from '../core/authz/digest.ts';
import type { HashFn } from '../core/authz/digest.ts';
import { decidedResult, resultOf } from '../core/authz/plan.ts';
import type { Plan, PlannedReplay, Role } from '../core/authz/plan.ts';
import type { ReplayResult } from '../core/authz/types.ts';
import { canonicalOrigin } from '../core/normalize/index.ts';
import type { Diagnostic } from '../core/types/index.ts';

/** Time limit of one replay (18 chapter 12a). */
export const REPLAY_TIMEOUT_MS = 10_000;
export const PROBE_HEADER = 'x-pw-sec-probe';

export interface ReplayProject {
  name: string;
  storageState: string | undefined;
  ignoreHTTPSErrors: boolean;
}

/** Makes request contexts; tests pass a fake. */
export type ContextFactory = (options: {
  storageState?: string;
  extraHTTPHeaders: Record<string, string>;
  ignoreHTTPSErrors: boolean;
}) => Promise<Pick<APIRequestContext, 'fetch' | 'dispose'>>;

export interface ReplayOptions {
  authz: ResolvedAuthz;
  roles: readonly Role[];
  projects: readonly ReplayProject[];
  runId: string;
  hash: HashFn;
  /** Directory of the Playwright config: relative storageState paths start there. */
  configDir: string;
  maxBodyBytes: number;
  diagnostic(d: Diagnostic): void;
  /** For tests; @playwright/test request.newContext by default. */
  newContext?: ContextFactory;
  /** For tests. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export interface ReplayOutcome {
  results: ReplayResult[];
  used: number;
  exceeded: boolean;
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((r) => setTimeout(r, Math.max(0, ms)));

async function playwrightContexts(): Promise<ContextFactory> {
  const { request } = await import('@playwright/test');
  return (options) =>
    request.newContext({
      ...options,
      // No baseURL: every template has a full URL (18-REQ-14).
    });
}

const TEXT_TYPE = /^(?:application\/(?:[\w.+-]*\+)?json|text\/html|application\/xhtml\+xml)$/;

/**
 * Sends the planned replays one after another (18-REQ-14) and compares each answer with the digest
 * of its original (18-REQ-15). Never throws for a single replay; Ctrl+C ends the replays.
 */
export async function sendReplays(plan: Plan, o: ReplayOptions): Promise<ReplayOutcome> {
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? defaultSleep;
  const factory = o.newContext ?? (await playwrightContexts());
  const deadline = now() + o.authz.maxDurationMinutes * 60_000;
  const gap = 1000 / o.authz.maxRps;
  const projects = new Map(o.projects.map((p) => [p.name, p]));
  const roleOf = new Map(o.roles.map((r) => [r.name, r]));
  const contexts = new Map<string, Pick<APIRequestContext, 'fetch' | 'dispose'>>();
  const missingState = new Set<string>();
  const results: ReplayResult[] = [];
  let used = 0;
  let exceeded = false;
  let interrupted = false;
  let lastStart = Number.NEGATIVE_INFINITY;
  const onSigint = (): void => {
    interrupted = true;
  };
  process.once('SIGINT', onSigint);

  const statePath = (project: string): string | null | undefined => {
    const state = projects.get(project)?.storageState;
    if (state === undefined) return undefined;
    const candidates = isAbsolute(state)
      ? [state]
      : [resolve(o.configDir, state), resolve(process.cwd(), state)];
    return candidates.find((c) => existsSync(c)) ?? null;
  };

  const contextFor = async (
    p: PlannedReplay,
  ): Promise<Pick<APIRequestContext, 'fetch' | 'dispose'> | 'state-missing'> => {
    const ignoreHTTPSErrors = projects.get(p.template.project)?.ignoreHTTPSErrors ?? false;
    const id = `${p.asProject ?? ''}\u0000${String(ignoreHTTPSErrors)}`;
    const known = contexts.get(id);
    if (known !== undefined) return known;
    const headers: Record<string, string> = {};
    let storageState: string | undefined;
    if (p.asProject !== null) {
      const path = statePath(p.asProject);
      if (path === null) {
        if (!missingState.has(p.asProject)) {
          missingState.add(p.asProject);
          o.diagnostic({
            code: 'AUTHZ_STATE_MISSING',
            level: 'warn',
            message: `authz: the storageState file of project ${p.asProject} does not exist; replays as role ${p.asRole} were skipped`,
          });
        }
        return 'state-missing';
      }
      if (path !== undefined) storageState = path;
      const role = roleOf.get(p.asRole);
      const options = o.authz.roles[p.asProject];
      Object.assign(headers, role?.headers ?? {}, options?.headers ?? {});
    }
    if (o.authz.probeHeader) headers[PROBE_HEADER] = o.runId;
    const created = await factory({
      ...(storageState === undefined ? {} : { storageState }),
      extraHTTPHeaders: headers,
      ignoreHTTPSErrors,
    });
    contexts.set(id, created);
    return created;
  };

  try {
    for (const p of plan.replays) {
      const decided = decidedResult(p);
      if (decided !== undefined) {
        results.push(decided);
        continue;
      }
      if (interrupted) {
        results.push(resultOf(p, { result: 'skipped', reason: 'interrupted' }));
        continue;
      }
      if (used >= o.authz.maxRequests || now() > deadline) {
        if (!exceeded) {
          exceeded = true;
          o.diagnostic({
            code: 'AUTHZ_BUDGET_EXCEEDED',
            level: 'warn',
            message: `authz: the budget was used up (${String(used)} of authz.maxRequests ${String(o.authz.maxRequests)} requests, authz.maxDurationMinutes ${String(o.authz.maxDurationMinutes)}); the other replays were skipped`,
          });
        }
        results.push(resultOf(p, { result: 'skipped', reason: 'budget' }));
        continue;
      }
      // The hard check right before sending (18-REQ-03, 18-REQ-04).
      const origin = canonicalOrigin(p.template.url);
      const denied = origin === null ? 'no origin' : deniedReason(origin, o.authz);
      if (origin === null || !o.authz.allowedOrigins.includes(origin) || denied !== null) {
        o.diagnostic({
          code: 'AUTHZ_ORIGIN_BLOCKED',
          level: 'error',
          message: `authz: a replay to ${origin ?? 'an unknown origin'} was blocked: ${denied ?? 'the origin is not in authz.allowedOrigins'}; this is a bug in the package, please report it`,
        });
        results.push(resultOf(p, { result: 'skipped', reason: 'origin-blocked' }));
        continue;
      }
      const ctx = await contextFor(p);
      if (ctx === 'state-missing') {
        results.push(resultOf(p, { result: 'skipped', reason: 'state-missing' }));
        continue;
      }
      await sleep(lastStart + gap - now());
      lastStart = now();
      used += 1;
      const headers = Object.fromEntries(p.template.headers.map((h) => [h.name, h.value]));
      try {
        const response = await ctx.fetch(p.template.url, {
          method: p.template.method,
          headers,
          maxRedirects: 0,
          timeout: REPLAY_TIMEOUT_MS,
          failOnStatusCode: false,
        });
        const type =
          (response.headers()['content-type'] ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
        let body: string | undefined;
        let length = Number(response.headers()['content-length'] ?? 0) || 0;
        if (p.template.method !== 'HEAD') {
          const bytes = await response.body();
          length = bytes.length;
          if (p.template.digest.kind !== 'other' && TEXT_TYPE.test(type)) {
            body = bytes.subarray(0, o.maxBodyBytes).toString('utf8');
          }
        }
        let path = '/';
        try {
          path = new URL(p.template.url).pathname;
        } catch {
          // canonicalOrigin() parsed it already
        }
        const compared = compareReplay(
          p.template.digest,
          { status: response.status(), contentType: type, body, length, path },
          o.hash,
          o.authz.similarity,
        );
        results.push(
          resultOf(p, {
            result: compared.verdict,
            status: response.status(),
            ...(compared.similarity === undefined ? {} : { similarity: compared.similarity }),
            markers: compared.markers,
            kind: compared.kind === p.template.digest.kind ? compared.kind : p.template.digest.kind,
          }),
        );
      } catch (error) {
        o.diagnostic({
          code: 'AUTHZ_REPLAY_FAILED',
          level: 'info',
          message: `authz: the replay of ${p.template.endpointKey} failed: ${(error instanceof Error ? error.message : String(error)).split('\n')[0] ?? ''}`,
        });
        results.push(resultOf(p, { result: 'skipped', reason: 'replay-failed' }));
      }
    }
  } finally {
    process.off('SIGINT', onSigint);
    await Promise.all([...contexts.values()].map((c) => c.dispose().catch(() => undefined)));
  }
  return { results, used, exceeded };
}
