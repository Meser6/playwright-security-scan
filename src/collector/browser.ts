// Browser collector (05, chapters 7 and 8): CSP violation events through an init script and a
// binding, and the end-of-test scan of the cookie jar and Web Storage.
import type { BrowserContext } from '@playwright/test';
import { canonicalOrigin } from '../core/normalize/index.ts';
import type { CookieView } from '../core/types/index.ts';
import { cspListenerScript, readStorage } from './page-script.ts';
import { domainMatches } from './scope.ts';
import type { TestCollector } from './test-collector.ts';

/** Time budget of the end-of-test scan per context (05-REQ-23). */
export const STORAGE_SCAN_BUDGET_MS = 2000;

/** Contexts that already have the init script and binding (once per context). */
const instrumented = new WeakSet<BrowserContext>();

interface CspPayload {
  directive?: unknown;
  blocked?: unknown;
  disposition?: unknown;
  documentURI?: unknown;
}

/**
 * Adds the CSP listener to a context once (05-REQ-20); events go to the collector returned by
 * `current` at the time they arrive. The binding name has a random suffix per run.
 */
export async function instrumentContext(
  context: BrowserContext,
  bindingName: string,
  current: () => TestCollector | undefined,
): Promise<void> {
  if (instrumented.has(context)) return;
  instrumented.add(context);
  await context.exposeBinding(bindingName, (_source, payload: CspPayload) => {
    const collector = current();
    if (collector === undefined || typeof payload !== 'object' || payload === null) return;
    try {
      const documentOrigin = canonicalOrigin(String(payload.documentURI ?? ''));
      if (documentOrigin === null || !collector.options.scope.has(documentOrigin)) return;
      const blocked = String(payload.blocked ?? '');
      // The browser's own favicon request (Firefox) is not the page's doing (WP-02).
      if (/\/favicon\.ico(?:[?#]|$)/i.test(blocked)) return;
      collector.analyzeEvent({
        kind: 'csp-violation',
        documentOrigin,
        directive: String(payload.directive ?? ''),
        blockedOrigin: canonicalOrigin(blocked) ?? blocked.slice(0, 40),
        disposition: payload.disposition === 'report' ? 'report' : 'enforce',
        context: collector.test,
      });
    } catch {
      // never fails the test (P-08)
    }
  });
  await context.addInitScript(cspListenerScript(bindingName));
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`timed out after ${ms} ms`)), ms),
    ),
  ]);
}

const sameSite = (value: string): CookieView['sameSite'] =>
  value === 'Strict' || value === 'None' ? value : 'Lax';

/**
 * End-of-test scan of one context before it closes (05-REQ-23 … 05-REQ-25): the cookie jar of
 * in-scope hosts and Web Storage of every open in-scope page. Values stay in the worker (P-07).
 */
export async function scanContext(
  context: BrowserContext,
  collector: TestCollector,
  storageScan: boolean,
): Promise<void> {
  const scope = collector.options.scope;
  const work = async (): Promise<void> => {
    const origins = scope.listed.filter((o) => !o.includes('*'));
    const originOf = (domain: string): string | undefined =>
      origins.find((o) => domainMatches(new URL(o).hostname, domain));
    const cookies = (await context.cookies())
      .filter((c) => originOf(c.domain) !== undefined)
      .map((c): CookieView => ({
        origin: originOf(c.domain) as string,
        name: c.name,
        value: c.value,
        domain: c.domain,
        path: c.path,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: sameSite(c.sameSite),
        expires: c.expires,
      }));
    if (cookies.length > 0) {
      collector.analyzeEvent({ kind: 'cookie-jar', cookies, context: collector.test });
    }
    if (!storageScan) return;
    const seen = new Set<string>();
    for (const page of context.pages()) {
      if (page.isClosed()) continue;
      const origin = canonicalOrigin(page.url());
      if (origin === null || !scope.has(origin) || seen.has(origin)) continue;
      seen.add(origin);
      const storage = await page.evaluate(readStorage);
      for (const area of ['local', 'session'] as const) {
        const entries = (area === 'local' ? storage.local : storage.session).map(
          ([key, value]) => ({
            key,
            value,
          }),
        );
        collector.analyzeEvent({ kind: 'storage', origin, area, entries, context: collector.test });
      }
    }
  };
  try {
    await withTimeout(work(), STORAGE_SCAN_BUDGET_MS);
  } catch (error) {
    collector.diagnostic(
      'STORAGE_SCAN_FAILED',
      'info',
      `collector: the end-of-test scan of cookies and Web Storage was skipped: ${(error instanceof Error ? error.message : String(error)).split('\n')[0] ?? ''}`,
    );
  }
}
