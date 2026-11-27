// APIRequestContext traffic (15): wrapping the request methods of one context and turning each
// call into a record of source 'api'. The wrapping pattern follows the perf package so that both
// packages can wrap the same object (15-REQ-02, 01-REQ-09).
import type { APIResponse } from '@playwright/test';
import { canonicalOrigin } from '../core/normalize/index.ts';
import type { Header, ResponseRecord } from '../core/types/index.ts';
import { wrappedRequestContexts } from '../registry/index.ts';
import { bodySkipReason, bodyView } from './body.ts';
import type { TestCollector } from './test-collector.ts';
import type { KeyBuilder } from './tracker.ts';

/** Methods that send a request (15, chapter 2). */
export const API_METHODS = ['fetch', 'get', 'post', 'put', 'patch', 'delete', 'head'] as const;
/** How long the end of a test waits for API analyses in progress (15-REQ-03). */
export const API_DRAIN_BUDGET_MS = 5000;

/** The side of a test that receives API calls. */
export interface ApiSink {
  collector: TestCollector;
  keys: KeyBuilder;
  /** Analyses started for this test; awaited at its end. */
  pending: Set<Promise<void>>;
  /** Origins already reported as out of scope (15-REQ-06). */
  reportedOrigins: Set<string>;
}

/** Synchronous nesting of wrapped calls: get() calling fetch() inside Playwright (15-REQ-02). */
let depth = 0;

const METHOD = /^[A-Z]+$/u;

function callString(target: unknown, name: string): string | undefined {
  if (typeof target !== 'object' || target === null) return undefined;
  const fn = (target as Record<string, unknown>)[name];
  if (typeof fn !== 'function') return undefined;
  const value: unknown = (fn as () => unknown).call(target);
  return typeof value === 'string' ? value : undefined;
}

/** Method and request headers of a call (15, chapter 4). */
export function describeApiCall(
  name: string,
  args: readonly unknown[],
): { method: string; headers: Header[] } | undefined {
  const [target, options] = args;
  const opts =
    typeof options === 'object' && options !== null ? (options as Record<string, unknown>) : {};
  let method = name;
  if (name === 'fetch') {
    method =
      (typeof opts.method === 'string' ? opts.method : undefined) ??
      callString(target, 'method') ??
      'GET';
  }
  method = method.toUpperCase();
  if (!METHOD.test(method)) return undefined;
  const headers: Header[] = [];
  if (typeof opts.headers === 'object' && opts.headers !== null) {
    for (const [key, value] of Object.entries(opts.headers as Record<string, unknown>)) {
      if (typeof value === 'string') headers.push({ name: key.toLowerCase(), value });
    }
  }
  return { method, headers };
}

function isPromise(value: unknown): value is Promise<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

function isApiResponse(value: unknown): value is APIResponse {
  if (typeof value !== 'object' || value === null) return false;
  const r = value as Record<string, unknown>;
  return ['url', 'status', 'headersArray', 'body'].every((n) => typeof r[n] === 'function');
}

/** True for an object that looks like an APIRequestContext. */
export function isApiRequestContext(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const target = value as Record<string, unknown>;
  return ['fetch', 'get', 'post', 'dispose', 'storageState'].every(
    (name) => typeof target[name] === 'function',
  );
}

/** Builds and analyses the record of one API response (15, chapter 4). */
async function analyze(
  sink: ApiSink,
  call: { method: string; headers: Header[] },
  response: APIResponse,
): Promise<void> {
  const { collector, keys } = sink;
  const url = response.url();
  const origin = canonicalOrigin(url);
  if (origin === null) return;
  if (!collector.options.scope.has(origin)) {
    collector.outOfScope(origin);
    if (!sink.reportedOrigins.has(origin)) {
      sink.reportedOrigins.add(origin);
      collector.diagnostic(
        'API_ORIGIN_OUT_OF_SCOPE',
        'info',
        `API calls to ${origin} are out of scope; add it to scope.origins to scan them`,
      );
    }
    return;
  }
  const key = keys({ method: call.method, url, resourceType: 'api' });
  if (!key.ok) return;
  const responseHeaders = response
    .headersArray()
    .map((h) => ({ name: h.name.toLowerCase(), value: h.value }));
  const record: ResponseRecord = {
    kind: 'response',
    id: 0,
    source: 'api',
    method: call.method,
    url,
    endpointKey: key.key,
    origin,
    resourceType: 'api',
    isNavigation: false,
    requestHeaders: call.headers,
    status: response.status(),
    responseHeaders,
    context: collector.test,
  };
  const header = (name: string): string | undefined =>
    responseHeaders.find((h) => h.name === name)?.value;
  const limits = collector.options.config.limits;
  const skip = bodySkipReason({
    resourceType: 'api',
    status: record.status,
    contentType: header('content-type'),
    contentLength: header('content-length'),
    maxBodyBytes: limits.maxBodyBytes,
    allowedTypes: limits.bodyContentTypes,
    wanted: collector.bodyTypes.has('api'),
  });
  if (skip === null) {
    try {
      record.body = bodyView(await response.body(), header('content-type'), limits.maxBodyBytes);
      collector.coverage.bodiesAnalyzed += 1;
    } catch (error) {
      collector.skipBody('read-failed');
      collector.diagnostic(
        'BODY_READ_FAILED',
        'info',
        `collector: the body of an API response could not be read: ${(error instanceof Error ? error.message : String(error)).split('\n')[0] ?? ''}`,
      );
    }
  } else if (skip !== 'no-rule') {
    collector.skipBody(skip);
  }
  collector.analyzeRecord(record);
  delete record.body;
}

/**
 * Wraps the request methods of `context` once (15-REQ-01, 15-REQ-02). A call made while a test of a
 * scanned project runs is analysed by that test after the promise settles; the wrapped method
 * returns the very promise of the original, so the test sees the same value or error (15-REQ-03).
 * Returns false when the context was already wrapped by this package.
 */
export function wrapRequestContext(context: object, sink: () => ApiSink | undefined): boolean {
  const wrapped = wrappedRequestContexts();
  if (wrapped.has(context)) return false;
  wrapped.add(context);
  const target = context as Record<string, unknown>;
  for (const name of API_METHODS) {
    const original = target[name];
    if (typeof original !== 'function') continue;
    const fn = original as (...args: unknown[]) => unknown;
    const wrapper = function (this: unknown, ...args: unknown[]): unknown {
      const active = depth === 0 ? sink() : undefined;
      if (active === undefined) return fn.apply(this, args);
      let call: ReturnType<typeof describeApiCall>;
      try {
        call = describeApiCall(name, args);
      } catch {
        call = undefined;
      }
      depth += 1;
      let result: unknown;
      try {
        result = fn.apply(this, args);
      } finally {
        depth -= 1;
      }
      if (call === undefined || !isPromise(result)) return result;
      const described = call;
      const analysis = result.then(
        (response) => (isApiResponse(response) ? analyze(active, described, response) : undefined),
        () => {
          // The call threw: no record (15-REQ-05); the test gets the error from `result`.
          active.collector.skipBody('request-failed');
        },
      );
      const tracked = analysis.catch((error: unknown) => {
        active.collector.diagnostic(
          'COLLECTOR_ERROR',
          'info',
          `collector: an API response was skipped: ${error instanceof Error ? error.message : String(error)}`,
        );
      });
      active.pending.add(tracked);
      void tracked.finally(() => active.pending.delete(tracked));
      return result;
    };
    Object.defineProperty(target, name, {
      value: wrapper,
      configurable: true,
      enumerable: false,
      writable: true,
    });
  }
  return true;
}

/** Waits for the API analyses of a test (15-REQ-03): at most API_DRAIN_BUDGET_MS. */
export async function drainApi(sink: ApiSink, budgetMs = API_DRAIN_BUDGET_MS): Promise<void> {
  if (sink.pending.size === 0) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<'timeout'>((resolve) => {
    timer = setTimeout(() => resolve('timeout'), budgetMs);
  });
  const result = await Promise.race([Promise.all([...sink.pending]).then(() => 'done'), timeout]);
  clearTimeout(timer);
  if (result === 'timeout') {
    sink.collector.diagnostic(
      'API_ANALYSIS_TIMEOUT',
      'warn',
      `collector: ${sink.pending.size} API responses were still being analysed ${budgetMs} ms after the test ended`,
    );
  }
}
