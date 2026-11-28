// ResponseTracker (05, chapter 5): turns the network events of one browser context during one
// test into response records. Never changes requests (P-04) and never fails the test (P-08).
import type { BrowserContext, Request, Response } from '@playwright/test';
import { canonicalOrigin } from '../core/normalize/index.ts';
import type { KeyResult, KeySample } from '../core/normalize/index.ts';
import type { Header, ResponseRecord } from '../core/types/index.ts';
import { bodySkipReason, bodyView, STATIC_TYPES } from './body.ts';
import type { TestCollector } from './test-collector.ts';

/** Concurrent records per context (05-REQ-09). */
export const CONCURRENCY = 4;
/** How long the teardown waits for records still being built. */
export const DRAIN_BUDGET_MS = 10_000;
/**
 * How long the drain waits for a late requestfinished once the active body reads have settled
 * (05-REQ-09). A body that finishes right after the test fires it within this grace; a no-store
 * response Chromium never finishes (05-REQ-29) then gets a header-only record instead.
 */
export const AWAITING_GRACE_MS = 1000;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export type KeyBuilder = (sample: KeySample) => KeyResult;

const lower = (headers: { name: string; value: string }[]): Header[] =>
  headers.map((h) => ({ name: h.name.toLowerCase(), value: h.value }));

const errorText = (error: unknown): string =>
  (error instanceof Error ? error.message : String(error)).split('\n')[0] ?? '';

export class ResponseTracker {
  readonly context: BrowserContext;
  readonly #collector: TestCollector;
  readonly #keys: KeyBuilder;
  readonly #pending: (() => Promise<void>)[] = [];
  readonly #running = new Set<Promise<void>>();
  readonly #detach: (() => void)[] = [];
  /** Responses with headers but no requestfinished yet: their bodies are still arriving. */
  readonly #awaiting = new Set<Request>();
  /** Order of the responses within the test (06, chapter 4.14). */
  readonly #order = new WeakMap<Request, number>();
  #accepting = true;
  readonly #webkit: boolean;

  constructor(context: BrowserContext, collector: TestCollector, keys: KeyBuilder) {
    this.context = context;
    this.#collector = collector;
    this.#keys = keys;
    this.#webkit = context.browser()?.browserType().name() === 'webkit';
    // Responses whose body has not arrived yet: a context closed during the read loses them
    // without requestfinished (05-REQ-09, 05-AC-03).
    const awaiting = this.#awaiting;
    const lost = (count: number): void => {
      if (count === 0) return;
      this.#collector.diagnostic(
        'BODY_READ_FAILED',
        'info',
        `collector: ${count} response bodies were not complete when the request failed or the context closed`,
      );
    };
    const onResponse = (response: Response): void => {
      const request = response.request();
      awaiting.add(request);
      this.#order.set(request, this.#collector.nextSequence());
    };
    const onFinished = (request: Request): void => {
      awaiting.delete(request);
      this.#enqueue(request);
    };
    const onFailed = (request: Request): void => {
      this.#collector.skipBody('request-failed');
      if (awaiting.delete(request)) lost(1);
    };
    const onClose = (): void => {
      lost(awaiting.size);
      awaiting.clear();
    };
    context.on('response', onResponse);
    context.on('requestfinished', onFinished);
    context.on('requestfailed', onFailed);
    context.on('close', onClose);
    this.#detach.push(
      () => context.off('response', onResponse),
      () => context.off('requestfinished', onFinished),
      () => context.off('requestfailed', onFailed),
      () => context.off('close', onClose),
    );
  }

  #enqueue(request: Request): void {
    if (!this.#accepting) return;
    this.#pending.push(() => this.#process(request));
    this.#pump();
  }

  #pump(): void {
    while (this.#running.size < CONCURRENCY && this.#pending.length > 0) {
      const task = this.#pending.shift() as () => Promise<void>;
      const run: Promise<void> = task()
        .catch((error: unknown) => {
          this.#collector.diagnostic(
            'COLLECTOR_ERROR',
            'info',
            `collector: a response was skipped: ${errorText(error)}`,
          );
        })
        .finally(() => {
          this.#running.delete(run);
          this.#pump();
        });
      this.#running.add(run);
    }
  }

  /** Waits for queued records (before the base fixture closes the context, 05-REQ-09), then detaches. */
  async drain(budgetMs = DRAIN_BUDGET_MS): Promise<void> {
    const deadline = Date.now() + budgetMs;
    const busyReads = (): boolean => this.#running.size > 0 || this.#pending.length > 0;
    // Wait for active body reads, and for flowing bodies to fire requestfinished (a fetch whose
    // body the page did not read finishes right after the test, 05-REQ-09). Once only responses
    // without requestfinished are left, give them a short grace and then move on: a no-store
    // response Chromium never finishes would otherwise hold the drain for the whole budget.
    let graceUntil = Number.POSITIVE_INFINITY;
    while ((busyReads() || this.#awaiting.size > 0) && Date.now() < deadline) {
      if (busyReads()) {
        graceUntil = Number.POSITIVE_INFINITY;
        await Promise.race([
          this.#running.size > 0 ? Promise.all([...this.#running]) : sleep(20),
          sleep(Math.max(0, deadline - Date.now())),
        ]);
      } else {
        if (graceUntil === Number.POSITIVE_INFINITY) graceUntil = Date.now() + AWAITING_GRACE_MS;
        if (Date.now() >= graceUntil) break;
        await sleep(Math.min(20, Math.max(0, graceUntil - Date.now())));
      }
    }
    this.#accepting = false;
    for (const detach of this.#detach) detach();
    this.#detach.length = 0;
    if (this.#pending.length > 0 || this.#running.size > 0) {
      this.#collector.diagnostic(
        'BODY_READ_FAILED',
        'info',
        `collector: ${this.#pending.length + this.#running.size} responses were still being read when the test ended`,
      );
      this.#pending.length = 0;
    }
    // Responses with headers but no requestfinished (Chromium never fires it for a no-store
    // response whose body the page did not read): build a header-only record so the header rules
    // still run (05-REQ-29, 05-AC-05). The context is still open here, so the headers are
    // readable; the body is not read.
    if (this.#awaiting.size > 0) {
      const awaiting = [...this.#awaiting];
      this.#awaiting.clear();
      for (const request of awaiting) this.#pending.push(() => this.#process(request, true));
      this.#pump();
      const flushDeadline = Date.now() + AWAITING_GRACE_MS;
      while ((this.#running.size > 0 || this.#pending.length > 0) && Date.now() < flushDeadline) {
        await Promise.race([
          this.#running.size > 0 ? Promise.all([...this.#running]) : sleep(20),
          sleep(Math.max(0, flushDeadline - Date.now())),
        ]);
      }
      this.#pending.length = 0;
    }
  }

  /** WebKit has no server address for a real 3xx the browser followed (05-REQ-26 v0.7). */
  #followedRedirect(response: Response): boolean {
    return (
      this.#webkit &&
      response.status() >= 300 &&
      response.status() <= 399 &&
      response.request().redirectedTo() !== null
    );
  }

  async #process(request: Request, bodyUnavailable = false): Promise<void> {
    const response: Response | null = await request.response();
    if (response === null) return;
    // Service worker traffic is out of the MVP (05-REQ-26).
    if (request.serviceWorker() !== null) return;
    const url = request.url();
    const origin = canonicalOrigin(url);
    if (origin === null) return;
    const collector = this.#collector;
    const opts = collector.options;
    const inScope = opts.scope.has(origin);
    if (!inScope) collector.outOfScope(origin);
    const resourceType = request.resourceType();
    const key = this.#keys({ method: request.method(), url, resourceType });
    if (!key.ok) return;

    if (inScope && (await response.serverAddr()) === null && !this.#followedRedirect(response)) {
      // route.fulfill(): not analysed (05-REQ-26).
      collector.skipBody('mocked');
      return;
    }

    const [requestHeaders, responseHeaders] = await Promise.all([
      request.headersArray().then(lower),
      response.headersArray().then(lower),
    ]);
    let frameUrl: string | undefined;
    try {
      frameUrl = request.frame().url();
    } catch {
      frameUrl = undefined;
    }
    const record: ResponseRecord = {
      kind: 'response',
      id: this.#order.get(request) ?? collector.nextSequence(),
      source: 'browser',
      method: request.method().toUpperCase(),
      url,
      endpointKey: key.key,
      origin,
      resourceType,
      isNavigation: request.isNavigationRequest(),
      requestHeaders,
      status: response.status(),
      responseHeaders,
      context: collector.test,
    };
    if (frameUrl !== undefined) record.frameUrl = frameUrl;
    const redirectedFrom = request.redirectedFrom()?.url();
    if (redirectedFrom !== undefined) record.redirectedFrom = redirectedFrom;

    if (!inScope) {
      collector.analyzeOutOfScope(record);
      return;
    }
    // Attack templates keep the request body the test sent (19-REQ-03).
    if (collector.attackTemplates?.wants(record) === true) {
      let sent: string | null;
      try {
        sent = request.postData();
      } catch {
        sent = null;
      }
      collector.attackTemplates.add(record, sent);
    }
    // The end-of-test input (05-REQ-27): no values, only hashes and the CSRF signal.
    if (collector.wantsTraffic) {
      let postData: string | null;
      try {
        postData = request.postData();
      } catch {
        postData = null;
      }
      collector.addTraffic(record, postData);
    }
    if (resourceType === 'document' && url.startsWith('https:')) {
      const details = await response.securityDetails().catch(() => null);
      if (details?.protocol !== undefined) record.tls = { protocol: details.protocol };
    }

    if (bodyUnavailable) {
      // No requestfinished arrived by the end of the drain (Chromium never fires it for a no-store
      // response whose body the page did not read): keep a header-only record so the header rules
      // still run (05-REQ-29). Content rules that need a body do not run for it.
      collector.skipBody('incomplete');
      collector.diagnostic(
        'BODY_READ_FAILED',
        'info',
        `collector: a ${resourceType} response had no requestfinished by the end of the test; it was analysed without its body`,
      );
      if (collector.templates?.wants(record) === true) collector.templates.add(record, undefined);
      collector.analyzeRecord(record);
      return;
    }

    const header = (name: string): string | undefined =>
      responseHeaders.find((h) => h.name === name)?.value;
    // A template of the authorization tests needs the body for its digest (05-REQ-28).
    const template = collector.templates?.wants(record) === true ? collector.templates : undefined;
    const ruleWantsBody = collector.bodyTypes.has(resourceType);
    const skip = bodySkipReason({
      resourceType,
      status: record.status,
      contentType: header('content-type'),
      contentLength: header('content-length'),
      maxBodyBytes: opts.config.limits.maxBodyBytes,
      allowedTypes: opts.config.limits.bodyContentTypes,
      wanted: ruleWantsBody || template !== undefined,
    });
    if (skip !== null) {
      if (skip !== 'no-rule') collector.skipBody(skip);
      template?.add(record, undefined);
      collector.analyzeRecord(record);
      return;
    }

    // A static asset already read by this worker is not read again (05-REQ-14, 05-AC-02).
    const validator = header('etag') ?? header('last-modified') ?? header('content-length');
    const staticKey =
      STATIC_TYPES.has(resourceType) && validator !== undefined
        ? `${url}\u0000${validator}`
        : undefined;
    const knownSha = staticKey === undefined ? undefined : opts.cache.hash(staticKey);
    if (knownSha !== undefined) {
      collector.skipBody('cached');
      collector.analyzeRecord(record, knownSha);
      return;
    }

    try {
      const bytes = await response.body();
      record.body = bodyView(bytes, header('content-type'), opts.config.limits.maxBodyBytes);
      collector.coverage.bodiesAnalyzed += 1;
      if (staticKey !== undefined) opts.cache.setHash(staticKey, record.body.sha256);
    } catch (error) {
      collector.skipBody('read-failed');
      collector.diagnostic(
        'BODY_READ_FAILED',
        'info',
        `collector: the body of a ${resourceType} response could not be read: ${errorText(error)}`,
      );
    }
    template?.add(record, record.body?.text);
    // A body read only for the template is not given to the rules.
    if (!ruleWantsBody) delete record.body;
    collector.analyzeRecord(record);
    // The body is dropped with the record (05-REQ-12).
    delete record.body;
  }
}
