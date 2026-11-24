// withSecurityFixtures(), trackContext() (05, chapter 3). Outside scan mode only the `security`
// fixture is added and nothing else changes (05-REQ-01, P-02).
import { randomBytes } from 'node:crypto';
import { relative } from 'node:path';
import type { BrowserContext, Page, TestInfo, TestType } from '@playwright/test';
import { resolveConfig } from '../core/config/index.ts';
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import { Redactor } from '../core/fingerprint/index.ts';
import { canonicalOrigin, createKeyBuilder } from '../core/normalize/index.ts';
import { BUILT_IN_RULES } from '../core/rules/index.ts';
import type { TestContextRef } from '../core/types/index.ts';
import { instrumentContext, scanContext } from '../collector/browser.ts';
import { Scope } from '../collector/scope.ts';
import { AnalysisCache, ATTACHMENT_NAME, TestCollector } from '../collector/test-collector.ts';
import { ResponseTracker } from '../collector/tracker.ts';
import type { KeyBuilder } from '../collector/tracker.ts';
import { SALT_ENV, scanModeOn } from '../mode/index.ts';
import {
  activeCollector,
  getRegistered,
  setActiveCollector,
  trackedContexts,
  wrappedTests,
} from '../registry/index.ts';

/** The `security` fixture (05, chapter 3). */
export interface SecurityApi {
  /** Scans a context created in the test, e.g. with browser.newContext() (05-REQ-02). */
  track(context: BrowserContext): Promise<void>;
}

export interface SecurityFixtures {
  security: SecurityApi;
}

/** `base` with the `security` fixture added; other fixtures keep their types. */
export type SecurityTestType<T> =
  T extends TestType<infer TestArgs, infer WorkerArgs>
    ? TestType<TestArgs & SecurityFixtures, WorkerArgs>
    : never;

/** Per-worker state: config, scope, keys, redaction and the analysis cache. */
interface WorkerState {
  config: ResolvedSecurityConfig;
  scope: Scope;
  keys: KeyBuilder;
  redactor: Redactor;
  cache: AnalysisCache;
  binding: string;
  scannedProjects: string[] | 'all';
  /** withSecurity() was not applied in this process (01-REQ-06). */
  configMissing: boolean;
}

let worker: WorkerState | undefined;

function workerState(baseURL: string | undefined): WorkerState {
  if (worker !== undefined) return worker;
  const registered = getRegistered();
  const fallback = resolveConfig(undefined);
  const config = registered?.config ?? (fallback.ok ? fallback.config : (undefined as never));
  const baseOrigin = baseURL === undefined ? null : canonicalOrigin(baseURL);
  const baseOrigins = registered?.baseOrigins ?? (baseOrigin === null ? [] : [baseOrigin]);
  const salt = process.env[SALT_ENV] || registered?.salt || randomBytes(16).toString('hex');
  const paramNames = config.rules['data.token-in-url']?.options.paramNames;
  worker = {
    config,
    scope: new Scope({
      baseOrigins,
      includeBaseURL: config.scope.includeBaseURL,
      origins: config.scope.origins,
      exclude: config.scope.exclude,
    }),
    keys: createKeyBuilder(config.normalization, { baseOrigins }),
    redactor: new Redactor({
      salt,
      paramNames: Array.isArray(paramNames) ? (paramNames as string[]) : [],
    }),
    cache: new AnalysisCache(),
    binding: `__pwSec_${salt.slice(0, 8)}`,
    scannedProjects: registered?.scannedProjects ?? 'all',
    configMissing: registered === undefined,
  };
  return worker;
}

/** TestContextRef of a test (02, chapter 2). */
export function testRef(testInfo: TestInfo): TestContextRef {
  const root = testInfo.config.rootDir;
  return {
    testId: testInfo.testId,
    // titlePath starts with the file name; the reports show the file separately.
    titlePath: testInfo.titlePath.slice(1),
    file: relative(root, testInfo.file).split('\\').join('/'),
    line: testInfo.line,
    project: testInfo.project.name,
  };
}

/** The scan of one test: its collector and the trackers of its contexts. */
class TestScan {
  readonly collector: TestCollector;
  readonly #state: WorkerState;
  readonly #trackers = new Map<BrowserContext, ResponseTracker>();
  readonly #finished = new Set<BrowserContext>();

  constructor(collector: TestCollector, state: WorkerState) {
    this.collector = collector;
    this.#state = state;
  }

  async track(context: BrowserContext): Promise<void> {
    if (this.#trackers.has(context)) return;
    this.#trackers.set(context, new ResponseTracker(context, this.collector, this.#state.keys));
    if (this.#state.config.browser.cspEvents) {
      try {
        await instrumentContext(
          context,
          this.#state.binding,
          () => activeCollector<TestScan>()?.collector,
        );
      } catch (error) {
        this.collector.diagnostic(
          'COLLECTOR_ERROR',
          'info',
          `collector: the CSP listener could not be added: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  /** End-of-test scan and drain of one context, before it closes (05-REQ-23, 05-REQ-09). */
  async finish(context: BrowserContext): Promise<void> {
    if (this.#finished.has(context)) return;
    this.#finished.add(context);
    const tracker = this.#trackers.get(context);
    if (tracker === undefined) return;
    await scanContext(context, this.collector, this.#state.config.browser.storageScan);
    await tracker.drain();
  }

  async finishAll(): Promise<void> {
    for (const context of this.#trackers.keys()) await this.finish(context);
  }
}

interface SecBuffer {
  scan: TestScan | null;
  api: SecurityApi;
}

const PASSIVE_API: SecurityApi = {
  track: async () => {
    // Nothing is scanned outside scan mode or in projects that are not scanned.
  },
};

function openBuffer(baseURL: string | undefined, testInfo: TestInfo): SecBuffer {
  const state = workerState(baseURL);
  if (state.scannedProjects !== 'all' && !state.scannedProjects.includes(testInfo.project.name)) {
    return { scan: null, api: PASSIVE_API };
  }
  const collector = new TestCollector({
    config: state.config,
    rules: BUILT_IN_RULES,
    scope: state.scope,
    redactor: state.redactor,
    cache: state.cache,
    test: testRef(testInfo),
  });
  if (state.configMissing) {
    collector.diagnostic(
      'CONFIG_MISSING',
      'error',
      'config: withSecurityFixtures() is used but withSecurity() was not applied to the Playwright config; the defaults are used',
    );
  }
  const scan = new TestScan(collector, state);
  return { scan, api: { track: (context) => scan.track(context) } };
}

/* eslint-disable no-empty-pattern -- Playwright reads fixture dependencies from the pattern. */
const passiveFixtures = {
  security: async ({}, use: (api: SecurityApi) => Promise<void>): Promise<void> => {
    await use(PASSIVE_API);
  },
};
/* eslint-enable no-empty-pattern */

const scanFixtures = {
  _secBuffer: [
    async (
      { baseURL }: { baseURL: string | undefined },
      use: (buffer: SecBuffer) => Promise<void>,
      testInfo: TestInfo,
    ): Promise<void> => {
      const buffer = openBuffer(baseURL, testInfo);
      const scan = buffer.scan;
      if (scan !== null) {
        setActiveCollector(scan);
        for (const context of trackedContexts()) await scan.track(context as BrowserContext);
      }
      await use(buffer);
      if (scan === null) return;
      await scan.finishAll();
      if (activeCollector() === scan) setActiveCollector(undefined);
      await testInfo.attach(ATTACHMENT_NAME, {
        body: scan.collector.attachment(),
        contentType: 'application/json',
      });
    },
    { auto: true, box: true },
  ],
  context: async (
    { context, _secBuffer }: { context: BrowserContext; _secBuffer: SecBuffer },
    use: (context: BrowserContext) => Promise<void>,
  ): Promise<void> => {
    await _secBuffer.scan?.track(context);
    await use(context);
    // Before the base fixture closes the context (05-REQ-09, 05-REQ-23).
    await _secBuffer.scan?.finish(context);
  },
  page: async (
    { page, _secBuffer }: { page: Page; _secBuffer: SecBuffer },
    use: (page: Page) => Promise<void>,
  ): Promise<void> => {
    await _secBuffer.scan?.track(page.context());
    await use(page);
  },
  security: async (
    { _secBuffer }: { _secBuffer: SecBuffer },
    use: (api: SecurityApi) => Promise<void>,
  ): Promise<void> => {
    await use(_secBuffer.api);
  },
};

/**
 * Adds the scan fixtures to `base` (05, chapter 3). Outside scan mode only `security` is added
 * (05-REQ-01). Wrapping a test object this function returned gives it back unchanged. Never
 * imports @playwright/test at runtime: it works with the `base` it gets.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function withSecurityFixtures<T extends TestType<any, any>>(base: T): SecurityTestType<T> {
  const wrapped = wrappedTests();
  if (wrapped.has(base)) return base as unknown as SecurityTestType<T>;
  const extend = base.extend as (fixtures: object) => SecurityTestType<T>;
  const result = extend.call(base, scanModeOn() ? scanFixtures : passiveFixtures);
  wrapped.add(result as object);
  return result;
}

/**
 * Registers a worker-scoped browser context (05-REQ-02): every test of a scanned project scans it.
 * Call it once, right after creating the context. Does nothing outside scan mode.
 */
export async function trackContext(context: BrowserContext): Promise<void> {
  if (!scanModeOn()) return;
  const contexts = trackedContexts();
  if (!contexts.has(context)) {
    contexts.add(context);
    context.once('close', () => contexts.delete(context));
  }
  // Registered during a test: scanned from now on (05-REQ-02).
  await activeCollector<TestScan>()?.track(context);
}
