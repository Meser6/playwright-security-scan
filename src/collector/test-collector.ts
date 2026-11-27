// The collector of one test (05, chapters 5.2, 6 and 8): runs the rules on records and browser
// events, keeps the redacted findings, coverage and diagnostics, and builds the attachment.
import { addCoverage, emptyCoverage } from '../core/coverage.ts';
import { dedupeTest, normalizeAssetUrl, toFinding } from '../core/fingerprint/index.ts';
import type { Redactor } from '../core/fingerprint/index.ts';
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import { CustomRuleAsyncError } from '../core/custom/adapt.ts';
import { LOGIN_PATH_PATTERN } from '../core/manifest/rules.ts';
import { cookieValueClass, isDeletion, parseSetCookie } from '../core/rules/cookies.ts';
import type { BuiltInRule, RuleContext, RuleInput } from '../core/rules/index.ts';
import type {
  BrowserEvent,
  CookieView,
  Coverage,
  Diagnostic,
  Finding,
  RawFinding,
  ResponseRecord,
  Source,
  TestAttachment,
  TestContextRef,
  TestTraffic,
  TrafficRequest,
} from '../core/types/index.ts';
import { isAbsolute, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isLocalOrigin } from './scope.ts';
import type { Scope } from './scope.ts';
import { templatesAttachmentBody } from './templates.ts';
import type { AttackTemplateCollector, TemplateCollector } from './templates.ts';

export const ATTACHMENT_NAME = 'pw-sec-findings';
/** Maximum attachment size (02-REQ-05). */
export const MAX_ATTACHMENT_BYTES = 256 * 1024;
const MAX_CACHE_ENTRIES = 2000;

/**
 * Analysis cache of the worker (05-REQ-14): redacted results of body rules per rule, URL and body
 * hash of static assets; and the body hash per URL and validator, so an unchanged bundle is read
 * once per worker (05-AC-02). Bodies themselves are never kept (05-REQ-12).
 */
export class AnalysisCache {
  readonly #findings = new Map<string, RawFinding[]>();
  readonly #hashes = new Map<string, string>();
  /** Custom rules switched off for the rest of the run in this worker (16-REQ-08). */
  readonly offInWorker = new Set<string>();

  findings(key: string): RawFinding[] | undefined {
    return this.#findings.get(key);
  }

  setFindings(key: string, value: RawFinding[]): void {
    if (this.#findings.size >= MAX_CACHE_ENTRIES) this.#findings.clear();
    this.#findings.set(key, value);
  }

  hash(key: string): string | undefined {
    return this.#hashes.get(key);
  }

  setHash(key: string, sha: string): void {
    if (this.#hashes.size >= MAX_CACHE_ENTRIES) this.#hashes.clear();
    this.#hashes.set(key, sha);
  }
}

export interface TestCollectorOptions {
  config: ResolvedSecurityConfig;
  rules: readonly BuiltInRule[];
  scope: Scope;
  redactor: Redactor;
  cache: AnalysisCache;
  test: TestContextRef;
}

export class TestCollector {
  readonly options: TestCollectorOptions;
  readonly coverage: Coverage = emptyCoverage();
  readonly #findings: Finding[] = [];
  readonly #diagnostics = new Map<string, Diagnostic>();
  /** Rules switched off for this test after an exception (05-REQ-15). */
  readonly #failed = new Set<string>();
  readonly #perRule = new Map<string, number>();
  readonly #enabled: BuiltInRule[];
  /** Resource types some enabled rule reads the body of (05-REQ-10). */
  readonly bodyTypes: ReadonlySet<string>;
  /** Some enabled rule reads the end-of-test traffic (05-REQ-27). */
  readonly wantsTraffic: boolean;
  readonly #traffic: TrafficRequest[] = [];
  #jar: Omit<CookieView, 'value'>[] = [];
  #sequence = 0;
  readonly #loginPath: RegExp;
  /** Request templates of the authorization tests (05-REQ-28); unset when they are off. */
  templates: TemplateCollector | undefined;
  /** Request templates of the attack mode (19-REQ-03); unset outside it. */
  attackTemplates: AttackTemplateCollector | undefined;

  constructor(options: TestCollectorOptions) {
    this.options = options;
    this.#enabled = options.rules.filter(
      (r) => options.config.rules[r.id]?.enabled === true && !options.cache.offInWorker.has(r.id),
    );
    this.bodyTypes = new Set(this.#enabled.flatMap((r) => r.needsBody ?? []));
    this.wantsTraffic = this.#enabled.some((r) => r.appliesTo.testEnd === true);
    const pattern = options.config.rules['auth.session-fixation']?.options.loginPathPattern;
    this.#loginPath = safeRegExp(
      typeof pattern === 'string' ? pattern : LOGIN_PATH_PATTERN,
      LOGIN_PATH_PATTERN,
    );
  }

  /** Order of a response within the test, across contexts (06, chapter 4.14). */
  nextSequence(): number {
    this.#sequence += 1;
    return this.#sequence;
  }

  get test(): TestContextRef {
    return this.options.test;
  }

  diagnostic(code: string, level: Diagnostic['level'], message: string): void {
    const key = `${code}\u0000${message}`;
    if (!this.#diagnostics.has(key)) {
      this.#diagnostics.set(key, { code, level, message, testId: this.options.test.testId });
    }
  }

  skipBody(reason: string): void {
    this.coverage.bodiesSkipped[reason] = (this.coverage.bodiesSkipped[reason] ?? 0) + 1;
  }

  outOfScope(origin: string): void {
    this.coverage.outOfScope += 1;
    // Origins of the traffic outside the scope, for the check (04-REQ-13).
    const origins = (this.coverage.outOfScopeOrigins ??= {});
    origins[origin] = (origins[origin] ?? 0) + 1;
  }

  #context(rule: BuiltInRule, origin: string, isHttps: boolean): RuleContext {
    const resolved = this.options.config.rules[rule.id];
    const scope = this.options.scope;
    return {
      options: resolved?.options ?? {},
      severity: resolved?.severity ?? rule.manifest.defaultSeverity,
      confidence: resolved?.confidence ?? rule.manifest.defaultConfidence,
      localDev: isLocalOrigin(origin),
      isHttps,
      inScope: (o) => scope.has(o),
      redact: this.options.redactor,
    };
  }

  /** Runs one rule with error isolation (05-REQ-15, P-08) and redaction (05-REQ-16). */
  #run(rule: BuiltInRule, input: RuleInput, ctx: RuleContext): RawFinding[] {
    this.coverage.rulesRun[rule.id] = (this.coverage.rulesRun[rule.id] ?? 0) + 1;
    try {
      return rule.check(input, ctx).map((raw) => this.options.redactor.enforce(raw));
    } catch (error) {
      this.#failed.add(rule.id);
      const message = error instanceof Error ? error.message : String(error);
      if (rule.manifest.group !== 'custom') {
        this.diagnostic(
          'RULE_ERROR',
          'warn',
          `rule ${rule.id} threw and is off for the rest of this test: ${message}`,
        );
      } else if (error instanceof CustomRuleAsyncError) {
        // 16-REQ-08: off for the rest of the run in this worker.
        this.options.cache.offInWorker.add(rule.id);
        this.diagnostic(
          'CUSTOM_RULE_ASYNC',
          'error',
          `custom rule ${rule.id}: check() returned a promise; custom rules must be synchronous. The rule is off for the rest of the run in this worker`,
        );
      } else {
        // 16-REQ-09: a custom rule that does not run makes the result unreliable.
        const at = userStackLine(error);
        this.diagnostic(
          'CUSTOM_RULE_ERROR',
          'error',
          `custom rule ${rule.id} threw and is off for the rest of this test: ${this.options.redactor.text(message)}${at === undefined ? '' : ` (${at})`}`,
        );
      }
      return [];
    }
  }

  #add(raws: readonly RawFinding[], source: Source): void {
    const limit = this.options.config.limits.maxFindingsPerRule;
    for (const raw of raws) {
      const count = this.#perRule.get(raw.ruleId) ?? 0;
      if (count >= limit) {
        this.diagnostic(
          'RULE_FINDINGS_LIMIT',
          'warn',
          `rule ${raw.ruleId} reached limits.maxFindingsPerRule (${limit}) in this test; further findings were dropped`,
        );
        continue;
      }
      this.#perRule.set(raw.ruleId, count + 1);
      this.#findings.push(toFinding(raw, this.options.test, source));
    }
  }

  /** Counts a record in scope (02, chapter 6). */
  #count(record: ResponseRecord): void {
    const c = this.coverage;
    c.responses += 1;
    if (record.source === 'api') c.apiResponses += 1;
    const isDocument = record.resourceType === 'document';
    if (isDocument) c.documents += 1;
    const origin = (c.origins[record.origin] ??= { responses: 0, documents: 0 });
    origin.responses += 1;
    if (isDocument) origin.documents += 1;
    c.endpoints[record.endpointKey] = (c.endpoints[record.endpointKey] ?? 0) + 1;
    if (record.resourceType === 'script' || record.resourceType === 'stylesheet') {
      const asset = normalizeAssetUrl(record.url);
      if (asset !== null && !c.assets.includes(asset)) c.assets.push(asset);
    }
  }

  /**
   * Analyses an in-scope record (05-REQ-15). `cachedSha` is set when the body of a static asset
   * was not read because the worker already analysed it (05-REQ-14).
   */
  analyzeRecord(record: ResponseRecord, cachedSha?: string): void {
    this.#count(record);
    const isHttps = record.url.startsWith('https:');
    for (const rule of this.#enabled) {
      if (this.#failed.has(rule.id) || !applies(rule, record)) continue;
      const ctx = this.#context(rule, record.origin, isHttps);
      const readsBody = rule.needsBody?.includes(record.resourceType) === true;
      const sha = record.body?.sha256 ?? cachedSha;
      const cacheable =
        readsBody &&
        sha !== undefined &&
        (record.resourceType === 'script' || record.resourceType === 'stylesheet');
      const key = `${rule.id}\u0000${record.url}\u0000${sha ?? ''}`;
      if (cacheable && record.body === undefined) {
        this.#add(this.options.cache.findings(key) ?? [], record.source);
        continue;
      }
      const raws = this.#run(rule, record, ctx);
      if (cacheable) this.options.cache.setFindings(key, raws);
      this.#add(raws, record.source);
    }
  }

  /** Analyses an out-of-scope record with the rules that ask for it (05-REQ-05). */
  analyzeOutOfScope(record: ResponseRecord): void {
    for (const rule of this.#enabled) {
      if (this.#failed.has(rule.id) || rule.appliesTo.outOfScope !== true) continue;
      if (!applies(rule, record)) continue;
      const ctx = this.#context(rule, record.origin, record.url.startsWith('https:'));
      this.#add(this.#run(rule, record, ctx), record.source);
    }
  }

  /**
   * Keeps an in-scope browser record for the end-of-test input (05-REQ-27): cookie values only as
   * salted hashes and value classes, form field names only for the CSRF signal (06, chapter 4.14).
   */
  addTraffic(record: ResponseRecord, postData: string | null): void {
    if (!this.wantsTraffic || record.source !== 'browser') return;
    const redact = this.options.redactor;
    const sentCookies: TrafficRequest['sentCookies'] = [];
    for (const h of record.requestHeaders) {
      if (h.name !== 'cookie') continue;
      for (const pair of h.value.split(';')) {
        const eq = pair.indexOf('=');
        if (eq <= 0) continue;
        const value = pair.slice(eq + 1).trim();
        sentCookies.push({
          name: pair.slice(0, eq).trim(),
          valueHash: redact.hash(value),
          valueClass: cookieValueClass(value),
        });
      }
    }
    const date = record.responseHeaders.find((h) => h.name === 'date')?.value;
    const now = date === undefined ? Number.NaN : Date.parse(date);
    const setCookies: TrafficRequest['setCookies'] = [];
    for (const h of record.responseHeaders) {
      if (h.name !== 'set-cookie') continue;
      for (const line of h.value.split('\n')) {
        const c = parseSetCookie(line);
        if (c === null || isDeletion(c, Number.isFinite(now) ? now : undefined)) continue;
        const sameSite = sameSiteOf(c.sameSite);
        setCookies.push({
          name: c.name,
          valueHash: redact.hash(c.value),
          valueClass: cookieValueClass(c.value),
          ...(c.domain === undefined || c.domain === '' ? {} : { domain: c.domain }),
          ...(sameSite === undefined ? {} : { sameSite }),
          secure: c.secure,
          httpOnly: c.httpOnly,
        });
      }
    }
    const requestType = record.requestHeaders.find((h) => h.name === 'content-type')?.value;
    const contentType = requestType?.split(';')[0]?.trim().toLowerCase();
    const path = URL.canParse(record.url) ? new URL(record.url).pathname : '';
    this.#traffic.push({
      id: record.id,
      method: record.method,
      endpointKey: record.endpointKey,
      origin: record.origin,
      status: record.status,
      resourceType: record.resourceType,
      isLoginCandidate:
        record.method === 'POST' &&
        record.status >= 200 &&
        record.status < 400 &&
        this.#loginPath.test(path),
      ...(contentType === undefined || contentType === '' ? {} : { contentType }),
      sentCookies,
      setCookies,
      hasAuthorization: record.requestHeaders.some((h) => h.name === 'authorization'),
      csrfSignal: csrfSignal(record, contentType, postData),
    });
  }

  /** Runs the rules with `appliesTo.testEnd` once, after the final sweep (05-REQ-27). */
  analyzeTestEnd(): void {
    if (!this.wantsTraffic || this.#traffic.length === 0) return;
    const traffic: TestTraffic = {
      kind: 'test-end',
      context: this.options.test,
      requests: [...this.#traffic].sort((a, b) => a.id - b.id),
      jarCookies: this.#jar,
    };
    this.#traffic.length = 0;
    const origin = traffic.requests[0]?.origin ?? '';
    for (const rule of this.#enabled) {
      if (this.#failed.has(rule.id) || rule.appliesTo.testEnd !== true) continue;
      const ctx = this.#context(rule, origin, origin.startsWith('https:'));
      this.#add(this.#run(rule, traffic, ctx), 'browser');
    }
  }

  /** Analyses a browser event (05, chapters 7 and 8). */
  analyzeEvent(event: BrowserEvent): void {
    if (event.kind === 'storage' && !this.coverage.storageOrigins.includes(event.origin)) {
      this.coverage.storageOrigins.push(event.origin);
    }
    if (event.kind === 'cookie-jar' && this.wantsTraffic) {
      // Attributes only; values never reach the end-of-test input (07-REQ-13).
      this.#jar = [...this.#jar, ...event.cookies.map(({ value: _value, ...rest }) => rest)];
    }
    const origin =
      event.kind === 'storage'
        ? event.origin
        : event.kind === 'csp-violation'
          ? event.documentOrigin
          : '';
    for (const rule of this.#enabled) {
      if (this.#failed.has(rule.id)) continue;
      if (rule.appliesTo.events?.includes(event.kind) !== true) continue;
      const ctx = this.#context(rule, origin, origin.startsWith('https:'));
      this.#add(this.#run(rule, event, ctx), 'browser');
    }
  }

  /** Adds coverage of work done elsewhere (e.g. the API wrapper). */
  addCoverage(coverage: Coverage): void {
    addCoverage(this.coverage, coverage);
  }

  findings(): Finding[] {
    return dedupeTest(this.#findings);
  }

  diagnostics(): Diagnostic[] {
    return [...this.#diagnostics.values()];
  }

  /**
   * The templates attachment (02-REQ-07), or null; call it before attachment(), which carries
   * its diagnostic and the observed map (18-REQ-13).
   */
  templatesAttachment(): string | null {
    const templates = this.templates;
    if (templates === undefined && this.attackTemplates === undefined) return null;
    const out = templatesAttachmentBody(templates?.list() ?? [], this.attackTemplates?.list());
    if (templates !== undefined && Object.keys(templates.observed).length > 0) {
      this.coverage.authzObserved = Object.fromEntries(
        Object.entries(templates.observed).map(([k, v]) => [
          k,
          { roles: [...v.roles].sort(), public: v.public },
        ]),
      );
    }
    if (out?.authzTruncated === true) {
      this.diagnostic(
        'AUTHZ_TEMPLATES_TRUNCATED',
        'info',
        'authz: the request templates of this test exceeded 512 KB; the templates with the longest digests were dropped',
      );
    }
    if (out?.attackTruncated === true) {
      this.diagnostic(
        'ATTACK_TEMPLATES_TRUNCATED',
        'info',
        'attack: the request templates of this test exceeded 512 KB; the longest templates were dropped',
      );
    }
    return out?.body ?? null;
  }

  /** The attachment (02-REQ-05): at most 256 KB, else one evidence item per finding. */
  attachment(): string {
    const coverage = this.coverage;
    coverage.assets.sort();
    coverage.storageOrigins.sort();
    const doc: TestAttachment = {
      schemaVersion: 1,
      findings: this.findings(),
      coverage,
      diagnostics: this.diagnostics(),
    };
    let body = JSON.stringify(doc);
    if (Buffer.byteLength(body) > MAX_ATTACHMENT_BYTES) {
      doc.findings = doc.findings.map((f) => ({ ...f, evidence: f.evidence.slice(0, 1) }));
      doc.diagnostics.push({
        code: 'ATTACHMENT_TRUNCATED',
        level: 'warn',
        message:
          'the findings of this test exceeded 256 KB; evidence was cut to one item per finding',
        testId: this.options.test.testId,
      });
      body = JSON.stringify(doc);
    }
    return body;
  }
}

/** Files of the package itself, skipped when looking for the user's line in a stack. */
const PACKAGE_FILE = /[\\/]playwright-security-scan[\\/](dist|src)[\\/]/;

/** The first stack line outside the package and Node (16-REQ-09), relative to the cwd. */
export function userStackLine(error: unknown): string | undefined {
  if (!(error instanceof Error) || typeof error.stack !== 'string') return undefined;
  const line = error.stack
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.startsWith('at ') && !l.includes('node:') && !PACKAGE_FILE.test(l));
  if (line === undefined) return undefined;
  // "at fn (<file>:<line>:<col>)" or "at <file>:<line>:<col>"; <file> may be a file:// URL.
  const m = /^(at (?:.*? \()?)(.+?)(:\d+:\d+)(\)?)$/.exec(line);
  if (m === null) return line;
  const [, head = '', location = '', position = '', tail = ''] = m;
  let file = location;
  if (file.startsWith('file://')) {
    try {
      file = fileURLToPath(file);
    } catch {
      return line;
    }
  }
  const rel = relative(process.cwd(), file);
  const shown = rel !== '' && !rel.startsWith('..') && !isAbsolute(rel) ? rel : file;
  return `${head}${shown.split('\\').join('/')}${position}${tail}`;
}

function safeDecode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

function safeRegExp(pattern: string, fallback: string): RegExp {
  try {
    return new RegExp(pattern, 'i');
  } catch {
    return new RegExp(fallback, 'i');
  }
}

function sameSiteOf(value: string | undefined): 'Strict' | 'Lax' | 'None' | undefined {
  const lower = value?.trim().toLowerCase();
  if (lower === 'strict') return 'Strict';
  if (lower === 'lax') return 'Lax';
  if (lower === 'none') return 'None';
  return undefined;
}

const CSRF_NAME = /csrf|xsrf/i;
const CSRF_FIELD = /csrf|xsrf|_token/i;

/**
 * A CSRF header (`csrf`/`xsrf` in the name, or x-requested-with) or form field (`csrf`, `xsrf`,
 * `_token` in the name; names only) of a request (06, chapter 4.14).
 */
export function csrfSignal(
  record: Pick<ResponseRecord, 'requestHeaders'>,
  contentType: string | undefined,
  postData: string | null,
): boolean {
  if (record.requestHeaders.some((h) => CSRF_NAME.test(h.name) || h.name === 'x-requested-with')) {
    return true;
  }
  if (postData === null || postData === '') return false;
  if (contentType === 'application/x-www-form-urlencoded') {
    return postData.split('&').some((pair) => {
      const name = (pair.split('=')[0] ?? '').replace(/\+/g, ' ');
      return CSRF_FIELD.test(name) || CSRF_FIELD.test(safeDecode(name));
    });
  }
  if (contentType === 'multipart/form-data') {
    for (const m of postData.matchAll(/content-disposition:[^\r\n]*\bname="([^"]*)"/gi)) {
      if (CSRF_FIELD.test(m[1] ?? '')) return true;
    }
  }
  return false;
}

/** Whether a rule applies to a record (06, chapter 2). */
export function applies(rule: BuiltInRule, record: ResponseRecord): boolean {
  const to = rule.appliesTo;
  if (to.events !== undefined && to.events.length > 0 && to.records !== true) return false;
  if (to.testEnd === true && to.records !== true) return false;
  if (to.sources !== undefined && !to.sources.includes(record.source)) return false;
  if (!rule.manifest.sources.includes(record.source)) return false;
  return to.resourceTypes === undefined || to.resourceTypes.includes(record.resourceType);
}
