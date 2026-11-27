// Request templates of one test (05-REQ-28, 18-REQ-10…13): GET/HEAD requests in scope and in
// authz.allowedOrigins with a 2xx answer, without credential values, and a salted digest of the
// answer. Only made when the authorization tests are on; bodies never leave the worker (P-07).
import { createHash } from 'node:crypto';
import { BODY_METHODS, templateBody } from '../core/attack/body.ts';
import { attackOriginAllowed } from '../core/attack/config.ts';
import type { ResolvedAttack } from '../core/attack/config.ts';
import type { AttackTemplate } from '../core/attack/types.ts';
import { excludeMatcher, isLogoutPath } from '../core/authz/config.ts';
import type { ResolvedAuthz } from '../core/authz/config.ts';
import { digestResponse } from '../core/authz/digest.ts';
import type { HashFn } from '../core/authz/digest.ts';
import { roleNameOf } from '../core/authz/plan.ts';
import {
  MAX_TEMPLATES_BYTES,
  type RequestTemplate,
  type TemplatesAttachment,
} from '../core/authz/types.ts';
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import { isSensitiveHeader, SENSITIVE_PARAMS } from '../core/fingerprint/redact.ts';
import type { Redactor } from '../core/fingerprint/redact.ts';
import { NON_SESSION_COOKIES, SESSION_NAME_PATTERN } from '../core/manifest/rules.ts';
import { SESSION_PARAM_NAMES } from '../core/manifest/rules.ts';
import { isSessionCookie } from '../core/rules/cookies.ts';
import type { Coverage, Header, ResponseRecord, TestContextRef } from '../core/types/index.ts';

/** Resource types of browser records that give templates (18-REQ-10). */
const BROWSER_TYPES = new Set(['document', 'xhr', 'fetch']);
/** Request headers a template keeps (18-REQ-11). */
const KEPT_HEADERS = new Set(['accept', 'accept-language', 'content-type', 'x-requested-with']);
const CSRF_HEADER = /csrf|xsrf/i;

/** The salted hash of the digests (18-REQ-12, 18 chapter 12a). */
export function authzHash(salt: string): HashFn {
  return (text) =>
    createHash('sha256').update(`${salt}\u0000authz\u0000${text}`).digest('hex').slice(0, 8);
}

/** Headers of a template: the allow-list, never a credential (18-REQ-11, 07-REQ-13). */
export function templateHeaders(headers: readonly Header[]): Header[] {
  return headers.filter(
    (h) =>
      (KEPT_HEADERS.has(h.name) || CSRF_HEADER.test(h.name)) &&
      !isSensitiveHeader(h.name) &&
      h.name !== 'cookie',
  );
}

export interface TemplateOptions {
  config: ResolvedSecurityConfig;
  test: TestContextRef;
  salt: string;
  /**
   * Credentials the API collector cannot see (18 chapter 12a): the project has use.storageState
   * or an authorization header in use.extraHTTPHeaders.
   */
  apiCredentials: boolean;
}

export class TemplateCollector {
  readonly #authz: ResolvedAuthz;
  readonly #options: TemplateOptions;
  readonly #hash: HashFn;
  readonly #excluded: (key: string) => boolean;
  readonly #tokenParams: Set<string>;
  readonly #sessionPattern: string;
  readonly #nonSession: readonly string[];
  readonly #role: string;
  readonly #templates = new Map<string, RequestTemplate>();
  readonly observed: NonNullable<Coverage['authzObserved']> = {};

  constructor(options: TemplateOptions) {
    this.#options = options;
    this.#authz = options.config.authz;
    this.#hash = authzHash(options.salt);
    this.#excluded = excludeMatcher(this.#authz.exclude);
    const paramNames = options.config.rules['data.token-in-url']?.options.paramNames;
    this.#tokenParams = new Set(
      [
        ...SENSITIVE_PARAMS,
        ...SESSION_PARAM_NAMES,
        ...(Array.isArray(paramNames) ? (paramNames as string[]) : []),
      ].map((n) => n.toLowerCase()),
    );
    const cookieOptions = options.config.rules['cookie.no-httponly']?.options ?? {};
    this.#sessionPattern =
      typeof cookieOptions.sessionNamePattern === 'string'
        ? cookieOptions.sessionNamePattern
        : SESSION_NAME_PATTERN;
    this.#nonSession = Array.isArray(cookieOptions.nonSessionNames)
      ? (cookieOptions.nonSessionNames as string[])
      : NON_SESSION_COOKIES;
    this.#role = roleNameOf(options.test.project, this.#authz.roles);
  }

  /** A GET/HEAD 2xx record of an allowed origin (18-REQ-10); the caller checked the scope. */
  wants(
    record: Pick<ResponseRecord, 'method' | 'status' | 'origin' | 'source' | 'resourceType'>,
  ): boolean {
    if (record.method !== 'GET' && record.method !== 'HEAD') return false;
    if (record.status < 200 || record.status >= 300) return false;
    if (record.source === 'browser' && !BROWSER_TYPES.has(record.resourceType)) return false;
    return this.#authz.allowedOrigins.includes(record.origin);
  }

  /** The request carried a session cookie or an authorization header (18-REQ-11). */
  #credentials(record: ResponseRecord): boolean {
    for (const h of record.requestHeaders) {
      if (h.name === 'authorization') return true;
      if (h.name !== 'cookie') continue;
      if (record.source === 'api') return true;
      for (const pair of h.value.split(';')) {
        const eq = pair.indexOf('=');
        if (eq <= 0) continue;
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        if (isSessionCookie(name, value, this.#sessionPattern, this.#nonSession)) return true;
      }
    }
    return record.source === 'api' && this.#options.apiCredentials;
  }

  /**
   * Adds the record of a wanted request (05-REQ-28): to the observed map always, as a template when
   * it is not excluded. `body` is the text the collector read, undefined when it was not read.
   */
  add(record: ResponseRecord, body: string | undefined): void {
    const credentials = this.#credentials(record);
    const seen = (this.observed[record.endpointKey] ??= { roles: [], public: false });
    if (credentials) {
      if (!seen.roles.includes(this.#role)) seen.roles.push(this.#role);
    } else seen.public = true;

    if (this.#templates.has(record.endpointKey)) return; // the first one wins (18-REQ-10)
    let url: URL;
    try {
      url = new URL(record.url);
    } catch {
      return;
    }
    if (this.#excluded(record.endpointKey) || isLogoutPath(url.pathname)) return;
    for (const name of url.searchParams.keys())
      if (this.#tokenParams.has(name.toLowerCase())) return;
    const header = (name: string): string | undefined =>
      record.responseHeaders.find((h) => h.name === name)?.value;
    const contentType = (header('content-type') ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
    const length =
      body === undefined ? Number(header('content-length') ?? 0) || 0 : Buffer.byteLength(body);
    this.#templates.set(record.endpointKey, {
      method: record.method,
      url: record.url,
      headers: templateHeaders(record.requestHeaders),
      endpointKey: record.endpointKey,
      origin: record.origin,
      project: this.#options.test.project,
      source: record.source,
      withCredentials: credentials,
      hadAuthorization: record.requestHeaders.some((h) => h.name === 'authorization'),
      digest: digestResponse(
        {
          status: record.status,
          contentType,
          body,
          length,
          path: url.pathname,
          requestHeaders: record.requestHeaders,
        },
        this.#hash,
      ),
      context: this.#options.test,
    });
  }

  list(): RequestTemplate[] {
    return [...this.#templates.values()];
  }
}

export interface AttackTemplateOptions {
  config: ResolvedSecurityConfig;
  test: TestContextRef;
  redactor: Redactor;
}

/**
 * Request templates of the attack mode (19-REQ-03, 19 chapter 11a): methods of attack.methods,
 * origins of attack.allowedOrigins, status < 400, without credentials and without digests; bodies
 * of POST/PUT/PATCH/DELETE only of known types and redacted.
 */
export class AttackTemplateCollector {
  readonly #attack: ResolvedAttack;
  readonly #options: AttackTemplateOptions;
  readonly #excluded: (key: string) => boolean;
  readonly #tokenParams: Set<string>;
  readonly #methods: Set<string>;
  readonly #templates = new Map<string, AttackTemplate>();

  constructor(options: AttackTemplateOptions) {
    this.#options = options;
    this.#attack = options.config.attack;
    this.#excluded = excludeMatcher(this.#attack.exclude);
    this.#methods = new Set(this.#attack.methods);
    const paramNames = options.config.rules['data.token-in-url']?.options.paramNames;
    this.#tokenParams = new Set(
      [
        ...SENSITIVE_PARAMS,
        ...SESSION_PARAM_NAMES,
        ...(Array.isArray(paramNames) ? (paramNames as string[]) : []),
      ].map((n) => n.toLowerCase()),
    );
  }

  /** A record the attack wants (19-REQ-03); the caller checked the scope. */
  wants(
    record: Pick<ResponseRecord, 'method' | 'status' | 'origin' | 'source' | 'resourceType'>,
  ): boolean {
    if (!this.#methods.has(record.method)) return false;
    if (record.status < 200 || record.status >= 400) return false;
    if (record.source === 'browser' && !BROWSER_TYPES.has(record.resourceType)) return false;
    return attackOriginAllowed(record.origin, this.#attack);
  }

  /** Adds the record of a wanted request; `requestBody` is the body the test sent, if known. */
  add(
    record: ResponseRecord,
    requestBody: string | null | undefined,
    bodyType?: string | undefined,
  ): void {
    if (!this.wants(record) || this.#templates.has(record.endpointKey)) return;
    let url: URL;
    try {
      url = new URL(record.url);
    } catch {
      return;
    }
    if (this.#excluded(record.endpointKey) || isLogoutPath(url.pathname)) return;
    for (const name of url.searchParams.keys())
      if (this.#tokenParams.has(name.toLowerCase())) return;
    const headers = templateHeaders(record.requestHeaders);
    const contentType =
      record.requestHeaders.find((h) => h.name === 'content-type')?.value ?? bodyType;
    const body = BODY_METHODS.has(record.method)
      ? templateBody(requestBody, contentType, this.#options.config.limits.maxBodyBytes, {
          redactor: this.#options.redactor,
          names: this.#tokenParams,
        })
      : undefined;
    this.#templates.set(record.endpointKey, {
      method: record.method,
      url: record.url,
      // Without a kept body the content type would describe a body ZAP does not get.
      headers:
        body === undefined
          ? headers.filter((h) => h.name !== 'content-type')
          : headers.some((h) => h.name === 'content-type') || contentType === undefined
            ? headers
            : [...headers, { name: 'content-type', value: contentType }],
      ...(body === undefined ? {} : { body }),
      endpointKey: record.endpointKey,
      origin: record.origin,
      project: this.#options.test.project,
      source: record.source,
      context: this.#options.test,
    });
  }

  list(): AttackTemplate[] {
    return [...this.#templates.values()];
  }
}

/**
 * The pw-sec-templates attachment (02-REQ-07) of both lists, at most 512 KB together: the longest
 * entries are dropped first (18-REQ-13, 19 chapter 11a). Null without templates.
 */
export function templatesAttachmentBody(
  authz: readonly RequestTemplate[],
  attack: readonly AttackTemplate[] | undefined,
): { body: string; authzTruncated: boolean; attackTruncated: boolean } | null {
  if (authz.length === 0 && (attack === undefined || attack.length === 0)) return null;
  const doc = (a: readonly RequestTemplate[], b: readonly AttackTemplate[] | undefined): string =>
    JSON.stringify({
      schemaVersion: 1,
      templates: a,
      ...(b === undefined ? {} : { attack: b }),
    } satisfies TemplatesAttachment);
  let body = doc(authz, attack);
  if (Buffer.byteLength(body) <= MAX_TEMPLATES_BYTES)
    return { body, authzTruncated: false, attackTruncated: false };
  type Entry = { kind: 'authz' | 'attack'; size: number; t: RequestTemplate | AttackTemplate };
  const entries: Entry[] = [
    ...authz.map((t) => ({ kind: 'authz' as const, size: JSON.stringify(t).length, t })),
    ...(attack ?? []).map((t) => ({ kind: 'attack' as const, size: JSON.stringify(t).length, t })),
  ].sort((a, b) => a.size - b.size);
  let authzTruncated = false;
  let attackTruncated = false;
  while (entries.length > 0) {
    const dropped = entries.pop() as Entry;
    if (dropped.kind === 'authz') authzTruncated = true;
    else attackTruncated = true;
    const keep = new Set(entries.map((e) => e.t));
    body = doc(
      authz.filter((t) => keep.has(t)),
      attack?.filter((t) => keep.has(t)),
    );
    if (Buffer.byteLength(body) <= MAX_TEMPLATES_BYTES) break;
  }
  return { body, authzTruncated, attackTruncated };
}
