// Scan scope (05, chapter 4).
import { canonicalOrigin, matchingPattern, parseHostPattern } from '../core/normalize/index.ts';
import type { HostPattern } from '../core/normalize/index.ts';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export interface ScopeSettings {
  baseOrigins: readonly string[];
  includeBaseURL: boolean;
  origins: readonly string[];
  exclude: readonly string[];
}

function compile(list: readonly string[]): { exact: Set<string>; patterns: HostPattern[] } {
  const exact = new Set<string>();
  const patterns: HostPattern[] = [];
  for (const item of list) {
    if (item.includes('*')) {
      const parsed = parseHostPattern(item, '');
      if (typeof parsed !== 'string') patterns.push(parsed);
    } else {
      const origin = canonicalOrigin(item);
      if (origin !== null) exact.add(origin);
    }
  }
  return { exact, patterns };
}

/** Decides whether an origin is in scope (05-REQ-04); results are remembered. */
export class Scope {
  readonly #include: ReturnType<typeof compile>;
  readonly #exclude: ReturnType<typeof compile>;
  readonly #memo = new Map<string, boolean>();
  /** Origins and patterns of the scope, for the report. */
  readonly listed: string[];

  constructor(settings: ScopeSettings) {
    const include = [...(settings.includeBaseURL ? settings.baseOrigins : []), ...settings.origins];
    this.#include = compile(include);
    this.#exclude = compile(settings.exclude);
    this.listed = [...new Set(include)].sort();
  }

  #matches(list: ReturnType<typeof compile>, origin: string): boolean {
    if (list.exact.has(origin)) return true;
    if (list.patterns.length === 0) return false;
    return matchingPattern(list.patterns, new URL(origin)) !== null;
  }

  /** `origin` is a canonical origin (scheme://host[:port]). */
  has(origin: string): boolean {
    const known = this.#memo.get(origin);
    if (known !== undefined) return known;
    let result = false;
    if (canonicalOrigin(origin) === origin) {
      result = this.#matches(this.#include, origin) && !this.#matches(this.#exclude, origin);
    }
    this.#memo.set(origin, result);
    return result;
  }
}

/** localhost, 127.0.0.1 or [::1] (05-REQ-06). */
export function isLocalOrigin(origin: string): boolean {
  try {
    return LOCAL_HOSTS.has(new URL(origin).hostname);
  } catch {
    return false;
  }
}

/** Whether `host` domain-matches a cookie `domain` (RFC 6265, 5.1.3). */
export function domainMatches(host: string, domain: string): boolean {
  const d = domain.replace(/^\./, '').toLowerCase();
  const h = host.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}
