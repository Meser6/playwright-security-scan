// Copied from playwright-performance-regression@1.0.0 (commit 3895766), src/core/normalize,
// to keep endpoint keys identical to the perf package (D-08, 01-REQ-11, 07-REQ-01). Change it only
// together with the perf package; the golden cases in test/golden/normalize guard the copy.
// Endpoint keys from raw requests (07, chapters 4–9 and 11).
import type { NormalizationConfig } from './config.ts';
import { hashHex } from '../hash/index.ts';
import type { Issue } from './config.ts';
import { MAX_KEY_LENGTH } from './constants.ts';
import { compileHostPatterns, isHostPattern, matchingPattern } from './host-patterns.ts';
import { compileIdMatcher } from './patterns.ts';
import type { IdMatcher } from './patterns.ts';

/** NORMALIZE_* warnings; collected and collapsed by the reporter (02-REQ-20). */
export type NormalizeIssue = Issue;

export interface KeyBuilderContext {
  /** Origins of use.baseURL of measured projects only; get the empty label (07-REQ-03, 07-REQ-20). */
  baseOrigins: readonly string[];
}

export type KeyResult =
  // origin: canonical origin of the URL; label: its label (07-REQ-03); both feed report.origins.
  // null only for a keyBuilder key whose URL could not be parsed (07-REQ-23).
  | { ok: true; key: string; origin: string | null; label: string | null; issues: NormalizeIssue[] }
  | { ok: false; issues: NormalizeIssue[] };

export interface KeySample {
  method: string;
  url: string;
  resourceType: string;
}

const HINT_EXTEND = 'Use keys.extraIdPatterns or keys.keyBuilder for ids in other formats.';

/** Parses an http(s) URL; null for anything else (07-REQ-19). */
function parseHttpUrl(text: string): URL | null {
  if (!URL.canParse(text)) return null;
  const url = new URL(text);
  return url.protocol === 'http:' || url.protocol === 'https:' ? url : null;
}

/** Canonical WHATWG origin of an http(s) URL or origin text; null when it is not one. */
export function canonicalOrigin(text: string): string | null {
  return parseHttpUrl(text)?.origin ?? null;
}

/** Unique canonical origins, sorted by UTF-16 code units; invalid entries are dropped. */
export function canonicalOrigins(origins: readonly string[]): string[] {
  const set = new Set<string>();
  for (const origin of origins) {
    const canonical = canonicalOrigin(origin);
    if (canonical !== null) set.add(canonical);
  }
  return [...set].sort();
}

// Characters percent-encoded in parts of the key (07-REQ-06, 07-REQ-13).
/* eslint-disable no-control-regex */
const SEGMENT_ESCAPE = /[%/?#& \u0000-\u001f\u007f-\u009f]/g;
const NAME_ESCAPE = /[%&=# \u0000-\u001f\u007f-\u009f]/g;
const VALUE_ESCAPE = /[%&=#, \u0000-\u001f\u007f-\u009f]/g;
/* eslint-enable no-control-regex */
const escape = (text: string, chars: RegExp): string => text.replace(chars, encodeURIComponent);

function normalizePath(pathname: string, matchId: IdMatcher): string {
  const segments: string[] = [];
  for (const raw of pathname.split('/')) {
    const segment = raw.split(';', 1)[0] ?? '';
    if (segment === '') continue;
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      segments.push(segment);
      continue;
    }
    segments.push(matchId(decoded) ?? escape(decoded, SEGMENT_ESCAPE));
  }
  return `/${segments.join('/')}`;
}

function normalizeQuery(
  params: URLSearchParams,
  keys: NormalizationConfig,
  matchId: IdMatcher,
): string {
  const drop = new Set(keys.dropQueryParams);
  const keep = new Set(keys.keepQueryValues);
  const names = new Map<string, Set<string> | null>();
  for (const [rawName, value] of params) {
    const name = rawName.replace(/\[[0-9]+\]/g, '[]');
    if (name === '' || drop.has(name) || matchId(name) !== null) continue;
    const encoded = escape(name, NAME_ESCAPE);
    if (!keep.has(name)) {
      if (!names.has(encoded)) names.set(encoded, null);
      continue;
    }
    const values = names.get(encoded) ?? new Set<string>();
    values.add(matchId(value) ?? escape(value, VALUE_ESCAPE));
    names.set(encoded, values);
  }
  // Default sort compares UTF-16 code units (07-REQ-13).
  return [...names.keys()]
    .sort()
    .map((name) => {
      const values = names.get(name);
      return values ? `${name}=${[...values].sort().join(',')}` : name;
    })
    .join('&');
}

/** Cuts a key longer than MAX_KEY_LENGTH and appends a hash of the whole key (07-REQ-18). */
export function truncateKey(key: string): string {
  if (key.length <= MAX_KEY_LENGTH) return key;
  const suffix = `…~${hashHex(key)}`;
  let cut = MAX_KEY_LENGTH - suffix.length;
  const before = key.charCodeAt(cut - 1);
  const after = key.charCodeAt(cut);
  if (before >= 0xd800 && before <= 0xdbff && after >= 0xdc00 && after <= 0xdfff) cut -= 1;
  return key.slice(0, cut) + suffix;
}

/**
 * Label of an origin (07-REQ-03, 07-REQ-25): an exact keys.origins entry, else the best host
 * pattern, else '' for a baseURL origin of a measured project, else null (the host is used).
 * Results are remembered for the run.
 */
export function originLabels(
  origins: Readonly<Record<string, string>>,
  baseOrigins: readonly string[],
): (url: URL) => string | null {
  const exact = new Map<string, string>();
  for (const [origin, label] of Object.entries(origins)) {
    if (isHostPattern(origin)) continue;
    const canonical = canonicalOrigin(origin);
    if (canonical !== null) exact.set(canonical, label);
  }
  const patterns = compileHostPatterns(origins);
  const base = new Set(canonicalOrigins(baseOrigins));
  const memo = new Map<string, string | null>();
  return (url) => {
    const known = memo.get(url.origin);
    if (known !== undefined) return known;
    const label =
      exact.get(url.origin) ??
      matchingPattern(patterns, url)?.label ??
      (base.has(url.origin) ? '' : null);
    memo.set(url.origin, label);
    return label;
  };
}

/** Whether keys.origins maps the origin, exactly or by a pattern (07-REQ-26). */
export function coveredByOrigins(
  origins: Readonly<Record<string, string>>,
  origin: string,
): boolean {
  const url = parseHttpUrl(origin);
  if (url === null) return false;
  return originLabels(origins, [])(url) !== null;
}

/**
 * Compiles the `keys` config once and returns a pure function from a request sample to its
 * endpoint key (07, chapter 12). Collecting and collapsing warnings is up to the caller.
 */
export function createKeyBuilder(
  cfg: NormalizationConfig,
  ctx: KeyBuilderContext,
): (sample: KeySample) => KeyResult {
  const matchId = compileIdMatcher(cfg);
  const labelOf = originLabels(cfg.origins, ctx.baseOrigins);
  const keyBuilder = cfg.keyBuilder;

  return (sample) => {
    const method = sample.method.toUpperCase();
    const url = parseHttpUrl(sample.url);
    const issues: NormalizeIssue[] = [];
    let key: string | undefined;

    if (keyBuilder !== undefined) {
      let built: unknown;
      try {
        built = keyBuilder({ method, url: sample.url, resourceType: sample.resourceType });
      } catch (error) {
        issues.push({
          code: 'NORMALIZE_KEY_BUILDER_THREW',
          message: `keys.keyBuilder threw an exception: ${error instanceof Error ? error.message : String(error)}. The built-in normalization was used instead.`,
          hint: 'Fix the keyBuilder function; it must not throw.',
        });
        built = undefined;
      }
      if (typeof built === 'string' && built.trim() !== '') {
        key = built;
      } else if (built !== undefined) {
        issues.push({
          code: 'NORMALIZE_KEY_BUILDER_INVALID',
          message:
            'keys.keyBuilder returned a value that is neither a non-empty string nor undefined. The built-in normalization was used instead.',
          hint: 'Return the whole key as a non-empty string, or undefined for the built-in normalization.',
        });
      }
    }

    if (key === undefined) {
      if (url === null) {
        issues.push({
          code: 'NORMALIZE_UNSUPPORTED_URL',
          message:
            'A request URL could not be parsed or does not use http/https; the sample was skipped.',
        });
        return { ok: false, issues };
      }
      const label = labelOf(url) ?? url.host;
      const query = cfg.query === 'names' ? normalizeQuery(url.searchParams, cfg, matchId) : '';
      key = `${method} ${label}${normalizePath(url.pathname, matchId)}${query === '' ? '' : `?${query}`}`;
    }

    const truncated = truncateKey(key);
    if (truncated !== key) {
      issues.push({
        code: 'NORMALIZE_KEY_TRUNCATED',
        message: `An endpoint key longer than ${MAX_KEY_LENGTH} characters was truncated and suffixed with its hash.`,
        hint: HINT_EXTEND,
      });
    }
    return {
      ok: true,
      key: truncated,
      origin: url?.origin ?? null,
      label: url === null ? null : (labelOf(url) ?? url.host),
      issues,
    };
  };
}
