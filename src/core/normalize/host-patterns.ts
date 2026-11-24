// Copied from playwright-performance-regression@1.0.0 (commit 3895766), src/core/normalize,
// to keep endpoint keys identical to the perf package (D-08, 01-REQ-11, 07-REQ-01). Change it only
// together with the perf package; the golden cases in test/golden/normalize guard the copy.
// Host patterns in keys.origins (03-REQ-20) and their matching (07-REQ-25). No regular
// expressions are built from user text, so there is no ReDoS risk.

export interface HostPattern {
  scheme: 'http' | 'https';
  /** Lowercase host labels; a label may contain one `*`. */
  labels: string[];
  /** Explicit port, '' for the default port of the scheme. */
  port: string;
  /** `<scheme>://<host>[:<port>]` after canonicalization. */
  canonical: string;
  label: string;
}

const FORM = /^([A-Za-z]+):\/\/([^/?#@:]+)(?::([0-9]+))?\/?$/u;
const LABEL = /^[a-z0-9*-]+$/u;
const DEFAULT_PORT: Record<string, string> = { http: '80', https: '443' };

/** A key of keys.origins with `*` is a pattern (03-REQ-20). */
export function isHostPattern(key: string): boolean {
  return key.includes('*');
}

/** Parses a pattern; a string is the reason it is invalid (03-REQ-20). */
export function parseHostPattern(text: string, label: string): HostPattern | string {
  const match = FORM.exec(text);
  if (match === null) {
    return 'a host pattern must have the form <scheme>://<host>[:<port>], without a path, query, fragment or credentials';
  }
  const scheme = (match[1] ?? '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https')
    return 'the scheme of a host pattern must be http or https';
  const host = (match[2] ?? '').toLowerCase();
  const labels = host.split('.');
  if (labels.length < 2) return 'a host pattern needs at least two host labels, e.g. *.example.com';
  for (const part of labels) {
    if (part === '' || !LABEL.test(part)) {
      return 'host labels may contain only letters, digits, "-" and "*" (international names in their xn-- form)';
    }
    if (part.split('*').length > 2) return 'a host label may contain at most one "*"';
  }
  if ((labels.at(-1) ?? '').includes('*'))
    return 'the last host label (the top-level domain) cannot contain "*"';
  if (labels.every((part) => part.includes('*'))) {
    return 'at least one host label must be without "*", or the pattern would match every host';
  }
  let port = match[3] ?? '';
  if (port !== '') {
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535)
      return 'the port must be a number from 1 to 65535';
    port = String(n);
    if (port === DEFAULT_PORT[scheme]) port = '';
  }
  return {
    scheme,
    labels,
    port,
    canonical: `${scheme}://${host}${port === '' ? '' : `:${port}`}`,
    label,
  };
}

function labelMatches(pattern: string, label: string): boolean {
  const star = pattern.indexOf('*');
  if (star < 0) return pattern === label;
  const before = pattern.slice(0, star);
  const after = pattern.slice(star + 1);
  return (
    label.length > before.length + after.length && label.startsWith(before) && label.endsWith(after)
  );
}

/** Whether the pattern matches the canonical origin `url` (07-REQ-25). IPv6 hosts never match. */
export function patternMatches(pattern: HostPattern, url: URL): boolean {
  if (url.protocol !== `${pattern.scheme}:`) return false;
  if (url.port !== pattern.port) return false;
  if (url.hostname.startsWith('[')) return false;
  const labels = url.hostname.toLowerCase().split('.');
  if (labels.length !== pattern.labels.length) return false;
  return pattern.labels.every((part, i) => labelMatches(part, labels[i] ?? ''));
}

/** Literal characters of the host of a pattern, the first tie-breaker (07-REQ-25). */
function literal(pattern: HostPattern): number {
  return pattern.labels.join('.').replaceAll('*', '').length;
}

function stars(pattern: HostPattern): number {
  return pattern.labels.filter((part) => part.includes('*')).length;
}

/** Patterns in priority order: more literal characters, fewer `*`, smaller text (07-REQ-25). */
export function sortPatterns(patterns: readonly HostPattern[]): HostPattern[] {
  return [...patterns].sort(
    (a, b) =>
      literal(b) - literal(a) ||
      stars(a) - stars(b) ||
      (a.canonical < b.canonical ? -1 : a.canonical > b.canonical ? 1 : 0),
  );
}

/** The patterns of keys.origins, valid ones only, in priority order. */
export function compileHostPatterns(origins: Readonly<Record<string, string>>): HostPattern[] {
  const out: HostPattern[] = [];
  for (const [key, label] of Object.entries(origins)) {
    if (!isHostPattern(key)) continue;
    const parsed = parseHostPattern(key, label);
    if (typeof parsed !== 'string') out.push(parsed);
  }
  return sortPatterns(out);
}

/** The first matching pattern for an origin, or null (07-REQ-25). */
export function matchingPattern(patterns: readonly HostPattern[], url: URL): HostPattern | null {
  return patterns.find((p) => patternMatches(p, url)) ?? null;
}
