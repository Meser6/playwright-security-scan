// Normalization of origins, cookie and storage key names, and asset URLs (07, chapter 2).

/** `scheme://host[:port]`, lowercase, without the default port (07-REQ-02); null if invalid. */
export function normalizeOrigin(text: string): string | null {
  if (!URL.canParse(text)) return null;
  const url = new URL(text);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  return url.origin;
}

const UUID = /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i;
const DIGITS = /^[0-9]{6,}$/;
const HEX = /^(?=.*[0-9])[0-9a-f]{8,}$/i;
const UPPER_ID = /^(?=.*[0-9])(?=.*[A-Z])[A-Z0-9]{5,}$/;
const RANDOM = /^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9]{16,}$/;

/** A dynamic suffix: UUID, 6+ digits, hex with a digit, an upper-case id or a random string. */
function isDynamic(part: string): boolean {
  return (
    UUID.test(part) ||
    DIGITS.test(part) ||
    HEX.test(part) ||
    UPPER_ID.test(part) ||
    RANDOM.test(part)
  );
}

/**
 * A cookie or storage key name with its dynamic suffix replaced by `*` (07-REQ-03):
 * `_ga_3XK21` → `_ga_*`, `session_8f14e45f` → `session_*`, `wp_user_123456` → `wp_user_*`.
 */
export function normalizeName(name: string): string {
  const uuid =
    /^(.*[^_\-.:][_\-.:])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.exec(name);
  if (uuid !== null) return `${uuid[1] ?? ''}*`;
  const match = /^(.*[_\-.:])([^_\-.:]+)$/.exec(name);
  if (match === null) return name;
  const [, prefix = '', suffix = ''] = match;
  if (prefix.replace(/[_\-.:]/g, '') === '') return name;
  return isDynamic(suffix) ? `${prefix}*` : name;
}

/** Cookie domain without the leading dot, lowercase (07-REQ-03). */
export function normalizeCookieDomain(domain: string): string {
  return domain.replace(/^\./, '').toLowerCase();
}

/** Subject of a cookie finding: `name@domain` after normalization (06, chapter 4.2). */
export function cookieSubject(name: string, domain: string): string {
  return `${normalizeName(name)}@${normalizeCookieDomain(domain)}`;
}

const BUILD_HASH =
  /^(?:(?=.*[0-9])[0-9a-f]{8,}|[0-9]{8,}|(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9_]{8,})$/i;

function normalizeSegment(segment: string): string {
  // Parts split by '.' and '-' keep their separators: main.3f2a9c1b.js → main.*.js.
  return segment
    .split(/([.\-~])/)
    .map((part) => (BUILD_HASH.test(part) ? '*' : part))
    .join('');
}

/**
 * Normalized URL of an asset (07-REQ-04): no query or fragment, build hashes in path
 * segments replaced by `*` (`main.3f2a9c1b.js` → `main.*.js`, `chunk-ABCD1234.js` →
 * `chunk-*.js`). Null for a URL that is not http(s).
 */
export function normalizeAssetUrl(text: string): string | null {
  if (!URL.canParse(text)) return null;
  const url = new URL(text);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  const path = url.pathname
    .split('/')
    .map((segment) => normalizeSegment(segment))
    .join('/');
  return `${url.origin}${path}`;
}
