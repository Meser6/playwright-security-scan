// Set-Cookie parsing and the session cookie heuristic (06, chapter 4.2).
import { NON_SESSION_COOKIES } from '../manifest/rules.ts';
import { looksLikeJwt, looksLikeToken } from '../patterns/entropy.ts';

export interface ParsedCookie {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  /** As written; undefined when the attribute is missing. */
  sameSite?: string;
  /** Seconds, from Max-Age. */
  maxAge?: number;
  /** Text of Expires. */
  expires?: string;
  domain?: string;
  path?: string;
}

/** Parses one Set-Cookie header value (RFC 6265, 5.2); null without a name. */
export function parseSetCookie(header: string): ParsedCookie | null {
  const [pair = '', ...attributes] = header.split(';');
  const eq = pair.indexOf('=');
  if (eq <= 0) return null;
  const cookie: ParsedCookie = {
    name: pair.slice(0, eq).trim(),
    value: pair.slice(eq + 1).trim(),
    secure: false,
    httpOnly: false,
  };
  for (const attribute of attributes) {
    const i = attribute.indexOf('=');
    const key = (i < 0 ? attribute : attribute.slice(0, i)).trim().toLowerCase();
    const value = i < 0 ? '' : attribute.slice(i + 1).trim();
    if (key === 'secure') cookie.secure = true;
    else if (key === 'httponly') cookie.httpOnly = true;
    else if (key === 'samesite') cookie.sameSite = value;
    else if (key === 'max-age' && /^-?\d+$/.test(value)) cookie.maxAge = Number(value);
    else if (key === 'expires') cookie.expires = value;
    else if (key === 'domain') cookie.domain = value;
    else if (key === 'path') cookie.path = value;
  }
  return cookie;
}

/** A cookie that deletes itself (logout): empty value, Max-Age ≤ 0 or Expires in the past. */
export function isDeletion(cookie: ParsedCookie, now: number | undefined): boolean {
  if (cookie.value === '' || cookie.value === '""') return true;
  if (cookie.maxAge !== undefined && cookie.maxAge <= 0) return true;
  if (cookie.expires !== undefined && now !== undefined) {
    const at = Date.parse(cookie.expires);
    if (Number.isFinite(at) && at <= now) return true;
  }
  return false;
}

/** Analytics, consent and CDN cookies (manifest default of the option nonSessionNames). */
export const NON_SESSION_NAMES: readonly string[] = NON_SESSION_COOKIES;

function matchesName(name: string, patterns: readonly string[]): boolean {
  return patterns.some((p) =>
    p.endsWith('*') ? name.startsWith(p.slice(0, -1)) : name.toLowerCase() === p.toLowerCase(),
  );
}

/** An opaque token value: no dots or spaces, token characters only (06, chapter 4.2). */
const OPAQUE = /^[A-Za-z0-9+/=_%-]+$/;

/**
 * Session cookie (06, chapter 4.2): not a known analytics or consent cookie, and the name matches
 * the pattern or the value is a JWT or an opaque high-entropy token.
 */
export function isSessionCookie(
  name: string,
  value: string,
  pattern: string,
  nonSession: readonly string[] = NON_SESSION_NAMES,
): boolean {
  if (matchesName(name, nonSession)) return false;
  let re: RegExp;
  try {
    re = new RegExp(pattern, 'i');
  } catch {
    re = /(sess|sid|auth|token|jwt)/i;
  }
  if (re.test(name)) return true;
  return looksLikeJwt(value) || (OPAQUE.test(value) && looksLikeToken(value));
}
