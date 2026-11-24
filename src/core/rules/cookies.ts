// Set-Cookie parsing and the session cookie heuristic (06, chapter 4.2).
import { looksLikeToken } from '../patterns/entropy.ts';

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

/** Session cookie (06, chapter 4.2): the name matches the pattern or the value looks like a token. */
export function isSessionCookie(name: string, value: string, pattern: string): boolean {
  let re: RegExp;
  try {
    re = new RegExp(pattern, 'i');
  } catch {
    re = /(sess|sid|auth|token|jwt)/i;
  }
  return re.test(name) || looksLikeToken(value);
}
