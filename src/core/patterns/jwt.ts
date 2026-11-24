// JWT detection and decoding without signature verification (06, chapter 4.5).

/** JWTs inside a text: three base64url segments, the first starting with eyJ ('{"'). */
export const JWT_IN_TEXT = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown> | null;
}

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Decodes base64url to text (UTF-8); null when the input is not base64url. */
export function base64UrlDecode(input: string): string | null {
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of input.replace(/=+$/, '')) {
    const index = BASE64URL.indexOf(ch === '+' ? '-' : ch === '/' ? '_' : ch);
    if (index < 0) return null;
    value = (value << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
  } catch {
    return null;
  }
}

function parseObject(text: string | null): Record<string, unknown> | null {
  if (text === null) return null;
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** A JWT: its header decodes to a JSON object with `alg` (06, chapter 4.5); otherwise null. */
export function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const header = parseObject(base64UrlDecode(parts[0] ?? ''));
  if (header === null || typeof header.alg !== 'string') return null;
  return { header, payload: parseObject(base64UrlDecode(parts[1] ?? '')) };
}
