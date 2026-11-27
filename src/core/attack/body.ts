// Request bodies of attack templates (19-REQ-03, 19 chapter 11a): only some types, values of
// credential-like fields replaced, then the evidence redaction of 07-REQ-13 over the whole text.
import type { Redactor } from '../fingerprint/index.ts';

/** Methods whose templates keep a body. */
export const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
/** The value of a redacted field. */
export const REDACTED_FIELD = '[redacted]';
/** A field name with one of these parts is redacted, whatever the lists say. */
const CREDENTIAL_PART = /pass|pwd|secret|token|auth|key/i;

/** The kind of body a template may keep, or null. */
export function bodyKind(contentType: string | undefined): 'json' | 'form' | 'text' | null {
  const type = (contentType ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
  if (type === 'application/json' || type.endsWith('+json')) return 'json';
  if (type === 'application/x-www-form-urlencoded') return 'form';
  if (type === 'text/plain') return 'text';
  return null;
}

export interface BodyRedaction {
  redactor: Redactor;
  /** Lower-case names of data.token-in-url (with paramNames) and auth.session-in-url. */
  names: ReadonlySet<string>;
}

const credential = (name: string, r: BodyRedaction): boolean =>
  r.names.has(name.toLowerCase()) || CREDENTIAL_PART.test(name);

function redactJson(value: unknown, r: BodyRedaction): unknown {
  if (Array.isArray(value)) return value.map((v) => redactJson(v, r));
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [
        k,
        credential(k, r) && (typeof v !== 'object' || v === null)
          ? REDACTED_FIELD
          : redactJson(v, r),
      ]),
    );
  }
  return value;
}

/**
 * The body a template keeps (19 chapter 11a), or undefined: another type, too long (cut bodies are
 * not valid requests) or not parseable JSON.
 */
export function templateBody(
  text: string | null | undefined,
  contentType: string | undefined,
  maxBytes: number,
  r: BodyRedaction,
): string | undefined {
  if (text === null || text === undefined || text === '') return undefined;
  if (new TextEncoder().encode(text).length > maxBytes) return undefined;
  const kind = bodyKind(contentType);
  if (kind === 'json') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return undefined;
    }
    return r.redactor.full(JSON.stringify(redactJson(parsed, r)));
  }
  if (kind === 'form') {
    const params = new URLSearchParams(text);
    const out = new URLSearchParams();
    for (const [name, value] of params) {
      out.append(name, credential(name, r) ? REDACTED_FIELD : r.redactor.full(value));
    }
    return out.toString();
  }
  if (kind === 'text') return r.redactor.full(text);
  return undefined;
}
