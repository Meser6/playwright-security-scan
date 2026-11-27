// Redaction of evidence (07, chapter 5; P-07). Runs in the worker on rule results, before they
// reach the buffer (05-REQ-16); enforceRedaction() is applied to every snippet anyway (07-REQ-12).
import { sha256 } from '../hash/index.ts';
import { entropy } from '../patterns/entropy.ts';
import { decodeJwt, JWT_IN_TEXT } from '../patterns/jwt.ts';
import {
  CARD_IN_TEXT,
  cardNumber,
  EMAIL_IN_TEXT,
  isPesel,
  PESEL_IN_TEXT,
  PHONE_IN_TEXT,
} from '../patterns/pii.ts';
import { SECRET_PATTERNS } from '../patterns/secrets.ts';
import type { Evidence, RawFinding } from '../types/index.ts';

/** Maximum length of an evidence snippet (02, chapter 4; 07-REQ-14). */
export const MAX_SNIPPET = 200;
/** Characters kept before and after a match in a body snippet (07-REQ-14). */
export const SNIPPET_CONTEXT = 80;

/** Query parameters whose values are always redacted: the defaults of data.token-in-url (06). */
export const SENSITIVE_PARAMS: readonly string[] = [
  'token',
  'access_token',
  'id_token',
  'refresh_token',
  'api_key',
  'apikey',
  'password',
  'passwd',
  'secret',
  'session',
  'sessionid',
  'jwt',
  'auth',
];

/** Session parameters of auth.session-in-url, redacted too (07-REQ-13, v0.4). */
export const SESSION_PARAMS: readonly string[] = ['sid', 'jsessionid', 'phpsessid', 'session_id'];

/** Headers whose values are always redacted (07-REQ-13). */
const SENSITIVE_HEADER =
  /^(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token)$/i;
const SENSITIVE_HEADER_PART = /token|secret|key|auth|session|passw/i;

/** Whether the value of a header is always redacted (07-REQ-13). */
export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADER.test(name) || SENSITIVE_HEADER_PART.test(name);
}

// Placeholders the redactor writes; never redacted again.
const PLACEHOLDER =
  /\[(?:redacted |jwt [^\]]*|email |pesel |phone |card [a-z]+ |)sha256:[0-9a-f]{6}\]/g;
// Long base64/hex-like runs: candidates for the entropy check of the final filter.
const TOKEN_RUN = /[A-Za-z0-9+/_=-]{24,}/g;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g;

export interface RedactorOptions {
  /** Random per run (07-REQ-15): hashes compare within a report, not across runs. */
  salt: string;
  /** Extra query parameter names to redact, e.g. the paramNames option of data.token-in-url. */
  paramNames?: readonly string[];
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Redacts values; one instance per run and worker, created with the run salt. */
export class Redactor {
  readonly #salt: string;
  readonly #params: RegExp;

  constructor(options: RedactorOptions) {
    this.#salt = options.salt;
    const names = [
      ...new Set([...SENSITIVE_PARAMS, ...SESSION_PARAMS, ...(options.paramNames ?? [])]),
    ];
    this.#params = new RegExp(
      `([?&;#]|\\b)(${names.map(escapeRegex).join('|')})=([^&#\\s"'<>;]+)`,
      'gi',
    );
  }

  /** First 6 hex digits of the salted SHA-256 of `value` (07-REQ-15). */
  hash(value: string): string {
    return sha256(`${this.#salt}\u0000${value}`).slice(0, 6);
  }

  /** `[redacted sha256:xxxxxx]` */
  value(value: string): string {
    return `[redacted sha256:${this.hash(value)}]`;
  }

  /** `eyJ…[jwt alg=HS256 sha256:xxxxxx]` (07-REQ-13). */
  jwt(token: string): string {
    const alg = decodeJwt(token)?.header.alg;
    const algText =
      typeof alg === 'string' ? ` alg=${alg.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 16)}` : '';
    return `eyJ…[jwt${algText} sha256:${this.hash(token)}]`;
  }

  /** The first 4 characters and `…[sha256:xxxxxx]` (07-REQ-13). */
  secret(match: string): string {
    return `${match.slice(0, 4)}…[sha256:${this.hash(match)}]`;
  }

  /** `[email sha256:xxxxxx]`, `[pesel …]`, `[phone …]` (07-REQ-13, v3). */
  pii(kind: 'email' | 'pesel' | 'phone', value: string): string {
    return `[${kind} sha256:${this.hash(value)}]`;
  }

  /** `[card visa sha256:xxxxxx]`: the brand without any digit of the number (07-REQ-13). */
  card(brand: string, digits: string): string {
    return `[card ${brand} sha256:${this.hash(digits)}]`;
  }

  /** A header value as it may appear in evidence (07-REQ-13). */
  header(name: string, value: string): string {
    const lower = name.toLowerCase();
    if (lower === 'set-cookie') return this.setCookie(value);
    if (lower === 'cookie') {
      return value
        .split(';')
        .map((pair) => {
          const eq = pair.indexOf('=');
          return eq < 0
            ? pair.trim()
            : `${pair.slice(0, eq).trim()}=${this.value(pair.slice(eq + 1).trim())}`;
        })
        .join('; ');
    }
    if (lower === 'authorization' || lower === 'proxy-authorization') {
      const space = value.indexOf(' ');
      const scheme = space > 0 ? value.slice(0, space) : '';
      const credentials = space > 0 ? value.slice(space + 1).trim() : value;
      const redacted =
        decodeJwt(credentials) !== null ? this.jwt(credentials) : this.value(credentials);
      return scheme === '' ? redacted : `${scheme} ${redacted}`;
    }
    if (isSensitiveHeader(lower)) return this.value(value);
    return this.text(value);
  }

  /** A Set-Cookie value with its cookie value replaced; attributes are kept (07-REQ-13). */
  setCookie(value: string): string {
    const semi = value.indexOf(';');
    const pair = semi < 0 ? value : value.slice(0, semi);
    const attributes = semi < 0 ? '' : value.slice(semi);
    const eq = pair.indexOf('=');
    const name = eq < 0 ? '' : pair.slice(0, eq).trim();
    const cookieValue = eq < 0 ? pair : pair.slice(eq + 1);
    return this.text(`${name}=${this.value(cookieValue.trim())}${attributes}`);
  }

  /**
   * The final filter for any text (07-REQ-12, 07-REQ-13): JWTs, secret patterns, values of
   * sensitive query parameters, Bearer credentials and long high-entropy strings are redacted;
   * control characters are replaced; the result is at most MAX_SNIPPET characters.
   */
  text(input: string): string {
    return truncate(this.#redact(input), MAX_SNIPPET);
  }

  /**
   * The filter of text() without the length limit, for request bodies of attack templates
   * (19 chapter 11a): they are sent to ZAP whole.
   */
  full(input: string): string {
    return this.#redact(input);
  }

  #redact(input: string): string {
    const kept: string[] = [];
    // Protect placeholders written earlier.
    // Control characters first: the markers below are control characters themselves.
    const clean = input.replace(/\r\n|[\r\n\t]/g, ' ').replace(CONTROL, '?');
    let text = clean.replace(PLACEHOLDER, (m) => {
      kept.push(m);
      return `\u0001${kept.length - 1}\u0001`;
    });
    const keep = (m: string): string => {
      kept.push(m);
      return `\u0001${kept.length - 1}\u0001`;
    };
    text = text.replace(JWT_IN_TEXT, (m) => keep(this.jwt(m)));
    for (const pattern of SECRET_PATTERNS) {
      text = text.replace(new RegExp(pattern.regex.source, pattern.regex.flags), (m) =>
        keep(this.secret(m)),
      );
    }
    // Personal data and card numbers in any evidence (07-REQ-13, v3).
    text = text.replace(EMAIL_IN_TEXT, (m) => keep(this.pii('email', m)));
    text = text.replace(CARD_IN_TEXT, (m) => {
      const digits = m.replace(/[ -]/g, '');
      const brand = cardNumber(digits);
      return brand === undefined ? m : keep(this.card(brand, digits));
    });
    text = text.replace(PESEL_IN_TEXT, (m) => (isPesel(m) ? keep(this.pii('pesel', m)) : m));
    text = text.replace(PHONE_IN_TEXT, (m) => keep(this.pii('phone', m)));
    text = text.replace(
      /\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{8,})/g,
      (_m, scheme: string, value: string) => keep(`${scheme} ${this.value(value)}`),
    );
    text = text.replace(this.#params, (_m, lead: string, name: string, value: string) =>
      keep(`${lead}${name}=${this.value(value)}`),
    );
    text = text.replace(TOKEN_RUN, (m) =>
      /[0-9]/.test(m) && /[A-Za-z]/.test(m) && entropy(m) >= 3.5 ? keep(this.value(m)) : m,
    );
    // eslint-disable-next-line no-control-regex
    text = text.replace(/\u0001(\d+)\u0001/g, (_m, i: string) => kept[Number(i)] ?? '');
    return text;
  }

  /** A snippet of `text` around [index, index + length) (07-REQ-14), redacted. */
  snippet(text: string, index: number, length: number): string {
    const start = Math.max(0, index - SNIPPET_CONTEXT);
    const end = Math.min(text.length, index + length + SNIPPET_CONTEXT);
    const prefix = start > 0 ? '…' : '';
    const suffix = end < text.length ? '…' : '';
    return this.text(`${prefix}${text.slice(start, end)}${suffix}`);
  }

  /** Every evidence snippet and the message through the final filter (07-REQ-12). */
  enforce<T extends Pick<RawFinding, 'evidence' | 'message'>>(finding: T): T {
    return {
      ...finding,
      message: this.text(finding.message),
      evidence: finding.evidence.map((e): Evidence => ({ ...e, snippet: this.text(e.snippet) })),
    };
  }
}

/** Cuts `text` to `max` characters, ending with '…' when cut; never splits a surrogate pair. */
export function truncate(text: string, max: number): string {
  if (text.length <= max) return text;
  let cut = max - 1;
  const code = text.charCodeAt(cut - 1);
  if (code >= 0xd800 && code <= 0xdbff) cut -= 1;
  return `${text.slice(0, cut)}…`;
}
