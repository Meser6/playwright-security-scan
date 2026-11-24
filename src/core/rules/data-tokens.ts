// data.* rules about tokens in URLs, JWTs and passwords (06, chapter 4.5).
import { decodeJwt, JWT_IN_TEXT } from '../patterns/jwt.ts';
import { looksLikeJwt } from '../patterns/entropy.ts';
import type { RawFinding, ResponseRecord } from '../types/index.ts';
import { finding, header, headers, isJson, manifestOf } from './types.ts';
import type { BuiltInRule, RuleContext } from './types.ts';

const isRecord = (input: unknown): input is ResponseRecord =>
  typeof input === 'object' && input !== null && 'status' in input;

const TOKEN_IN_URL = manifestOf('data.token-in-url');
export const tokenInUrl: BuiltInRule = {
  id: TOKEN_IN_URL.id,
  manifest: TOKEN_IN_URL,
  appliesTo: {},
  check(input, ctx) {
    if (!isRecord(input)) return [];
    let url: URL;
    try {
      url = new URL(input.url);
    } catch {
      return [];
    }
    const names = new Set(
      ((ctx.options.paramNames as string[] | undefined) ?? []).map((n) => n.toLowerCase()),
    );
    const out: RawFinding[] = [];
    const seen = new Set<string>();
    for (const [name, value] of url.searchParams) {
      if (value === '' || seen.has(name)) continue;
      const jwt = looksLikeJwt(value);
      if (!names.has(name.toLowerCase()) && !jwt) continue;
      seen.add(name);
      out.push(
        finding(ctx, TOKEN_IN_URL, {
          subject: input.endpointKey,
          discriminator: name,
          location: { origin: input.origin, endpointKey: input.endpointKey, param: name },
          evidence: [
            {
              kind: 'url',
              name,
              snippet: `${name}=${jwt ? ctx.redact.jwt(value) : ctx.redact.value(value)}`,
            },
          ],
          message: `${input.endpointKey} carries ${jwt ? 'a JWT' : 'a secret value'} in the query parameter "${name}".`,
        }),
      );
    }
    return out;
  },
  docs: {
    title: TOKEN_IN_URL.title,
    why: 'URLs end up in browser history, server and proxy logs and the Referer header of linked sites, so a token in the query leaks far beyond the request.',
    fix: [
      'Send tokens in a header (`Authorization`) or a request body, never in the query string; for links (password reset, magic login) use short-lived one-time codes.',
      '',
      '- nginx: do not log the query of such endpoints (`log_format` without `$args`) while fixing the client',
      "- Express: read the token from `req.get('authorization')`, not `req.query`",
      '- Spring Security: `BearerTokenResolver` without `setAllowUriQueryParameter(true)`',
    ].join('\n'),
    falsePositives:
      'OAuth authorization codes (`code`) are expected and not on the default list; one-time codes in email links can be accepted with a note. The names are the option paramNames.',
  },
};

interface FoundJwt {
  token: string;
  where: 'authorization' | 'set-cookie' | 'cookie' | 'body';
  /** Text before the token in a body, to tell refresh tokens apart. */
  context: string;
}

/** JWTs of a record (06, chapter 4.5): the authorization header, cookies and the body. */
function jwtsOf(r: ResponseRecord): FoundJwt[] {
  const out: FoundJwt[] = [];
  const auth = header(r.requestHeaders, 'authorization');
  const bearer = auth === undefined ? undefined : /^\s*bearer\s+(\S+)/i.exec(auth)?.[1];
  if (bearer !== undefined && looksLikeJwt(bearer))
    out.push({ token: bearer, where: 'authorization', context: '' });
  for (const line of headers(r.responseHeaders, 'set-cookie')) {
    const pair = line.split(';')[0] ?? '';
    const value = pair.slice(pair.indexOf('=') + 1).trim();
    if (looksLikeJwt(value))
      out.push({ token: value, where: 'set-cookie', context: pair.slice(0, pair.indexOf('=')) });
  }
  for (const pair of (header(r.requestHeaders, 'cookie') ?? '').split(';')) {
    const value = pair.slice(pair.indexOf('=') + 1).trim();
    if (looksLikeJwt(value))
      out.push({ token: value, where: 'cookie', context: pair.slice(0, pair.indexOf('=')) });
  }
  if (r.body !== undefined) {
    for (const m of r.body.text.matchAll(JWT_IN_TEXT)) {
      out.push({
        token: m[0],
        where: 'body',
        context: r.body.text.slice(Math.max(0, m.index - 40), m.index),
      });
    }
  }
  return out;
}

/**
 * Subject of a JWT finding: tokens a response issues (body, Set-Cookie) belong to the endpoint;
 * tokens a request sends (authorization, cookie) to the origin, so one token used by every API
 * call is one finding (06, chapter 4.9).
 */
function jwtFinding(
  ctx: RuleContext,
  m: ReturnType<typeof manifestOf>,
  r: ResponseRecord,
  jwt: FoundJwt,
  message: string,
  discriminator?: string,
): RawFinding {
  const sent = jwt.where === 'authorization' || jwt.where === 'cookie';
  return finding(ctx, m, {
    scope: sent ? 'origin' : 'endpoint',
    subject: sent ? r.origin : r.endpointKey,
    discriminator: discriminator ?? (sent ? `request-${jwt.where}` : undefined),
    location: { origin: r.origin, endpointKey: r.endpointKey },
    evidence: [
      {
        kind: jwt.where === 'body' ? 'body' : jwt.where === 'authorization' ? 'header' : 'cookie',
        name: jwt.where,
        snippet: ctx.redact.jwt(jwt.token),
      },
    ],
    message,
  });
}

function jwtRule(
  id: string,
  test: (
    decoded: NonNullable<ReturnType<typeof decodeJwt>>,
    jwt: FoundJwt,
    ctx: RuleContext,
  ) => { message: string; discriminator?: string } | null,
  docs: Omit<BuiltInRule['docs'], 'title'>,
): BuiltInRule {
  const m = manifestOf(id);
  return {
    id,
    manifest: m,
    appliesTo: { resourceTypes: ['document', 'xhr', 'fetch', 'api', 'other'] },
    needsBody: ['document', 'xhr', 'fetch', 'api'],
    check(input, ctx) {
      if (!isRecord(input)) return [];
      const out: RawFinding[] = [];
      const seen = new Set<string>();
      for (const jwt of jwtsOf(input)) {
        const decoded = decodeJwt(jwt.token);
        if (decoded === null) continue;
        const hit = test(decoded, jwt, ctx);
        if (hit === null) continue;
        const key = `${jwt.where}\u0000${hit.discriminator ?? ''}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(jwtFinding(ctx, m, input, jwt, hit.message, hit.discriminator));
      }
      return out;
    },
    docs: { title: m.title, ...docs },
  };
}

const JWT_FIX = (what: string, express: string, spring: string): string =>
  [
    what,
    '',
    '- nginx (auth_jwt / OpenResty): reject tokens that fail the check before they reach the app',
    `- Express: ${express}`,
    `- Spring Security: ${spring}`,
  ].join('\n');

export const jwtAlgNone = jwtRule(
  'data.jwt-alg-none',
  (d, jwt) =>
    String(d.header.alg).toLowerCase() === 'none'
      ? {
          message: `An unsigned JWT (alg "none") is ${jwt.where === 'body' || jwt.where === 'set-cookie' ? 'issued' : 'sent'} here.`,
        }
      : null,
  {
    why: 'A token with alg "none" has no signature: anyone can change its claims (user id, roles) and, if the server accepts it, become any user.',
    fix: JWT_FIX(
      'Sign every token and accept only the algorithms you issue.',
      "`jwt.verify(token, key, { algorithms: ['RS256'] })` (jsonwebtoken)",
      '`NimbusJwtDecoder.withPublicKey(key).signatureAlgorithm(SignatureAlgorithm.RS256).build()`',
    ),
    falsePositives: 'None known.',
  },
);

export const jwtNoExp = jwtRule(
  'data.jwt-no-exp',
  (d) =>
    d.payload !== null && d.payload.exp === undefined
      ? { message: 'A JWT without an expiry (exp) is used here.' }
      : null,
  {
    why: 'A token without exp is valid forever: a leaked token cannot expire and logout does not end the session.',
    fix: JWT_FIX(
      'Issue every access token with a short exp and check it.',
      "`jwt.sign(claims, key, { expiresIn: '15m' })`",
      '`JwtClaimsSet.builder().expiresAt(now.plus(15, MINUTES))`',
    ),
    falsePositives: 'Tokens of third parties you cannot change: accept them with a note.',
  },
);

export const jwtLongLived = jwtRule(
  'data.jwt-long-lived',
  (d, jwt, ctx) => {
    const p = d.payload;
    if (p === null || typeof p.exp !== 'number' || typeof p.iat !== 'number') return null;
    const refresh =
      /refresh/i.test(jwt.context) ||
      /refresh/i.test(String(p.typ ?? '')) ||
      /refresh/i.test(String(p.token_type ?? ''));
    if (refresh) return null;
    const hours = typeof ctx.options.maxJwtHours === 'number' ? ctx.options.maxJwtHours : 24;
    const lifetime = (p.exp - p.iat) / 3600;
    return lifetime > hours
      ? { message: `A JWT valid for ${Math.round(lifetime)} hours (limit ${hours}) is used here.` }
      : null;
  },
  {
    why: 'A long-lived access token gives an attacker who steals it a long window; access tokens should be short-lived and renewed with a refresh token.',
    fix: JWT_FIX(
      'Keep access tokens short (minutes) and renew them with a refresh token kept in an HttpOnly cookie.',
      "`jwt.sign(claims, key, { expiresIn: '15m' })`",
      '`JwtClaimsSet.builder().expiresAt(now.plus(15, MINUTES))`',
    ),
    falsePositives:
      'Refresh tokens are skipped when their name or claims say so. The limit is the option maxJwtHours.',
  },
);

const SENSITIVE_CLAIM = /(pass(word)?|pwd|secret|ssn|pesel|card|cvv|iban)/i;
export const jwtSensitiveClaims = jwtRule(
  'data.jwt-sensitive-claims',
  (d) => {
    const key = Object.keys(d.payload ?? {}).find((k) => SENSITIVE_CLAIM.test(k));
    return key === undefined
      ? null
      : { message: `A JWT carries the claim "${key}".`, discriminator: key };
  },
  {
    why: 'JWT payloads are only base64-encoded, not encrypted: anyone who sees the token reads every claim.',
    fix: JWT_FIX(
      'Keep secrets and personal data out of token claims; put an opaque id in the token and look the data up on the server.',
      '`jwt.sign({ sub: user.id }, key)` without sensitive fields',
      '`JwtClaimsSet.builder().subject(userId)` without sensitive claims',
    ),
    falsePositives:
      'Claims whose names only look sensitive (e.g. "card_type"): accept them as false-positive.',
  },
);

const PASSWORD = manifestOf('data.password-in-response');
const PASSWORD_KEYS = new Set(['password', 'passwordhash', 'password_hash', 'hash', 'salt']);
/** Password hash formats: bcrypt, argon2, scrypt, PBKDF2, crypt(3), long hex or base64. */
const HASH =
  /^(?:\$(?:2[abxy]?|argon2(?:id|i|d)|scrypt|pbkdf2[^$]*|[156])\$\S{8,}|[0-9a-f]{32,}|[A-Za-z0-9+/]{24,}={0,2})$/i;

/**
 * A value that can be a password or a hash, not a label: a hash format, or a single word of at
 * least 6 characters with a digit or a symbol. Translation files ("password": "Password") are
 * not reported (pwexample pilot).
 */
function secretLike(value: string): boolean {
  if (HASH.test(value)) return true;
  return value.length >= 6 && !/\s/.test(value) && /[^\p{L}]/u.test(value);
}

function findPasswordKeys(value: unknown, depth = 0, found = new Set<string>()): Set<string> {
  if (depth > 10 || value === null || typeof value !== 'object') return found;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 200)) findPasswordKeys(item, depth + 1, found);
    return found;
  }
  for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
    if (PASSWORD_KEYS.has(key.toLowerCase()) && typeof v === 'string' && secretLike(v))
      found.add(key);
    findPasswordKeys(v, depth + 1, found);
  }
  return found;
}

export const passwordInResponse: BuiltInRule = {
  id: PASSWORD.id,
  manifest: PASSWORD,
  appliesTo: { resourceTypes: ['xhr', 'fetch', 'api', 'document', 'other'] },
  needsBody: ['xhr', 'fetch', 'api', 'document'],
  check(input, ctx) {
    if (!isRecord(input) || input.body === undefined || !isJson(input.body.contentType)) return [];
    let parsed: unknown;
    try {
      parsed = JSON.parse(input.body.text);
    } catch {
      return [];
    }
    return [...findPasswordKeys(parsed)].sort().map((key) =>
      finding(ctx, PASSWORD, {
        subject: input.endpointKey,
        discriminator: key,
        location: { origin: input.origin, endpointKey: input.endpointKey },
        evidence: [{ kind: 'body', name: key, snippet: `"${key}": ${ctx.redact.value(key)}` }],
        message: `${input.endpointKey} returns the field "${key}" with a value.`,
      }),
    );
  },
  docs: {
    title: PASSWORD.title,
    why: 'Password hashes and salts in API responses can be cracked offline; they should never leave the server.',
    fix: [
      'Exclude credential fields from the response model (a DTO or serializer allow-list).',
      '',
      '- nginx: nothing to configure; fix the application',
      '- Express: `const { password, passwordHash, ...safe } = user; res.json(safe)` or a schema serializer',
      '- Spring: `@JsonIgnore` on the field or a response DTO without it',
    ].join('\n'),
    falsePositives:
      '"hash" or "salt" fields that are not credentials (content hashes, cache keys): accept them as false-positive.',
  },
};

export const TOKEN_RULES: readonly BuiltInRule[] = [
  tokenInUrl,
  jwtAlgNone,
  jwtNoExp,
  jwtLongLived,
  jwtSensitiveClaims,
  passwordInResponse,
];
