// data.* rules (06, chapter 4.5).
import { normalizeAssetUrl, normalizeName } from '../fingerprint/index.ts';
import { ruleManifest } from '../manifest/rules.ts';
import type { RuleManifest } from '../manifest/rules.ts';
import { looksLikeJwt, looksLikeToken } from '../patterns/entropy.ts';
import { SECRET_PATTERNS } from '../patterns/secrets.ts';
import type { Confidence } from '../types/index.ts';
import { finding } from './types.ts';
import type { BuiltInRule } from './types.ts';

const m = (id: string): RuleManifest => {
  const found = ruleManifest(id);
  if (found === undefined) throw new Error(`no manifest entry for ${id}`);
  return found;
};

const lower = (a: Confidence, b: Confidence): Confidence => {
  const order: Confidence[] = ['low', 'medium', 'high'];
  return order.indexOf(a) < order.indexOf(b) ? a : b;
};

interface CustomPattern {
  name: string;
  regex: string;
  flags?: string;
}

const STATIC = new Set(['script', 'stylesheet']);

const SECRET = m('data.secret-in-asset');
export const secretInAsset: BuiltInRule = {
  id: SECRET.id,
  manifest: SECRET,
  appliesTo: { resourceTypes: ['document', 'script', 'xhr', 'fetch', 'api'] },
  needsBody: ['document', 'script', 'xhr', 'fetch', 'api'],
  check(input, ctx) {
    if (!('status' in input) || input.body === undefined) return [];
    const ignore = new Set((ctx.options.ignore as string[] | undefined) ?? []);
    const custom = ((ctx.options.patterns as CustomPattern[] | undefined) ?? []).map((p) => ({
      name: p.name,
      title: p.name,
      regex: new RegExp(p.regex, `${(p.flags ?? '').replace(/g/g, '')}g`),
      confidence: 'high' as Confidence,
    }));
    const isStatic = STATIC.has(input.resourceType);
    const subject = isStatic
      ? (normalizeAssetUrl(input.url) ?? input.endpointKey)
      : input.endpointKey;
    const text = input.body.text;
    const out = [];
    for (const pattern of [...SECRET_PATTERNS, ...custom]) {
      if (ignore.has(pattern.name)) continue;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      const match = regex.exec(text);
      if (match === null) continue;
      out.push(
        finding(ctx, SECRET, {
          scope: isStatic ? 'asset' : 'endpoint',
          subject,
          discriminator: pattern.name,
          confidence: lower(ctx.confidence, pattern.confidence),
          location: { origin: input.origin, endpointKey: input.endpointKey },
          evidence: [
            { kind: 'body', snippet: ctx.redact.snippet(text, match.index, match[0].length) },
          ],
          message: `${pattern.title} found in ${isStatic ? subject : input.endpointKey}.`,
        }),
      );
    }
    return out;
  },
  docs: {
    title: SECRET.title,
    why: 'Anything sent to the browser or returned by the API is public. A secret key in a bundle or a response can be copied by anyone who opens the page.',
    fix: [
      'Remove the secret from client code and responses, rotate it, and call the third-party API from the server.',
      '',
      '- nginx: never inject secrets into served files (`sub_filter`, templated configs).',
      '- Express: keep secrets in server-only environment variables; do not expose them through `DefinePlugin`/`import.meta.env` with a public prefix.',
      '- Spring: keep secrets in server-side properties; never serialize them in DTOs.',
    ].join('\n'),
    falsePositives:
      'Publishable keys (Google Maps/Firebase `AIza…`) are public by design and reported with low confidence. Test fixtures and documentation examples may match; accept them as false-positive in the baseline.',
  },
};

const STORAGE = m('data.token-in-storage');
const STORAGE_KEY = /(token|jwt|auth|session)/i;
export const tokenInStorage: BuiltInRule = {
  id: STORAGE.id,
  manifest: STORAGE,
  appliesTo: { events: ['storage'], sources: ['browser'] },
  check(input, ctx) {
    if (!('kind' in input) || input.kind !== 'storage') return [];
    const out = [];
    for (const { key, value } of input.entries) {
      const jwt = looksLikeJwt(value);
      if (!jwt && !(STORAGE_KEY.test(key) && looksLikeToken(value))) continue;
      const name = normalizeName(key);
      out.push(
        finding(ctx, STORAGE, {
          subject: `${name}@${input.origin}`,
          discriminator: input.area,
          location: { origin: input.origin },
          evidence: [
            {
              kind: 'storage',
              name,
              snippet: jwt ? ctx.redact.jwt(value) : ctx.redact.value(value),
            },
          ],
          message: `${input.area === 'local' ? 'localStorage' : 'sessionStorage'} key "${name}" holds a ${jwt ? 'JWT' : 'token-like value'}.`,
        }),
      );
    }
    return out;
  },
  docs: {
    title: STORAGE.title,
    why: 'Web Storage is readable by every script on the page, so one XSS is enough to steal the token. HttpOnly cookies are not readable by scripts.',
    fix: [
      'Keep session tokens in a cookie with `HttpOnly; Secure; SameSite=Lax` and drop them from Web Storage.',
      '',
      '- nginx: proxy the auth endpoint and set the cookie there (`proxy_cookie_flags ~ httponly secure samesite=lax;`).',
      "- Express: `res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' })`.",
      '- Spring Security: use the session cookie (`server.servlet.session.cookie.http-only=true`) instead of returning the token to the SPA.',
    ].join('\n'),
    falsePositives:
      'Short-lived tokens of a Backend-for-Frontend, or values that only look random (cache keys, ids). Accept them in the baseline with a note.',
  },
};
