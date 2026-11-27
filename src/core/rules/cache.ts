// cache.* rules (06, chapters 4.13 and 4.14).
import type { ResponseRecord } from '../types/index.ts';
import { cookieValueClass, sessionTest } from './cookies.ts';
import { finding, header, isJson, manifestOf } from './types.ts';
import type { BuiltInRule } from './types.ts';

const CACHEABLE = manifestOf('cache.sensitive-cacheable');

/** Session cookies the request sent, by name (06, chapter 4.2). */
function sentSessionCookies(
  r: ResponseRecord,
  isSession: ReturnType<typeof sessionTest>,
): string[] {
  const out: string[] = [];
  for (const pair of (header(r.requestHeaders, 'cookie') ?? '').split(';')) {
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (value !== '' && isSession({ name, valueClass: cookieValueClass(value) })) out.push(name);
  }
  return out;
}

export const sensitiveCacheable: BuiltInRule = {
  id: CACHEABLE.id,
  manifest: CACHEABLE,
  appliesTo: { resourceTypes: ['document', 'xhr', 'fetch', 'api'] },
  check(input, ctx) {
    if (input.kind !== 'response' || input.method !== 'GET') return [];
    if (input.status < 200 || input.status > 299) return [];
    const type = (header(input.responseHeaders, 'content-type') ?? '').split(';')[0]?.trim() ?? '';
    if (!isJson(type) && type.toLowerCase() !== 'text/html') return [];
    const cacheControl = (header(input.responseHeaders, 'cache-control') ?? '').toLowerCase();
    if (/(?:^|[\s,])(?:no-store|private)(?:$|[\s,=])/.test(cacheControl)) return [];
    const authorization = header(input.requestHeaders, 'authorization') !== undefined;
    const cookies = sentSessionCookies(input, sessionTest(ctx));
    if (!authorization && cookies.length === 0) return [];
    // Shared caches do not store answers to authorization requests unless told so (RFC 9111 3.5);
    // the browser cache belongs to the same user (06, chapter 4.14).
    if (
      cookies.length === 0 &&
      !/(?:^|[\s,])(?:public|s-maxage|must-revalidate)(?:$|[\s,=])/.test(cacheControl)
    ) {
      return [];
    }
    // No freshness at all (no cache-control, expires or last-modified): nothing caches it, so the
    // finding does not block (06, chapter 4.14).
    const fresh =
      cacheControl !== '' ||
      header(input.responseHeaders, 'expires') !== undefined ||
      header(input.responseHeaders, 'last-modified') !== undefined;
    const credential = authorization
      ? 'an Authorization header'
      : `the session cookie ${cookies[0] ?? ''}`;
    return [
      finding(ctx, CACHEABLE, {
        subject: input.endpointKey,
        ...(fresh ? {} : { confidence: 'low' as const }),
        location: { origin: input.origin, endpointKey: input.endpointKey, header: 'cache-control' },
        evidence: [
          {
            kind: 'header',
            name: 'cache-control',
            snippet:
              cacheControl === ''
                ? 'no cache-control header'
                : `cache-control: ${ctx.redact.text(cacheControl)}`,
          },
        ],
        message: `${input.endpointKey} answers a request with ${credential} without Cache-Control no-store or private.`,
      }),
    ];
  },
  docs: {
    title: CACHEABLE.title,
    why: 'A personal response without `Cache-Control: no-store` (or at least `private`) can be kept by shared caches, proxies and the browser and shown to the next user of the same cache or device.',
    fix: [
      'Send `Cache-Control: no-store` on responses to authenticated requests (or `private, no-cache` when the browser may keep them).',
      '',
      '- nginx: `add_header Cache-Control "no-store" always;` in the locations of the application and API',
      "- Express: `res.set('Cache-Control', 'no-store')` in a middleware for authenticated routes (helmet's `noCache` in older versions)",
      '- Spring Security: the default `Cache-Control: no-cache, no-store, max-age=0, must-revalidate` — keep `headers().cacheControl()` on',
    ].join('\n'),
    falsePositives:
      'A response without cache-control, expires and last-modified has no freshness and is reported with low confidence. A CDN or gateway that sets cache headers after the application is not seen when the tests run against the application directly; public pages that only carry a session cookie. Requests with only an Authorization header are reported when the response allows shared caches (`public`, `s-maxage`, `must-revalidate`). API requests are judged only when the test passed the credential in its own headers.',
  },
};
