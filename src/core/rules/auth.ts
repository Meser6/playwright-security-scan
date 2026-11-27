// auth.* rules (06, chapters 4.13 and 4.14).
import { cookieSubject } from '../fingerprint/index.ts';
import { TOKEN_PARAM_NAMES } from '../manifest/rules.ts';
import type { RawFinding, ResponseRecord, TestTraffic, TrafficRequest } from '../types/index.ts';
import { sessionTest } from './cookies.ts';
import { finding, manifestOf } from './types.ts';
import type { BuiltInRule, RuleInput } from './types.ts';

const isRecord = (input: RuleInput): input is ResponseRecord => input.kind === 'response';
const isTraffic = (input: RuleInput): input is TestTraffic => input.kind === 'test-end';

/** The domain of a cookie for its subject: Domain attribute, cookie jar, or the request host. */
function cookieDomain(traffic: TestTraffic, name: string, fallbackOrigin: string): string {
  for (const r of traffic.requests) {
    const set = r.setCookies.find((c) => c.name === name && c.domain !== undefined);
    if (set?.domain !== undefined) return set.domain;
  }
  const jar = traffic.jarCookies.find((c) => c.name === name);
  if (jar !== undefined) return jar.domain;
  try {
    return new URL(fallbackOrigin).hostname;
  } catch {
    return fallbackOrigin;
  }
}

const FIXATION = manifestOf('auth.session-fixation');
export const sessionFixation: BuiltInRule = {
  id: FIXATION.id,
  manifest: FIXATION,
  appliesTo: { testEnd: true, sources: ['browser'] },
  check(input, ctx) {
    if (!isTraffic(input)) return [];
    const requests = [...input.requests].sort((a, b) => a.id - b.id);
    const loginAt = requests.findIndex((r) => r.isLoginCandidate);
    if (loginAt < 0) return [];
    const login = requests[loginAt] as TrafficRequest;
    const isSession = sessionTest(ctx);
    // Session cookies sent up to and with the login request: name → value hash.
    const before = new Map<string, string>();
    for (const r of requests.slice(0, loginAt + 1)) {
      for (const c of r.sentCookies) if (isSession(c)) before.set(c.name, c.valueHash);
    }
    const out: RawFinding[] = [];
    for (const [name, hash] of before) {
      let renewed = false;
      let reused = false;
      for (const r of requests.slice(loginAt)) {
        if (r !== login && r.sentCookies.some((c) => c.name === name && c.valueHash === hash)) {
          if (!renewed) reused = true;
        }
        if (r.setCookies.some((c) => c.name === name && c.valueHash !== hash)) renewed = true;
        if (renewed) break;
      }
      if (renewed || !reused) continue;
      out.push(
        finding(ctx, FIXATION, {
          subject: cookieSubject(name, cookieDomain(input, name, login.origin)),
          location: { origin: login.origin, endpointKey: login.endpointKey },
          evidence: [
            {
              kind: 'cookie',
              name,
              snippet: `${name}=[redacted sha256:${hash}] sent before and after ${login.endpointKey}`,
            },
          ],
          message: `Session cookie ${name} keeps its value across the login request ${login.endpointKey}.`,
        }),
      );
    }
    return out;
  },
  docs: {
    title: FIXATION.title,
    why: 'When the session id stays the same across login, an attacker who planted or learned the id before the victim signed in (session fixation) is signed in as the victim afterwards.',
    fix: [
      'Issue a new session id when the user signs in (and when privileges change), and invalidate the old one.',
      '',
      '- nginx: nothing to configure; the application must renew the session',
      '- Express: `req.session.regenerate(cb)` after a successful login (express-session)',
      '- Spring Security: session fixation protection `changeSessionId` (the default) — do not set `sessionFixation().none()`',
    ].join('\n'),
    falsePositives:
      'Login paths are recognized by the option loginPathPattern; an endpoint that only matches by name (e.g. a token refresh) can be reported. Sessions that only become privileged later (step-up) are not seen. Browser traffic only.',
  },
};

const IN_URL = manifestOf('auth.session-in-url');
const PATH_SESSION = /;(jsessionid|phpsessid)=([^;/?#]+)/gi;
export const sessionInUrl: BuiltInRule = {
  id: IN_URL.id,
  manifest: IN_URL,
  appliesTo: {},
  check(input, ctx) {
    if (!isRecord(input)) return [];
    let url: URL;
    try {
      url = new URL(input.url);
    } catch {
      return [];
    }
    const tokenNames = new Set(TOKEN_PARAM_NAMES);
    const names = new Set(
      ((ctx.options.paramNames as string[] | undefined) ?? [])
        .map((n) => n.toLowerCase())
        .filter((n) => !tokenNames.has(n)),
    );
    const found = new Map<string, { value: string; where: 'path' | 'query' }>();
    for (const m of url.pathname.matchAll(PATH_SESSION)) {
      const name = (m[1] ?? '').toLowerCase();
      if (!found.has(name)) found.set(name, { value: m[2] ?? '', where: 'path' });
    }
    for (const [name, value] of url.searchParams) {
      const lower = name.toLowerCase();
      if (value === '' || !names.has(lower) || found.has(name)) continue;
      found.set(name, { value, where: 'query' });
    }
    return [...found].map(([name, f]) =>
      finding(ctx, IN_URL, {
        subject: input.endpointKey,
        discriminator: name,
        location: { origin: input.origin, endpointKey: input.endpointKey, param: name },
        evidence: [
          {
            kind: 'url',
            name,
            snippet: `${f.where === 'path' ? ';' : ''}${name}=${ctx.redact.value(f.value)}`,
          },
        ],
        message: `${input.endpointKey} carries a session id in the ${f.where === 'path' ? 'path parameter' : 'query parameter'} "${name}".`,
      }),
    );
  },
  docs: {
    title: IN_URL.title,
    why: 'A session id in the URL ends up in browser history, logs and the Referer header of linked sites; whoever reads it takes over the session, and links with an id enable session fixation.',
    fix: [
      'Keep the session id in a cookie only and turn off URL rewriting of sessions.',
      '',
      '- nginx: do not log the query of such endpoints while fixing the application',
      '- Express: read the session from a cookie (express-session); never put `req.sessionID` into links',
      '- Spring Boot: `server.servlet.session.tracking-modes=cookie` (no `jsessionid` URL rewriting)',
    ].join('\n'),
    falsePositives:
      'A parameter named like a session that carries something else (e.g. `sid` as a site id): accept it with a note or change the option paramNames. Names of data.token-in-url are left to that rule.',
  },
};
