// cookie.* rules (06, chapter 4.2). Sources: Set-Cookie headers of in-scope responses and the
// cookie jar at the end of the test (05-REQ-23).
import { cookieSubject } from '../fingerprint/index.ts';
import type { RuleManifest } from '../manifest/rules.ts';
import type { BrowserEvent, Confidence, RawFinding, ResponseRecord } from '../types/index.ts';
import { isDeletion, isSessionCookie, parseSetCookie } from './cookies.ts';
import { finding, header, headers, manifestOf, transportConfidence } from './types.ts';
import type { BuiltInRule, RuleContext, RuleInput } from './types.ts';

/** A cookie as the rules see it, from a header or from the jar. */
interface CookieInput {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  /** undefined: the attribute is missing (headers) or unknown (jar). */
  sameSite: string | undefined;
  /** The jar cannot tell a missing SameSite from Lax. */
  sameSiteKnown: boolean;
  /** Lifetime in seconds, when known. */
  lifetime: number | undefined;
  domain: string;
  /** The Domain attribute of a Set-Cookie header; unset without it and for the jar. */
  domainAttribute?: string;
  https: boolean;
  origin: string;
  endpointKey?: string;
  /** Redacted Set-Cookie text or attribute summary, for evidence. */
  evidence: (ctx: RuleContext) => string;
}

function fromRecord(r: ResponseRecord): CookieInput[] {
  const date = header(r.responseHeaders, 'date');
  const now = date === undefined ? undefined : Date.parse(date);
  const out: CookieInput[] = [];
  for (const raw of headers(r.responseHeaders, 'set-cookie')) {
    // Some servers fold several cookies in one header line with newlines (allHeaders()).
    for (const line of raw.split('\n')) {
      const c = parseSetCookie(line);
      if (c === null || isDeletion(c, Number.isFinite(now) ? now : undefined)) continue;
      let lifetime: number | undefined = c.maxAge;
      if (
        lifetime === undefined &&
        c.expires !== undefined &&
        now !== undefined &&
        Number.isFinite(now)
      ) {
        const at = Date.parse(c.expires);
        if (Number.isFinite(at)) lifetime = Math.round((at - now) / 1000);
      }
      out.push({
        name: c.name,
        value: c.value,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite,
        sameSiteKnown: true,
        lifetime,
        domain: c.domain ?? new URL(r.url).hostname,
        ...(c.domain === undefined || c.domain === '' ? {} : { domainAttribute: c.domain }),
        https: r.url.startsWith('https:'),
        origin: r.origin,
        endpointKey: r.endpointKey,
        evidence: (ctx) => ctx.redact.setCookie(line),
      });
    }
  }
  return out;
}

function fromJar(event: Extract<BrowserEvent, { kind: 'cookie-jar' }>): CookieInput[] {
  return event.cookies
    .filter((c) => c.value !== '' && c.origin !== undefined)
    .map((c) => ({
      name: c.name,
      value: c.value,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      sameSiteKnown: false,
      lifetime: undefined,
      domain: c.domain,
      https: (c.origin ?? '').startsWith('https:'),
      origin: c.origin ?? '',
      evidence: (ctx: RuleContext) =>
        `${c.name}=${ctx.redact.value(c.value)}${c.secure ? '; Secure' : ''}${c.httpOnly ? '; HttpOnly' : ''}; SameSite=${c.sameSite} (cookie jar)`,
    }));
}

function cookiesOf(input: RuleInput): CookieInput[] {
  if (input.kind === 'response') return fromRecord(input);
  if (input.kind === 'cookie-jar') return fromJar(input);
  return [];
}

const sessionPattern = (ctx: RuleContext): string =>
  typeof ctx.options.sessionNamePattern === 'string'
    ? ctx.options.sessionNamePattern
    : 'sess|sid|auth|token';

function cookieFinding(
  ctx: RuleContext,
  m: RuleManifest,
  c: CookieInput,
  message: string,
  confidence?: Confidence,
): RawFinding {
  const location: RawFinding['location'] = { origin: c.origin };
  if (c.endpointKey !== undefined) location.endpointKey = c.endpointKey;
  return finding(ctx, m, {
    subject: cookieSubject(c.name, c.domain),
    location,
    evidence: [{ kind: 'cookie', name: c.name, snippet: c.evidence(ctx) }],
    message,
    ...(confidence === undefined ? {} : { confidence }),
  });
}

function cookieRule(
  id: string,
  test: (c: CookieInput, ctx: RuleContext) => { message: string; confidence?: Confidence } | null,
  docs: Omit<BuiltInRule['docs'], 'title'>,
  headersOnly = false,
): BuiltInRule {
  const m = manifestOf(id);
  return {
    id,
    manifest: m,
    // Headers of every in-scope response; the cookie jar too unless the rule needs attributes
    // the jar cannot give (SameSite missing, lifetime).
    appliesTo: headersOnly ? {} : { events: ['cookie-jar'], records: true },
    check(input, ctx) {
      const out: RawFinding[] = [];
      for (const c of cookiesOf(input)) {
        if (headersOnly && !c.sameSiteKnown) continue;
        const hit = test(c, ctx);
        if (hit !== null) out.push(cookieFinding(ctx, m, c, hit.message, hit.confidence));
      }
      return out;
    },
    docs: { title: m.title, ...docs },
  };
}

const isSession = (c: CookieInput, ctx: RuleContext): boolean =>
  isSessionCookie(
    c.name,
    c.value,
    sessionPattern(ctx),
    Array.isArray(ctx.options.nonSessionNames)
      ? (ctx.options.nonSessionNames as string[])
      : undefined,
  );

const cookieFix = (attributes: string, express: string, spring: string): string =>
  [
    `Set the cookie with \`${attributes}\`.`,
    '',
    `- nginx (as a proxy): \`proxy_cookie_flags ~ ${attributes.replace(/; /g, ' ').toLowerCase()};\``,
    `- Express: \`res.cookie('sid', value, ${express})\` (or the \`cookie\` options of \`express-session\`)`,
    `- Spring Boot: \`${spring}\``,
  ].join('\n');

const EXPRESS_SESSION = "{ secure: true, httpOnly: true, sameSite: 'lax' }";

export const noSecure = cookieRule(
  'cookie.no-secure',
  (c, ctx) =>
    c.https && !c.secure && isSession(c, ctx)
      ? {
          message: `Session cookie ${c.name} is set over HTTPS without Secure.`,
          confidence: transportConfidence(ctx),
        }
      : null,
  {
    why: 'A cookie without Secure is also sent over plain HTTP, where anyone on the network can read the session and take over the account.',
    fix: cookieFix(
      'Secure; HttpOnly; SameSite=Lax',
      EXPRESS_SESSION,
      'server.servlet.session.cookie.secure=true',
    ),
    falsePositives: 'Local development over HTTP is reported with low confidence only.',
  },
);

export const noHttpOnly = cookieRule(
  'cookie.no-httponly',
  (c, ctx) => {
    if (c.httpOnly || !isSession(c, ctx)) return null;
    const exceptions = Array.isArray(ctx.options.httpOnlyExceptions)
      ? (ctx.options.httpOnlyExceptions as string[]).map((n) => n.toLowerCase())
      : [];
    if (exceptions.includes(c.name.toLowerCase())) return null;
    return { message: `Session cookie ${c.name} is readable by JavaScript (no HttpOnly).` };
  },
  {
    why: 'A session cookie without HttpOnly can be read by any script on the page, so a single XSS steals the session.',
    fix: cookieFix(
      'Secure; HttpOnly; SameSite=Lax',
      EXPRESS_SESSION,
      'server.servlet.session.cookie.http-only=true',
    ),
    falsePositives:
      'CSRF tokens meant to be read by JavaScript (XSRF-TOKEN, csrftoken) are excluded by the option httpOnlyExceptions; add your own names there.',
  },
);

export const sameSiteNone = cookieRule(
  'cookie.samesite-none',
  (c, ctx) =>
    c.sameSite?.toLowerCase() === 'none' && isSession(c, ctx)
      ? {
          message: `Session cookie ${c.name} has SameSite=None and is sent with cross-site requests.`,
        }
      : null,
  {
    why: 'SameSite=None sends the session with requests started by other sites, which re-enables CSRF and cross-site leaks.',
    fix: cookieFix(
      'Secure; HttpOnly; SameSite=Lax',
      EXPRESS_SESSION,
      'server.servlet.session.cookie.same-site=lax',
    ),
    falsePositives:
      'Apps embedded in third-party sites (SSO, widgets) need SameSite=None: accept with a note.',
  },
);

export const sameSiteMissing = cookieRule(
  'cookie.samesite-missing',
  (c) =>
    c.sameSite === undefined ? { message: `Cookie ${c.name} has no SameSite attribute.` } : null,
  {
    why: 'Without SameSite the browser default applies (Lax in current browsers, None in old ones); being explicit avoids surprises.',
    fix: cookieFix(
      'Secure; HttpOnly; SameSite=Lax',
      EXPRESS_SESSION,
      'server.servlet.session.cookie.same-site=lax',
    ),
    falsePositives: 'Reported as info: current browsers treat a missing SameSite as Lax.',
  },
  true,
);

export const longLivedSession = cookieRule(
  'cookie.long-lived-session',
  (c, ctx) => {
    const days = typeof ctx.options.maxSessionDays === 'number' ? ctx.options.maxSessionDays : 30;
    if (c.lifetime === undefined || c.lifetime <= days * 86400 || !isSession(c, ctx)) return null;
    return {
      message: `Session cookie ${c.name} lives ${Math.round(c.lifetime / 86400)} days (limit ${days}).`,
    };
  },
  {
    why: 'A long-lived session stays valid on shared or stolen devices long after the user left.',
    fix: cookieFix(
      'Secure; HttpOnly; SameSite=Lax; Max-Age=86400',
      "{ secure: true, httpOnly: true, sameSite: 'lax', maxAge: 86_400_000 }",
      'server.servlet.session.timeout=30m',
    ),
    falsePositives:
      '"Remember me" cookies are long-lived by design: accept them with a note. The limit is the option maxSessionDays.',
  },
  true,
);

export const nonSessionInsecure = cookieRule(
  'cookie.non-session-insecure',
  (c, ctx) =>
    c.https && !c.secure && !isSession(c, ctx)
      ? { message: `Cookie ${c.name} is set over HTTPS without Secure.` }
      : null,
  {
    why: 'Cookies without Secure also travel over plain HTTP; even non-session cookies can carry preferences or tracking data.',
    fix: cookieFix(
      'Secure; SameSite=Lax',
      "{ secure: true, sameSite: 'lax' }",
      'cookie.setSecure(true)',
    ),
    falsePositives: 'Reported as info.',
  },
);

export const broadDomain = cookieRule(
  'cookie.broad-domain',
  (c, ctx) =>
    c.domainAttribute !== undefined && isSession(c, ctx)
      ? {
          message: `Session cookie ${c.name} has Domain=${c.domainAttribute} and is sent to every subdomain.`,
        }
      : null,
  {
    why: 'A cookie with a Domain attribute goes to every subdomain of that domain: any subdomain that is compromised, taken over or hosts user content can read or overwrite the session.',
    fix: [
      'Leave out the `Domain` attribute so the cookie stays on the host that set it (a host-only cookie), or use the `__Host-` name prefix, which forbids `Domain`.',
      '',
      '- nginx (as a proxy): `proxy_cookie_domain ~.* "";` removes the Domain attribute of upstream cookies',
      "- Express: no `domain` in `res.cookie('sid', value, { … })` or in the `cookie` options of `express-session`",
      '- Spring Boot: no `server.servlet.session.cookie.domain`; `cookie.setDomain(…)` not called',
    ].join('\n'),
    falsePositives:
      'Single sign-on across subdomains needs a shared cookie: accept it with a note when every subdomain is trusted.',
  },
  true,
);

export const COOKIE_RULES: readonly BuiltInRule[] = [
  noSecure,
  noHttpOnly,
  sameSiteNone,
  sameSiteMissing,
  longLivedSession,
  nonSessionInsecure,
];
