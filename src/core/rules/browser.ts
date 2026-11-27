// browser.* and asset.* rules (06, chapter 4.7).
import { normalizeAssetUrl } from '../fingerprint/index.ts';
import { canonicalOrigin } from '../normalize/index.ts';
import type { RawFinding, ResponseRecord } from '../types/index.ts';
import { sessionTest } from './cookies.ts';
import { finding, header, manifestOf } from './types.ts';
import type { BuiltInRule } from './types.ts';

const isRecord = (input: unknown): input is ResponseRecord =>
  typeof input === 'object' && input !== null && 'status' in input;
const isHtmlDoc = (r: ResponseRecord): boolean =>
  r.resourceType === 'document' &&
  r.status >= 200 &&
  r.status < 300 &&
  /html/i.test(header(r.responseHeaders, 'content-type') ?? 'text/html');

const CSP_VIOLATION = manifestOf('browser.csp-violation');
export const cspViolation: BuiltInRule = {
  id: CSP_VIOLATION.id,
  manifest: CSP_VIOLATION,
  appliesTo: { events: ['csp-violation'], sources: ['browser'] },
  check(input, ctx) {
    if (!('kind' in input) || input.kind !== 'csp-violation' || input.directive === '') return [];
    return [
      finding(ctx, CSP_VIOLATION, {
        subject: input.documentOrigin,
        discriminator: input.directive,
        location: { origin: input.documentOrigin },
        evidence: [
          {
            kind: 'event',
            name: input.directive,
            snippet: `${input.disposition}: ${input.directive} blocked ${ctx.redact.text(input.blockedOrigin)}`,
          },
        ],
        message: `The browser reported a CSP violation of ${input.directive} (${input.disposition === 'enforce' ? 'blocked' : 'report-only'}) on ${input.documentOrigin}.`,
      }),
    ];
  },
  docs: {
    title: CSP_VIOLATION.title,
    why: 'A violation means the page tried to load or run something the policy forbids: a broken feature, a policy to adjust, or an injection attempt.',
    fix: [
      'Find the blocked resource or inline script and either allow it explicitly (a nonce or hash, an origin in the right directive) or remove it.',
      '',
      '- nginx: adjust the `add_header Content-Security-Policy` value',
      '- Express: adjust the `helmet.contentSecurityPolicy` directives',
      '- Spring Security: adjust `contentSecurityPolicy(csp -> csp.policyDirectives(…))`',
    ].join('\n'),
    falsePositives:
      "Browser extensions and the browser's own requests can cause violations; /favicon.ico is ignored.",
  },
};

const SRI = manifestOf('asset.sri-missing');
const TAGS = /<(script|link)\b([^>]*)>/gi;
const attr = (attributes: string, name: string): string | undefined => {
  const m = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(
    attributes,
  );
  return m === null ? undefined : (m[1] ?? m[2] ?? m[3]);
};
export const sriMissing: BuiltInRule = {
  id: SRI.id,
  manifest: SRI,
  appliesTo: { resourceTypes: ['document'] },
  needsBody: ['document'],
  check(input, ctx) {
    if (!isRecord(input) || !isHtmlDoc(input) || input.body === undefined) return [];
    const out: RawFinding[] = [];
    const seen = new Set<string>();
    for (const m of input.body.text.matchAll(TAGS)) {
      const tag = (m[1] ?? '').toLowerCase();
      const attributes = m[2] ?? '';
      if (tag === 'link' && !/\brel\s*=\s*["']?stylesheet/i.test(attributes)) continue;
      const ref = attr(attributes, tag === 'script' ? 'src' : 'href');
      if (ref === undefined || attr(attributes, 'integrity') !== undefined) continue;
      let url: URL;
      try {
        url = new URL(ref, input.url);
      } catch {
        continue;
      }
      const origin = canonicalOrigin(url.href);
      if (origin === null || ctx.inScope(origin)) continue;
      const subject = normalizeAssetUrl(url.href);
      if (subject === null || seen.has(subject)) continue;
      seen.add(subject);
      out.push(
        finding(ctx, SRI, {
          subject,
          location: { origin: input.origin, endpointKey: input.endpointKey },
          evidence: [
            {
              kind: 'body',
              snippet: ctx.redact.text(
                `<${tag} ${tag === 'script' ? 'src' : 'href'}="${url.href}">`,
              ),
            },
          ],
          message: `${input.endpointKey} loads ${subject} from another origin without Subresource Integrity.`,
        }),
      );
    }
    return out;
  },
  docs: {
    title: SRI.title,
    why: 'A script or stylesheet from a third-party server runs with the rights of your page; if that server or CDN is compromised, so is your page.',
    fix: [
      'Add `integrity="sha384-…"` and `crossorigin="anonymous"` to third-party `<script>` and `<link rel="stylesheet">` tags, or host the files yourself.',
      '',
      '- nginx: serve third-party files from your own origin (`location /vendor/ { … }`)',
      '- Express: generate the tags with integrity hashes (e.g. `webpack-subresource-integrity`)',
      '- Spring: add `integrity` attributes in the templates (Thymeleaf `th:attr`)',
    ].join('\n'),
    falsePositives:
      'Scripts that change on every request (analytics loaders) cannot have SRI: accept them with a note.',
  },
};

const REDIRECT = manifestOf('browser.open-redirect-candidate');
export const openRedirectCandidate: BuiltInRule = {
  id: REDIRECT.id,
  manifest: REDIRECT,
  appliesTo: {},
  check(input, ctx) {
    if (!isRecord(input) || input.status < 300 || input.status > 399) return [];
    const location = header(input.responseHeaders, 'location');
    if (location === undefined) return [];
    let target: URL;
    let request: URL;
    try {
      request = new URL(input.url);
      target = new URL(location, input.url);
    } catch {
      return [];
    }
    if (!/^https?:\/\//i.test(location) && !location.startsWith('//')) return [];
    if (target.host === request.host) return [];
    const names = new Set(
      ((ctx.options.paramNames as string[] | undefined) ?? []).map((n) => n.toLowerCase()),
    );
    const same = (value: string): boolean => {
      try {
        return new URL(value, input.url).href === target.href;
      } catch {
        return false;
      }
    };
    const params = [...request.searchParams].filter(([, value]) => value !== '' && same(value));
    // A known redirect parameter first, else any parameter that equals the target.
    const hit = params.find(([name]) => names.has(name.toLowerCase())) ?? params[0];
    if (hit === undefined) return [];
    return [
      finding(ctx, REDIRECT, {
        subject: input.endpointKey,
        discriminator: hit[0],
        location: { origin: input.origin, endpointKey: input.endpointKey, param: hit[0] },
        evidence: [
          {
            kind: 'header',
            name: 'location',
            snippet: ctx.redact.text(`${input.status} → ${target.origin}${target.pathname}`),
          },
        ],
        message: `${input.endpointKey} redirects to another host taken from the parameter "${hit[0]}".`,
      }),
    ];
  },
  docs: {
    title: REDIRECT.title,
    why: 'A redirect that goes wherever a parameter says lets phishing links start on your trusted domain; confirmation needs an active test (stage E3).',
    fix: [
      'Redirect only to relative paths or to an allow-list of hosts.',
      '',
      '- nginx: do not build `return 302 $arg_next;` from parameters',
      "- Express: `const next = allowed.has(new URL(req.query.next, base).host) ? req.query.next : '/'`",
      '- Spring Security: `DefaultRedirectStrategy` with `setContextRelative(true)` or a validated target',
    ].join('\n'),
    falsePositives:
      'SSO flows that redirect to registered client URLs on purpose: accept them with a note.',
  },
};

const REFLECTED = manifestOf('browser.reflected-param');
const TRIVIAL = new Set(['true', 'false', 'null', 'undefined', 'none', 'asc', 'desc', 'default']);
export const reflectedParam: BuiltInRule = {
  id: REFLECTED.id,
  manifest: REFLECTED,
  appliesTo: { resourceTypes: ['document'] },
  needsBody: ['document'],
  check(input, ctx) {
    if (!isRecord(input) || !isHtmlDoc(input) || input.body === undefined) return [];
    let url: URL;
    try {
      url = new URL(input.url);
    } catch {
      return [];
    }
    const min = typeof ctx.options.minLength === 'number' ? ctx.options.minLength : 6;
    const out: RawFinding[] = [];
    for (const [name, value] of url.searchParams) {
      if (value.length < min || /^\d+$/.test(value) || TRIVIAL.has(value.toLowerCase())) continue;
      const index = input.body.text.indexOf(value);
      if (index < 0 || out.some((f) => f.discriminator === name)) continue;
      out.push(
        finding(ctx, REFLECTED, {
          subject: input.endpointKey,
          discriminator: name,
          location: { origin: input.origin, endpointKey: input.endpointKey, param: name },
          evidence: [
            {
              kind: 'body',
              name,
              snippet: ctx.redact.snippet(input.body.text, index, value.length),
            },
          ],
          message: `The value of the parameter "${name}" appears unencoded in the HTML of ${input.endpointKey}.`,
        }),
      );
    }
    return out;
  },
  docs: {
    title: REFLECTED.title,
    why: 'A reflected parameter is where reflected XSS starts; it is only a candidate until an active test (stage E3) confirms it, so it never blocks.',
    fix: [
      'Encode every reflected value for its HTML context (templates with auto-escaping) and keep a strict CSP.',
      '',
      '- nginx: nothing to configure; add a CSP (`add_header Content-Security-Policy "script-src \'self\'"`)',
      '- Express: render with an auto-escaping template engine; never concatenate `req.query` into HTML',
      '- Spring: Thymeleaf `th:text` (escaped), not `th:utext`',
    ].join('\n'),
    falsePositives:
      'Safe reflections such as search terms shown escaped (letters and digits look the same encoded). Reported as info with low confidence.',
  },
};

const CSRF = manifestOf('browser.csrf-missing');
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
export const csrfMissing: BuiltInRule = {
  id: CSRF.id,
  manifest: CSRF,
  appliesTo: { testEnd: true, sources: ['browser'] },
  check(input, ctx) {
    if (input.kind !== 'test-end') return [];
    const isSession = sessionTest(ctx);
    // SameSite of the session cookies set in this test (06, chapter 4.14): only these are judged.
    const weak = new Map<string, string>();
    for (const r of input.requests) {
      for (const c of r.setCookies) {
        if (!isSession(c)) continue;
        if (c.sameSite === undefined || c.sameSite === 'None') {
          weak.set(c.name, c.sameSite === undefined ? 'no SameSite' : 'SameSite=None');
        } else {
          weak.delete(c.name);
        }
      }
    }
    if (weak.size === 0) return [];
    const out: RawFinding[] = [];
    const seen = new Set<string>();
    for (const r of [...input.requests].sort((a, b) => a.id - b.id)) {
      if (!STATE_CHANGING.has(r.method) || r.csrfSignal || seen.has(r.endpointKey)) continue;
      if (r.contentType === 'application/json' || (r.contentType ?? '').endsWith('+json')) continue;
      const cookie = r.sentCookies.find((c) => weak.has(c.name) && isSession(c));
      if (cookie === undefined) continue;
      seen.add(r.endpointKey);
      out.push(
        finding(ctx, CSRF, {
          subject: r.endpointKey,
          location: { origin: r.origin, endpointKey: r.endpointKey },
          evidence: [
            {
              kind: 'cookie',
              name: cookie.name,
              snippet: `${r.method} with ${cookie.name} (${weak.get(cookie.name) ?? ''}), content-type ${r.contentType ?? 'none'}, no CSRF token or header`,
            },
          ],
          message: `${r.endpointKey} changes state with the session cookie ${cookie.name} (${weak.get(cookie.name) ?? ''}) and no CSRF token.`,
        }),
      );
    }
    return out;
  },
  docs: {
    title: CSRF.title,
    why: 'A cookie without SameSite=Lax/Strict goes along with requests from other sites: without a CSRF token, any page the user visits can submit this request in their name (cross-site request forgery).',
    fix: [
      'Set the session cookie with `SameSite=Lax` (or `Strict`) and protect state-changing requests with a CSRF token (synchronizer or double-submit) or a custom header that cross-site forms cannot send.',
      '',
      '- nginx (as a proxy): `proxy_cookie_flags ~ samesite=lax;`',
      "- Express: `csurf`-style middleware (e.g. `csrf-csrf`) and `cookie: { sameSite: 'lax' }` in express-session",
      '- Spring Security: CSRF protection on (the default) with `CookieCsrfTokenRepository` for SPAs',
    ].join('\n'),
    falsePositives:
      'Servers that check the Origin or Referer header, which is invisible to a passive scan. Reported with low confidence and never blocks by default. Cookies not set during the test (e.g. from storageState) are not judged.',
  },
};

const THIRD_PARTY = manifestOf('asset.unexpected-third-party');

/** Whether `origin` matches an allowed origin or a `https://*.example.com` pattern (06, 4.14). */
export function originAllowed(origin: string, allowed: readonly string[]): boolean {
  for (const entry of allowed) {
    const star = /^([a-z][a-z0-9+.-]*:\/\/)\*\.(.+)$/i.exec(entry.trim());
    if (star !== null) {
      const scheme = (star[1] ?? '').toLowerCase();
      const rest = (star[2] ?? '').toLowerCase();
      if (origin.startsWith(scheme) && origin.slice(scheme.length).endsWith(`.${rest}`))
        return true;
      continue;
    }
    if (canonicalOrigin(entry.trim()) === origin) return true;
  }
  return false;
}

export const unexpectedThirdParty: BuiltInRule = {
  id: THIRD_PARTY.id,
  manifest: THIRD_PARTY,
  appliesTo: { resourceTypes: ['script'], outOfScope: true },
  check(input, ctx) {
    if (input.kind !== 'response' || input.resourceType !== 'script') return [];
    if (ctx.inScope(input.origin) || input.frameUrl === undefined) return [];
    const page = canonicalOrigin(input.frameUrl);
    if (page === null || !ctx.inScope(page)) return [];
    const allowed = Array.isArray(ctx.options.allowedScriptOrigins)
      ? (ctx.options.allowedScriptOrigins as unknown[]).filter(
          (o): o is string => typeof o === 'string',
        )
      : [];
    if (originAllowed(input.origin, allowed)) return [];
    const asset = normalizeAssetUrl(input.url) ?? input.origin;
    return [
      finding(ctx, THIRD_PARTY, {
        subject: input.origin,
        // Without a list the rule is an inventory (06, chapter 4.13).
        ...(allowed.length === 0 ? { severity: 'info' as const } : {}),
        location: { origin: page },
        evidence: [{ kind: 'url', snippet: ctx.redact.text(asset) }],
        message:
          allowed.length === 0
            ? `${page} loads scripts from ${input.origin} (inventory: no allowedScriptOrigins set).`
            : `${page} loads scripts from ${input.origin}, which is not in allowedScriptOrigins.`,
      }),
    ];
  },
  docs: {
    title: THIRD_PARTY.title,
    why: 'Every script origin runs code with the full rights of your page; a new third-party origin is a new supplier that can read what users type. Keeping the list explicit makes new origins visible in review.',
    fix: [
      'List the expected script origins in the option `allowedScriptOrigins` (patterns like `https://*.example.com` allowed); remove or self-host scripts from origins you do not expect; restrict `script-src` in the CSP to the same list.',
      '',
      '- nginx: `add_header Content-Security-Policy "script-src \'self\' https://cdn.example.com"`',
      '- Express: `helmet.contentSecurityPolicy({ directives: { scriptSrc: ["\'self\'", "https://cdn.example.com"] } })`',
      '- Spring Security: `contentSecurityPolicy(csp -> csp.policyDirectives("script-src \'self\' https://cdn.example.com"))`',
    ].join('\n'),
    falsePositives:
      'A trusted CDN that is not on the list yet: add it to allowedScriptOrigins. Without the list the rule only keeps an inventory at severity info, and the baseline records the known origins.',
  },
};

const PASSWORD_GET = manifestOf('browser.password-form-get');
const FORM = /<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi;
const PASSWORD_INPUT = /<input\b[^>]*\btype\s*=\s*["']?password\b/i;
export const passwordFormGet: BuiltInRule = {
  id: PASSWORD_GET.id,
  manifest: PASSWORD_GET,
  appliesTo: { resourceTypes: ['document'] },
  needsBody: ['document'],
  check(input, ctx) {
    if (input.kind !== 'response' || !isHtmlDoc(input) || input.body === undefined) return [];
    for (const m of input.body.text.matchAll(FORM)) {
      const attributes = m[1] ?? '';
      if (!PASSWORD_INPUT.test(m[2] ?? '')) continue;
      const method = attr(attributes, 'method')?.trim().toLowerCase();
      const action = attr(attributes, 'action')?.trim();
      const realAction =
        action !== undefined && action !== '' && action !== '#' && !/^javascript:/i.test(action);
      if (!(method === 'get' || (method === undefined && realAction))) continue;
      const tag = `<form${method === undefined ? '' : ` method="${method}"`}${action === undefined ? '' : ` action="${action}"`}>`;
      return [
        finding(ctx, PASSWORD_GET, {
          subject: input.endpointKey,
          location: { origin: input.origin, endpointKey: input.endpointKey },
          evidence: [{ kind: 'body', snippet: ctx.redact.text(tag) }],
          message: `${input.endpointKey} has a password form that is sent with GET, so the password lands in the URL.`,
        }),
      ];
    }
    return [];
  },
  docs: {
    title: PASSWORD_GET.title,
    why: 'A form sent with GET puts its fields, the password included, into the URL: browser history, server and proxy logs and the Referer header of the next page keep it.',
    fix: [
      'Use `<form method="post">` for every form with a password field (or send it from script with a POST body).',
      '',
      '- nginx: nothing to configure; fix the form (and do not log query strings of the login path meanwhile)',
      '- Express: render the form with `method="post"` and handle it in `app.post(...)`',
      '- Spring: `th:method="post"` in the template and `@PostMapping` for the login handler (Spring Security login is POST only)',
    ].join('\n'),
    falsePositives:
      'Forms without method and action are skipped (single-page apps submit them from script); a form whose submit is always intercepted by script but has a GET action: fix the markup or accept it with a note.',
  },
};

export const BROWSER_RULES: readonly BuiltInRule[] = [
  cspViolation,
  sriMissing,
  openRedirectCandidate,
  reflectedParam,
];
