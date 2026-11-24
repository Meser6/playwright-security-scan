// browser.* and asset.* rules (06, chapter 4.7).
import { normalizeAssetUrl } from '../fingerprint/index.ts';
import { canonicalOrigin } from '../normalize/index.ts';
import type { RawFinding, ResponseRecord } from '../types/index.ts';
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

export const BROWSER_RULES: readonly BuiltInRule[] = [
  cspViolation,
  sriMissing,
  openRedirectCandidate,
  reflectedParam,
];
