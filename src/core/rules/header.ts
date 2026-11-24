// header.* rules (06, chapter 4.1).
import type { RuleManifest } from '../manifest/rules.ts';
import type { RawFinding, ResponseRecord } from '../types/index.ts';
import { metaCsp, policies, scriptSources, unsafeScriptTokens } from './csp.ts';
import { headerFix } from './fix-snippets.ts';
import { finding, header, headers, isJson, manifestOf, transportConfidence } from './types.ts';
import type { BuiltInRule, RuleContext } from './types.ts';

const is2xx = (r: ResponseRecord): boolean => r.status >= 200 && r.status < 300;
export const isRecord = (input: unknown): input is ResponseRecord =>
  typeof input === 'object' && input !== null && 'status' in input;

/** A 2xx HTML document (06, chapter 4: "doc"). */
export function isDocument(input: unknown): input is ResponseRecord {
  if (!isRecord(input) || input.resourceType !== 'document' || !is2xx(input)) return false;
  const type = header(input.responseHeaders, 'content-type');
  return type === undefined || /html/i.test(type);
}

const DOC_TYPES = ['document'];

function originFinding(
  ctx: RuleContext,
  m: RuleManifest,
  r: ResponseRecord,
  name: string,
  snippet: string,
  message: string,
  extra: Partial<RawFinding> = {},
): RawFinding {
  return finding(ctx, m, {
    subject: r.origin,
    location: { origin: r.origin, endpointKey: r.endpointKey, header: name },
    evidence: [{ kind: 'header', name, snippet }],
    message,
    ...extra,
  });
}

/** Enforced CSP of a document: headers, else <meta> in the body. */
function enforcedCsp(r: ResponseRecord): string[] {
  const fromHeaders = headers(r.responseHeaders, 'content-security-policy');
  return fromHeaders.length > 0 ? fromHeaders : metaCsp(r.body?.text);
}

const CSP_MISSING = manifestOf('header.csp-missing');
export const cspMissing: BuiltInRule = {
  id: CSP_MISSING.id,
  manifest: CSP_MISSING,
  appliesTo: { resourceTypes: DOC_TYPES },
  needsBody: DOC_TYPES,
  check(input, ctx) {
    if (!isDocument(input)) return [];
    if (enforcedCsp(input).length > 0) return [];
    // Report-only alone is header.csp-report-only.
    if (headers(input.responseHeaders, 'content-security-policy-report-only').length > 0) return [];
    return [
      originFinding(
        ctx,
        CSP_MISSING,
        input,
        'content-security-policy',
        '(missing)',
        `${input.endpointKey} has no Content-Security-Policy.`,
      ),
    ];
  },
  docs: {
    title: CSP_MISSING.title,
    why: 'Without a Content-Security-Policy any injected script runs: one XSS bug gives full control of the page and the session.',
    fix: headerFix(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      `http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; object-src 'none'")))`,
    ),
    falsePositives:
      'Pages that only redirect or download files. Start with Content-Security-Policy-Report-Only if the policy may break the page.',
  },
};

const CSP_UNSAFE = manifestOf('header.csp-unsafe');
export const cspUnsafe: BuiltInRule = {
  id: CSP_UNSAFE.id,
  manifest: CSP_UNSAFE,
  appliesTo: { resourceTypes: DOC_TYPES },
  needsBody: DOC_TYPES,
  check(input, ctx) {
    if (!isDocument(input)) return [];
    const list = policies(enforcedCsp(input)).filter((p) => scriptSources(p) !== undefined);
    if (list.length === 0) return [];
    // A token is a problem only when every policy that governs scripts allows it.
    const perPolicy = list.map(unsafeScriptTokens);
    const tokens = (perPolicy[0] ?? []).filter((t) => perPolicy.every((p) => p.includes(t)));
    return tokens.map((token) =>
      originFinding(
        ctx,
        CSP_UNSAFE,
        input,
        'content-security-policy',
        `script-src … ${token}`,
        `The Content-Security-Policy of ${input.endpointKey} allows ${token} for scripts.`,
        { discriminator: token.replace(/'/g, '') },
      ),
    );
  },
  docs: {
    title: CSP_UNSAFE.title,
    why: "'unsafe-inline', 'unsafe-eval', wildcards and whole schemes in script-src let injected scripts run, so the policy no longer stops XSS.",
    fix: headerFix(
      'Content-Security-Policy',
      "script-src 'self' 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'self'",
      `http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("script-src 'self' 'nonce-{nonce}'")))`,
    ),
    falsePositives:
      "Legacy apps with inline handlers may need 'unsafe-inline' for a while: accept with an expiry date (until) and a ticket.",
  },
};

const CSP_DIRECTIVES = manifestOf('header.csp-missing-directives');
export const cspMissingDirectives: BuiltInRule = {
  id: CSP_DIRECTIVES.id,
  manifest: CSP_DIRECTIVES,
  appliesTo: { resourceTypes: DOC_TYPES },
  needsBody: DOC_TYPES,
  check(input, ctx) {
    if (!isDocument(input)) return [];
    const list = policies(enforcedCsp(input));
    if (list.length === 0) return [];
    const out: RawFinding[] = [];
    const objectRestricted = list.some((p) => {
      const def = p.get('default-src');
      return p.has('object-src') || (def?.length === 1 && def[0] === "'none'");
    });
    if (!objectRestricted) {
      out.push(
        originFinding(
          ctx,
          CSP_DIRECTIVES,
          input,
          'content-security-policy',
          'object-src (missing)',
          `The Content-Security-Policy of ${input.endpointKey} has no object-src.`,
          { discriminator: 'object-src' },
        ),
      );
    }
    if (!list.some((p) => p.has('base-uri'))) {
      out.push(
        originFinding(
          ctx,
          CSP_DIRECTIVES,
          input,
          'content-security-policy',
          'base-uri (missing)',
          `The Content-Security-Policy of ${input.endpointKey} has no base-uri.`,
          { discriminator: 'base-uri' },
        ),
      );
    }
    return out;
  },
  docs: {
    title: CSP_DIRECTIVES.title,
    why: 'default-src does not cover base-uri, and plugins (object-src) can run code: without them an attacker can change the base URL of relative scripts or load a plugin.',
    fix: headerFix(
      'Content-Security-Policy',
      "…; object-src 'none'; base-uri 'self'",
      `http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("…; object-src 'none'; base-uri 'self'")))`,
    ),
    falsePositives: "None known; object-src is not needed when default-src is 'none'.",
  },
};

const CSP_RO = manifestOf('header.csp-report-only');
export const cspReportOnly: BuiltInRule = {
  id: CSP_RO.id,
  manifest: CSP_RO,
  appliesTo: { resourceTypes: DOC_TYPES },
  needsBody: DOC_TYPES,
  check(input, ctx) {
    if (!isDocument(input)) return [];
    if (enforcedCsp(input).length > 0) return [];
    const ro = header(input.responseHeaders, 'content-security-policy-report-only');
    if (ro === undefined) return [];
    return [
      originFinding(
        ctx,
        CSP_RO,
        input,
        'content-security-policy-report-only',
        ctx.redact.text(ro).slice(0, 120),
        `${input.endpointKey} has a report-only Content-Security-Policy and no enforced one.`,
      ),
    ];
  },
  docs: {
    title: CSP_RO.title,
    why: 'A report-only policy reports violations but blocks nothing; it is a step towards an enforced policy, not a protection.',
    fix: headerFix(
      'Content-Security-Policy',
      '<the report-only policy, once it reports no violations>',
      'http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("…")))  // without .reportOnly()',
    ),
    falsePositives: 'Expected while a new policy is being tuned: accept with an until date.',
  },
};

const CLICK = manifestOf('header.clickjacking');
export const clickjacking: BuiltInRule = {
  id: CLICK.id,
  manifest: CLICK,
  appliesTo: { resourceTypes: DOC_TYPES },
  check(input, ctx) {
    if (!isDocument(input)) return [];
    const csp = policies(headers(input.responseHeaders, 'content-security-policy'));
    if (csp.some((p) => p.has('frame-ancestors'))) return [];
    const xfo = header(input.responseHeaders, 'x-frame-options')?.trim().toUpperCase();
    if (xfo === 'DENY' || xfo === 'SAMEORIGIN') return [];
    return [
      originFinding(
        ctx,
        CLICK,
        input,
        'x-frame-options',
        xfo === undefined ? '(missing)' : ctx.redact.text(xfo),
        `${input.endpointKey} can be framed by any site (no frame-ancestors, no X-Frame-Options).`,
      ),
    ];
  },
  docs: {
    title: CLICK.title,
    why: 'A page that any site can put in an iframe can be overlaid with a decoy, so users click buttons they cannot see (clickjacking).',
    fix: headerFix(
      'Content-Security-Policy',
      "frame-ancestors 'none'",
      'http.headers(h -> h.frameOptions(f -> f.deny()))',
    ),
    falsePositives:
      'Pages meant to be embedded by partners (widgets): allow those origins in frame-ancestors, or accept the finding in the baseline.',
  },
};

const HSTS_MISSING = manifestOf('header.hsts-missing');
const hstsApplies = (r: ResponseRecord): boolean =>
  r.url.startsWith('https:') &&
  is2xx(r) &&
  (r.resourceType === 'document' ||
    (r.source === 'api' && isJson(header(r.responseHeaders, 'content-type'))));

export const hstsMissing: BuiltInRule = {
  id: HSTS_MISSING.id,
  manifest: HSTS_MISSING,
  appliesTo: { resourceTypes: ['document', 'api'] },
  check(input, ctx) {
    if (!isRecord(input) || !hstsApplies(input)) return [];
    if (header(input.responseHeaders, 'strict-transport-security') !== undefined) return [];
    return [
      originFinding(
        ctx,
        HSTS_MISSING,
        input,
        'strict-transport-security',
        '(missing)',
        `${input.origin} does not send Strict-Transport-Security.`,
        // HSTS concerns browsers; API responses and local origins are advisory (15, 05-REQ-06).
        { confidence: input.source === 'api' ? 'low' : transportConfidence(ctx) },
      ),
    ];
  },
  docs: {
    title: HSTS_MISSING.title,
    why: 'Without HSTS the first request of a visit can go over plain HTTP, where an attacker on the network can downgrade the connection and steal the session.',
    fix: headerFix(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains',
      'http.headers(h -> h.httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000).includeSubDomains(true)))',
    ),
    falsePositives:
      'Local and test environments without a real certificate; accept them or scan the deployed environment.',
  },
};

const HSTS_WEAK = manifestOf('header.hsts-weak');
export const hstsWeak: BuiltInRule = {
  id: HSTS_WEAK.id,
  manifest: HSTS_WEAK,
  appliesTo: { resourceTypes: ['document', 'api'] },
  check(input, ctx) {
    if (!isRecord(input) || !hstsApplies(input)) return [];
    const value = header(input.responseHeaders, 'strict-transport-security');
    if (value === undefined) return [];
    const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(value);
    const min = typeof ctx.options.minMaxAge === 'number' ? ctx.options.minMaxAge : 15_552_000;
    if (maxAge !== null && Number(maxAge[1]) >= min) return [];
    return [
      originFinding(
        ctx,
        HSTS_WEAK,
        input,
        'strict-transport-security',
        ctx.redact.text(value),
        `Strict-Transport-Security of ${input.origin} has max-age below ${min} seconds.`,
        { confidence: input.source === 'api' ? 'low' : transportConfidence(ctx) },
      ),
    ];
  },
  docs: {
    title: HSTS_WEAK.title,
    why: 'A short max-age lets the protection expire between visits, so the downgrade attack of a missing HSTS is possible again.',
    fix: headerFix(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains',
      'http.headers(h -> h.httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000)))',
    ),
    falsePositives:
      'A short max-age during an HSTS rollout: accept with an until date. The threshold is the option minMaxAge.',
  },
};

const XCTO = manifestOf('header.xcto-missing');
export const xctoMissing: BuiltInRule = {
  id: XCTO.id,
  manifest: XCTO,
  appliesTo: { resourceTypes: ['document', 'script', 'stylesheet', 'xhr', 'fetch', 'api'] },
  check(input, ctx) {
    if (!isRecord(input) || !is2xx(input)) return [];
    const type = header(input.responseHeaders, 'content-type');
    const relevant =
      ['document', 'script', 'stylesheet'].includes(input.resourceType) || isJson(type);
    if (!relevant) return [];
    const value = header(input.responseHeaders, 'x-content-type-options');
    if (value !== undefined && value.trim().toLowerCase() === 'nosniff') return [];
    return [
      originFinding(
        ctx,
        XCTO,
        input,
        'x-content-type-options',
        value === undefined ? '(missing)' : ctx.redact.text(value),
        `${input.endpointKey} (${input.resourceType}) has no "X-Content-Type-Options: nosniff".`,
      ),
    ];
  },
  docs: {
    title: XCTO.title,
    why: 'Without nosniff a browser may guess the type of a response and run text or JSON as a script or style (MIME sniffing), which helps XSS and data leaks.',
    fix: headerFix(
      'X-Content-Type-Options',
      'nosniff',
      'http.headers(h -> h.contentTypeOptions(withDefaults()))',
    ),
    falsePositives:
      'None known for HTML, scripts, styles and JSON. Accept it for legacy endpoints you cannot change.',
  },
};

const REFERRER = manifestOf('header.referrer-policy-unsafe');
export const referrerPolicyUnsafe: BuiltInRule = {
  id: REFERRER.id,
  manifest: REFERRER,
  appliesTo: { resourceTypes: DOC_TYPES },
  check(input, ctx) {
    if (!isDocument(input)) return [];
    const value = header(input.responseHeaders, 'referrer-policy');
    if (value === undefined) {
      // Browsers default to strict-origin-when-cross-origin (06, chapter 4.1).
      return [
        originFinding(
          ctx,
          REFERRER,
          input,
          'referrer-policy',
          '(missing)',
          `${input.endpointKey} has no Referrer-Policy; the browser default applies.`,
          { severity: 'info', discriminator: 'missing' },
        ),
      ];
    }
    // The last policy the browser knows wins.
    const effective =
      value
        .split(',')
        .map((v) => v.trim().toLowerCase())
        .filter(Boolean)
        .at(-1) ?? '';
    if (effective !== 'unsafe-url' && effective !== 'no-referrer-when-downgrade') return [];
    return [
      originFinding(
        ctx,
        REFERRER,
        input,
        'referrer-policy',
        effective,
        `Referrer-Policy ${effective} of ${input.endpointKey} sends full URLs (with query parameters) to other sites.`,
        { discriminator: effective },
      ),
    ];
  },
  docs: {
    title: REFERRER.title,
    why: 'unsafe-url and no-referrer-when-downgrade send the full URL, including tokens or personal data in the query, to every linked or embedded site.',
    fix: headerFix(
      'Referrer-Policy',
      'strict-origin-when-cross-origin',
      'http.headers(h -> h.referrerPolicy(r -> r.policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)))',
    ),
    falsePositives:
      'A missing header is reported as info only: current browsers use a safe default.',
  },
};

const CT = manifestOf('header.content-type-missing');
export const contentTypeMissing: BuiltInRule = {
  id: CT.id,
  manifest: CT,
  appliesTo: { resourceTypes: ['document', 'script', 'stylesheet', 'xhr', 'fetch', 'api'] },
  check(input, ctx) {
    if (!isRecord(input) || !is2xx(input) || input.status === 204) return [];
    if (header(input.responseHeaders, 'content-type') !== undefined) return [];
    const length = header(input.responseHeaders, 'content-length');
    const hasBody =
      (length !== undefined
        ? Number(length) > 0
        : header(input.responseHeaders, 'transfer-encoding') !== undefined) ||
      (input.body?.text.length ?? 0) > 0;
    if (!hasBody) return [];
    return [
      finding(ctx, CT, {
        subject: input.endpointKey,
        location: { origin: input.origin, endpointKey: input.endpointKey, header: 'content-type' },
        evidence: [{ kind: 'header', name: 'content-type', snippet: '(missing)' }],
        message: `${input.endpointKey} returns a body without Content-Type.`,
      }),
    ];
  },
  docs: {
    title: CT.title,
    why: 'Without Content-Type the browser guesses the type of the response, and a guessed HTML or script type can turn data into executable content.',
    fix: [
      'Send the right Content-Type (e.g. `application/json; charset=utf-8`) with every response that has a body.',
      '',
      '- nginx: `default_type application/octet-stream;` and correct `types` for static files',
      "- Express: `res.type('application/json')` or `res.json(...)` instead of `res.end(...)`",
      '- Spring: `@GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)`',
    ].join('\n'),
    falsePositives: 'Empty bodies are not reported. Binary downloads should still declare a type.',
  },
};

function docHeaderRule(
  id: string,
  name: string,
  display: string,
  value: string,
  spring: string,
  why: string,
): BuiltInRule {
  const m = manifestOf(id);
  return {
    id,
    manifest: m,
    appliesTo: { resourceTypes: DOC_TYPES },
    check(input, ctx) {
      if (!isDocument(input) || header(input.responseHeaders, name) !== undefined) return [];
      return [
        originFinding(ctx, m, input, name, '(missing)', `${input.endpointKey} has no ${display}.`),
      ];
    },
    docs: {
      title: m.title,
      why,
      fix: headerFix(display, value, spring),
      falsePositives:
        'Reported only in the strict preset; it hardens the page but its absence is not a vulnerability by itself.',
    },
  };
}

export const permissionsPolicyMissing = docHeaderRule(
  'header.permissions-policy-missing',
  'permissions-policy',
  'Permissions-Policy',
  'camera=(), microphone=(), geolocation=()',
  'http.headers(h -> h.permissionsPolicy(p -> p.policy("camera=(), microphone=()")))',
  'Permissions-Policy limits powerful browser features (camera, microphone, location) that injected or third-party code could otherwise use.',
);

export const coopMissing = docHeaderRule(
  'header.coop-missing',
  'cross-origin-opener-policy',
  'Cross-Origin-Opener-Policy',
  'same-origin',
  'http.headers(h -> h.crossOriginOpenerPolicy(c -> c.policy(SAME_ORIGIN)))',
  'Without Cross-Origin-Opener-Policy a page opened by another site keeps a reference to it (window.opener), which enables cross-window attacks and leaks.',
);

export const HEADER_RULES: readonly BuiltInRule[] = [
  cspMissing,
  cspUnsafe,
  cspMissingDirectives,
  cspReportOnly,
  clickjacking,
  hstsMissing,
  hstsWeak,
  xctoMissing,
  referrerPolicyUnsafe,
  contentTypeMissing,
  permissionsPolicyMissing,
  coopMissing,
];
