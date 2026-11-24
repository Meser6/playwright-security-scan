// transport.* rules (06, chapter 4.4).
import { normalizeAssetUrl } from '../fingerprint/index.ts';
import { canonicalOrigin } from '../normalize/index.ts';
import type { RawFinding, ResponseRecord } from '../types/index.ts';
import { finding, header, manifestOf, transportConfidence } from './types.ts';
import type { BuiltInRule } from './types.ts';

const isRecord = (input: unknown): input is ResponseRecord =>
  typeof input === 'object' && input !== null && 'status' in input;
const isHtmlDoc = (r: ResponseRecord): boolean =>
  r.resourceType === 'document' &&
  r.status >= 200 &&
  r.status < 300 &&
  /html/i.test(header(r.responseHeaders, 'content-type') ?? 'text/html');

const TLS_FIX = [
  'Serve the application only over HTTPS and redirect HTTP to HTTPS.',
  '',
  '- nginx: `server { listen 80; return 301 https://$host$request_uri; }`',
  "- Express: behind a proxy, `app.use((req, res, next) => req.secure ? next() : res.redirect(301, 'https://' + req.headers.host + req.url))`",
  '- Spring Security: `http.requiresChannel(c -> c.anyRequest().requiresSecure())`',
].join('\n');

const CLEARTEXT = manifestOf('transport.cleartext');
export const cleartext: BuiltInRule = {
  id: CLEARTEXT.id,
  manifest: CLEARTEXT,
  appliesTo: {},
  check(input, ctx) {
    if (!isRecord(input) || !input.url.startsWith('http:')) return [];
    return [
      finding(ctx, CLEARTEXT, {
        subject: input.origin,
        confidence: transportConfidence(ctx),
        location: { origin: input.origin, endpointKey: input.endpointKey },
        evidence: [{ kind: 'url', snippet: ctx.redact.text(`${input.method} ${input.origin}`) }],
        message: `${input.origin} is served over plain HTTP.`,
      }),
    ];
  },
  docs: {
    title: CLEARTEXT.title,
    why: 'Plain HTTP can be read and changed by anyone on the network: sessions, passwords and personal data are exposed.',
    fix: TLS_FIX,
    falsePositives: 'Local development (localhost) is reported with low confidence.',
  },
};

const MIXED = manifestOf('transport.mixed-content');
const MIXED_TAG =
  /<(script|img|iframe|link|audio|video|source|embed|object)\b[^>]*?\s(?:src|href|data)\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;

export const mixedContent: BuiltInRule = {
  id: MIXED.id,
  manifest: MIXED,
  appliesTo: { outOfScope: true },
  needsBody: ['document'],
  check(input, ctx) {
    if (!isRecord(input)) return [];
    const out: RawFinding[] = [];
    const report = (url: string, page: string, origin: string, evidence: string): void => {
      const subject = normalizeAssetUrl(url);
      if (subject === null) return;
      out.push(
        finding(ctx, MIXED, {
          subject,
          location: { origin },
          evidence: [{ kind: 'url', snippet: ctx.redact.text(evidence) }],
          message: `The HTTPS page ${page} loads ${subject} over HTTP.`,
        }),
      );
    };
    // A request for an http: resource made by an in-scope https document.
    if (
      input.url.startsWith('http:') &&
      input.resourceType !== 'document' &&
      input.frameUrl?.startsWith('https:') === true
    ) {
      const frameOrigin = canonicalOrigin(input.frameUrl);
      if (frameOrigin !== null && ctx.inScope(frameOrigin))
        report(input.url, frameOrigin, frameOrigin, `${input.resourceType} ${input.url}`);
    }
    // http: subresources in the HTML of an in-scope https document (blocked or upgraded requests).
    if (
      input.url.startsWith('https:') &&
      isHtmlDoc(input) &&
      ctx.inScope(input.origin) &&
      input.body !== undefined
    ) {
      for (const m of input.body.text.matchAll(MIXED_TAG)) {
        report(
          m[2] ?? '',
          input.endpointKey,
          input.origin,
          `<${(m[1] ?? '').toLowerCase()} … ${m[2] ?? ''}>`,
        );
      }
    }
    return out;
  },
  docs: {
    title: MIXED.title,
    why: 'An HTTP resource on an HTTPS page can be read or replaced on the network; a replaced script takes over the page.',
    fix: [
      'Load every resource over HTTPS (or with a relative URL) and add `upgrade-insecure-requests` to the CSP.',
      '',
      '- nginx: `add_header Content-Security-Policy "upgrade-insecure-requests" always;`',
      '- Express: `helmet.contentSecurityPolicy({ directives: { upgradeInsecureRequests: [] } })`',
      '- Spring Security: `http.headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives("upgrade-insecure-requests")))`',
    ].join('\n'),
    falsePositives: 'Links (<a href="http://…">) are not mixed content and are not reported.',
  },
};

const FORM = manifestOf('transport.form-to-http');
const FORM_ACTION = /<form\b[^>]*?\saction\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi;
export const formToHttp: BuiltInRule = {
  id: FORM.id,
  manifest: FORM,
  appliesTo: { resourceTypes: ['document'] },
  needsBody: ['document'],
  check(input, ctx) {
    if (
      !isRecord(input) ||
      !input.url.startsWith('https:') ||
      !isHtmlDoc(input) ||
      input.body === undefined
    )
      return [];
    const actions = [...input.body.text.matchAll(FORM_ACTION)].map((m) => m[1] ?? '');
    if (actions.length === 0) return [];
    return [
      finding(ctx, FORM, {
        subject: input.endpointKey,
        location: { origin: input.origin, endpointKey: input.endpointKey },
        evidence: actions.slice(0, 3).map((a) => ({
          kind: 'body' as const,
          snippet: ctx.redact.text(`<form action="${a}">`),
        })),
        message: `The HTTPS page ${input.endpointKey} has a form that submits over HTTP.`,
      }),
    ];
  },
  docs: {
    title: FORM.title,
    why: 'A form on an HTTPS page that posts to HTTP sends what the user typed (often passwords) in clear text.',
    fix: [
      "Use HTTPS (or a relative URL) in every form action and add `form-action 'self'` to the CSP.",
      '',
      '- nginx: `add_header Content-Security-Policy "form-action \'self\'" always;`',
      '- Express: `helmet.contentSecurityPolicy({ directives: { formAction: ["\'self\'"] } })`',
      '- Spring Security: `http.headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives("form-action \'self\'")))`',
    ].join('\n'),
    falsePositives: 'None known.',
  },
};

const WEAK_TLS = manifestOf('transport.weak-tls');
/** TLS 1.0/1.1 and SSL, in the spellings of all browsers (WP-02: "TLS 1.0", "TLSv1.1"). */
const WEAK = /^(?:ssl|tls ?v?1(?:\.[01])?)$/i;
export const weakTls: BuiltInRule = {
  id: WEAK_TLS.id,
  manifest: WEAK_TLS,
  appliesTo: { resourceTypes: ['document'] },
  check(input, ctx) {
    if (!isRecord(input)) return [];
    const protocol = input.tls?.protocol?.trim();
    if (protocol === undefined || !(WEAK.test(protocol) || /^ssl/i.test(protocol))) return [];
    return [
      finding(ctx, WEAK_TLS, {
        subject: input.origin,
        location: { origin: input.origin, endpointKey: input.endpointKey },
        evidence: [{ kind: 'event', name: 'tls', snippet: protocol }],
        message: `${input.origin} negotiated ${protocol}.`,
      }),
    ];
  },
  docs: {
    title: WEAK_TLS.title,
    why: 'TLS 1.0, TLS 1.1 and SSL have known weaknesses and are deprecated (RFC 8996).',
    fix: [
      'Allow only TLS 1.2 and TLS 1.3.',
      '',
      '- nginx: `ssl_protocols TLSv1.2 TLSv1.3;`',
      "- Express (Node https): `https.createServer({ minVersion: 'TLSv1.2', ... })`",
      '- Spring Boot: `server.ssl.enabled-protocols=TLSv1.2,TLSv1.3`',
    ].join('\n'),
    falsePositives: 'None known.',
  },
};

export const TRANSPORT_RULES: readonly BuiltInRule[] = [
  cleartext,
  mixedContent,
  formToHttp,
  weakTls,
];
