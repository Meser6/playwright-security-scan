// disclosure.* rules (06, chapter 4.6).
import { normalizeAssetUrl } from '../fingerprint/index.ts';
import type { RawFinding, ResponseRecord } from '../types/index.ts';
import { finding, header, isJson, manifestOf } from './types.ts';
import type { BuiltInRule, RuleContext } from './types.ts';

const isRecord = (input: unknown): input is ResponseRecord =>
  typeof input === 'object' && input !== null && 'status' in input;
const BODY_TYPES = ['document', 'xhr', 'fetch', 'api', 'other'];

function bodyMatch(
  ctx: RuleContext,
  m: ReturnType<typeof manifestOf>,
  r: ResponseRecord,
  patterns: readonly { name: string; re: RegExp }[],
  message: (name: string) => string,
  withDiscriminator: boolean,
): RawFinding[] {
  if (r.body === undefined) return [];
  for (const p of patterns) {
    const match = p.re.exec(r.body.text);
    if (match === null) continue;
    return [
      finding(ctx, m, {
        subject: r.endpointKey,
        ...(withDiscriminator ? { discriminator: p.name } : {}),
        location: { origin: r.origin, endpointKey: r.endpointKey },
        evidence: [
          { kind: 'body', snippet: ctx.redact.snippet(r.body.text, match.index, match[0].length) },
        ],
        message: message(p.name),
      }),
    ];
  }
  return [];
}

const ERRORS_FIX = (what: string, express: string, spring: string): string =>
  [
    what,
    '',
    '- nginx: `proxy_intercept_errors on;` with generic `error_page 500 502 503 504 /50x.html;`',
    `- Express: ${express}`,
    `- Spring Boot: ${spring}`,
  ].join('\n');

const STACK = manifestOf('disclosure.stack-trace');
const STACK_PATTERNS = [
  { name: 'java', re: /\bat [a-z][\w$]*\.[\w.$]+\([\w$]+\.java:\d+\)/ },
  { name: 'dotnet', re: /\bat [\w.`<>]+(?:\([^)]*\))? in .+:line \d+/ },
  { name: 'python', re: /Traceback \(most recent call last\)/ },
  { name: 'php', re: /(?:Fatal error|Warning): .+ on line \d+/ },
  { name: 'node', re: /\bat .+ \((?:\/|[A-Za-z]:\\).+node_modules[\\/].+:\d+:\d+\)/ },
  { name: 'ruby', re: /\.rb:\d+:in `/ },
];
export const stackTrace: BuiltInRule = {
  id: STACK.id,
  manifest: STACK,
  appliesTo: { resourceTypes: BODY_TYPES },
  needsBody: BODY_TYPES,
  check(input, ctx) {
    if (!isRecord(input)) return [];
    return bodyMatch(
      ctx,
      STACK,
      input,
      STACK_PATTERNS,
      (n) => `${input.endpointKey} returns a ${n} stack trace.`,
      true,
    );
  },
  docs: {
    title: STACK.title,
    why: 'Stack traces show file paths, library versions and code structure, which helps an attacker pick an exploit; they also signal unhandled errors.',
    fix: ERRORS_FIX(
      'Return a generic error body to clients and log the details on the server.',
      "an error handler `app.use((err, req, res, next) => { log(err); res.status(500).json({ error: 'Internal error' }); })` and `NODE_ENV=production`",
      '`server.error.include-stacktrace=never`',
    ),
    falsePositives:
      'Developer documentation pages that show sample traces: accept them as false-positive.',
  },
};

const SQL = manifestOf('disclosure.sql-error');
const SQL_PATTERNS = [
  /SQLSTATE\[/,
  /\bORA-\d{5}\b/,
  /You have an error in your SQL syntax/,
  /syntax error at or near/,
  /unterminated quoted string/i,
  /\bSqlException\b/,
  /\bSQLITE_ERROR\b/,
].map((re) => ({ name: 'sql', re }));
export const sqlError: BuiltInRule = {
  id: SQL.id,
  manifest: SQL,
  appliesTo: { resourceTypes: BODY_TYPES },
  needsBody: BODY_TYPES,
  check(input, ctx) {
    if (!isRecord(input)) return [];
    return bodyMatch(
      ctx,
      SQL,
      input,
      SQL_PATTERNS,
      () => `${input.endpointKey} returns a database error message.`,
      false,
    );
  },
  docs: {
    title: SQL.title,
    why: 'A database error in a response shows that input reached a query unescaped (a likely SQL injection) and leaks the schema.',
    fix: ERRORS_FIX(
      'Use parameterized queries everywhere and return generic errors.',
      "parameterized queries (`db.query('SELECT … WHERE id = $1', [id])`) and a generic error handler",
      'Spring Data / `JdbcTemplate` with `?` parameters and `server.error.include-message=never`',
    ),
    falsePositives:
      'Pages that document SQL errors. Confirm SQL injection with an active test (stage E3).',
  },
};

const VERSION = manifestOf('disclosure.server-version');
const VERSION_HEADERS = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
];
export const serverVersion: BuiltInRule = {
  id: VERSION.id,
  manifest: VERSION,
  appliesTo: {},
  check(input, ctx) {
    if (!isRecord(input)) return [];
    const out: RawFinding[] = [];
    for (const name of VERSION_HEADERS) {
      const value = header(input.responseHeaders, name);
      if (value === undefined || !/\d+\.\d+/.test(value)) continue;
      out.push(
        finding(ctx, VERSION, {
          subject: input.origin,
          discriminator: name,
          location: { origin: input.origin, endpointKey: input.endpointKey, header: name },
          evidence: [{ kind: 'header', name, snippet: ctx.redact.text(value) }],
          message: `${input.origin} discloses its software version in ${name}.`,
        }),
      );
    }
    return out;
  },
  docs: {
    title: VERSION.title,
    why: 'Exact versions let an attacker look up known vulnerabilities of the server or framework without probing.',
    fix: [
      'Hide versions in response headers.',
      '',
      '- nginx: `server_tokens off;` (and `more_clear_headers Server;` with headers-more)',
      "- Express: `app.disable('x-powered-by')` (or `helmet()`)",
      '- Spring Boot: `server.server-header=` (empty) and no `X-Application-Context`',
    ].join('\n'),
    falsePositives: 'None known; reported with low severity.',
  },
};

const DEBUG = manifestOf('disclosure.debug-mode');
const DEBUG_PATTERNS = [
  {
    name: 'werkzeug',
    re: /Werkzeug Debugger|The debugger caught an exception in your WSGI application/,
  },
  {
    name: 'django',
    re: /You're seeing this error because you have <code>DEBUG = True<\/code>|DEBUG = True/,
  },
  { name: 'laravel', re: /Whoops! There was an error\.|window\.ignite|ignition-/ },
  { name: 'symfony', re: /\bsf-toolbar\b|sfwdt[a-f0-9]{6}/ },
  { name: 'rails', re: /Action Controller: Exception caught/ },
];
export const debugMode: BuiltInRule = {
  id: DEBUG.id,
  manifest: DEBUG,
  appliesTo: { resourceTypes: BODY_TYPES },
  needsBody: BODY_TYPES,
  check(input, ctx) {
    if (!isRecord(input)) return [];
    return bodyMatch(
      ctx,
      DEBUG,
      input,
      DEBUG_PATTERNS,
      (n) => `${input.endpointKey} shows the ${n} debug page.`,
      true,
    );
  },
  docs: {
    title: DEBUG.title,
    why: 'Debug pages expose source code, settings and sometimes an interactive console (Werkzeug) that runs code on the server.',
    fix: [
      'Turn debug mode off outside development.',
      '',
      '- nginx: nothing to configure; set the framework to production mode',
      '- Express: `NODE_ENV=production`; remove `errorhandler` in production',
      '- Spring Boot: no `spring-boot-devtools` in production, `server.error.include-stacktrace=never`',
    ].join('\n'),
    falsePositives:
      'Development environments scanned on purpose: scan the deployed environment instead.',
  },
};

const PRIVATE_IP = manifestOf('disclosure.private-ip');
const IP =
  /(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![\d.])/;
const isPrivateHost = (origin: string): boolean => {
  try {
    return IP.test(new URL(origin).hostname);
  } catch {
    return false;
  }
};
export const privateIp: BuiltInRule = {
  id: PRIVATE_IP.id,
  manifest: PRIVATE_IP,
  appliesTo: { resourceTypes: ['document', 'xhr', 'fetch', 'api', 'other'] },
  needsBody: ['document', 'xhr', 'fetch', 'api'],
  check(input, ctx) {
    if (!isRecord(input) || isPrivateHost(input.origin)) return [];
    for (const h of input.responseHeaders) {
      const m = IP.exec(h.value);
      if (m !== null) {
        return [
          finding(ctx, PRIVATE_IP, {
            subject: input.endpointKey,
            location: { origin: input.origin, endpointKey: input.endpointKey, header: h.name },
            evidence: [{ kind: 'header', name: h.name, snippet: ctx.redact.text(m[0]) }],
            message: `${input.endpointKey} discloses a private IP address in ${h.name}.`,
          }),
        ];
      }
    }
    if (input.body === undefined) return [];
    const m = IP.exec(input.body.text);
    if (m === null) return [];
    return [
      finding(ctx, PRIVATE_IP, {
        subject: input.endpointKey,
        location: { origin: input.origin, endpointKey: input.endpointKey },
        evidence: [
          { kind: 'body', snippet: ctx.redact.snippet(input.body.text, m.index, m[0].length) },
        ],
        message: `${input.endpointKey} discloses a private IP address.`,
      }),
    ];
  },
  docs: {
    title: PRIVATE_IP.title,
    why: 'Internal addresses map the network behind the application and help attacks such as SSRF.',
    fix: [
      'Remove internal addresses from responses and headers (load balancer, upstream and debug fields).',
      '',
      '- nginx: `proxy_hide_header X-Backend-Server;` and similar upstream headers',
      '- Express: do not return infrastructure fields; `app.set("trust proxy", …)` instead of echoing addresses',
      '- Spring Boot: exclude infrastructure fields from DTOs; `server.forward-headers-strategy=framework`',
    ].join('\n'),
    falsePositives:
      'Version strings that look like addresses, and apps served from a private address (skipped).',
  },
};

const LISTING = manifestOf('disclosure.directory-listing');
export const directoryListing: BuiltInRule = {
  id: LISTING.id,
  manifest: LISTING,
  appliesTo: { resourceTypes: BODY_TYPES },
  needsBody: BODY_TYPES,
  check(input, ctx) {
    if (!isRecord(input) || input.status < 200 || input.status >= 300) return [];
    return bodyMatch(
      ctx,
      LISTING,
      input,
      [{ name: 'listing', re: /<title>\s*Index of \/|Directory listing for /i }],
      () => `${input.endpointKey} shows a directory listing.`,
      false,
    );
  },
  docs: {
    title: LISTING.title,
    why: 'A directory listing exposes every file of a folder, including backups and files that were never linked.',
    fix: [
      'Turn directory listings off.',
      '',
      '- nginx: `autoindex off;`',
      '- Express: no `serve-index`; `express.static(dir, { index: false })` without a listing middleware',
      '- Spring Boot: no `ResourceHttpRequestHandler` listings; `spring.web.resources.add-mappings` only for public assets',
    ].join('\n'),
    falsePositives: 'Public download folders meant to be browsed: accept them with a note.',
  },
};

const SOURCE_MAP = manifestOf('disclosure.source-map');
export const sourceMap: BuiltInRule = {
  id: SOURCE_MAP.id,
  manifest: SOURCE_MAP,
  appliesTo: { resourceTypes: ['script'] },
  needsBody: ['script'],
  check(input, ctx) {
    if (!isRecord(input) || input.status < 200 || input.status >= 300) return [];
    const fromHeader =
      header(input.responseHeaders, 'sourcemap') ?? header(input.responseHeaders, 'x-sourcemap');
    const comment =
      input.body === undefined
        ? null
        : /\/\/[#@]\s*sourceMappingURL=(\S+)\s*$/m.exec(input.body.text);
    if (fromHeader === undefined && comment === null) return [];
    const subject = normalizeAssetUrl(input.url) ?? input.endpointKey;
    const target = fromHeader ?? comment?.[1] ?? '';
    return [
      finding(ctx, SOURCE_MAP, {
        subject,
        location: { origin: input.origin, endpointKey: input.endpointKey },
        evidence: [
          {
            kind: fromHeader === undefined ? 'body' : 'header',
            snippet: ctx.redact.text(
              `sourceMappingURL=${target.startsWith('data:') ? 'data:…' : target}`,
            ),
          },
        ],
        message: `${subject} references a source map.`,
      }),
    ];
  },
  docs: {
    title: SOURCE_MAP.title,
    why: 'Source maps publish the original source code, comments included; the package does not download the map (passive only).',
    fix: [
      'Do not deploy source maps to production, or serve them only to authenticated developers.',
      '',
      '- nginx: `location ~* \\.map$ { deny all; }`',
      '- Express: build without `devtool: "source-map"`, or `app.use(/\\.map$/, (req, res) => res.sendStatus(404))`',
      '- Spring Boot: exclude `*.map` from `spring.web.resources.static-locations`',
    ].join('\n'),
    falsePositives: 'Open-source frontends that publish their code anyway. Reported as info.',
  },
};

const SERVER_ERROR = manifestOf('disclosure.server-error');
export const serverError: BuiltInRule = {
  id: SERVER_ERROR.id,
  manifest: SERVER_ERROR,
  appliesTo: {},
  check(input, ctx) {
    if (!isRecord(input) || input.status < 500 || input.status > 599) return [];
    return [
      finding(ctx, SERVER_ERROR, {
        subject: input.endpointKey,
        discriminator: String(input.status),
        location: { origin: input.origin, endpointKey: input.endpointKey },
        evidence: [{ kind: 'event', name: 'status', snippet: String(input.status) }],
        message: `${input.endpointKey} answered ${input.status} during the tests.`,
      }),
    ];
  },
  docs: {
    title: SERVER_ERROR.title,
    why: 'Unhandled server errors often reveal fragile input handling; they are also functional bugs.',
    fix: ERRORS_FIX(
      'Handle the error case and return a 4xx for invalid input.',
      'validate input and return `res.status(400)` for bad requests',
      '`@ControllerAdvice` with `@ExceptionHandler` returning 4xx for client errors',
    ),
    falsePositives: 'Tests that provoke 5xx on purpose. Reported as info.',
  },
};

const INTERNAL = manifestOf('disclosure.internal-hostname');
/** Host names with an internal suffix; svc.cluster.local first, it also ends with .local. */
const INTERNAL_HOST =
  /(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+)(svc\.cluster\.local|internal|local|lan|corp|intranet)(?![\w-]|\.[a-z0-9])/g;
const INTERNAL_SUFFIXES = ['svc.cluster.local', 'internal', 'local', 'lan', 'corp', 'intranet'];
/** Object names of scripts: `config.internal` is a property, not a host (06, chapter 4.14). */
const JS_NAMES = new Set([
  'this',
  'window',
  'document',
  'self',
  'globalthis',
  'config',
  'options',
  'props',
  'state',
  'process',
  'module',
  'exports',
]);
const SCRIPT_OR_STYLE = /<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi;

function internalSuffix(host: string): string | undefined {
  const lower = host.toLowerCase();
  return INTERNAL_SUFFIXES.find((s) => lower === s || lower.endsWith(`.${s}`));
}

/** Internal host names in `text`, with their suffix. */
function findInternalHost(text: string): { index: number; length: number; suffix: string }[] {
  const out: { index: number; length: number; suffix: string }[] = [];
  for (const m of text.matchAll(INTERNAL_HOST)) {
    const first = (m[1] ?? '').split('.')[0] ?? '';
    if (JS_NAMES.has(first)) continue;
    out.push({ index: m.index, length: m[0].length, suffix: internalSuffix(m[0]) ?? m[2] ?? '' });
  }
  return out;
}

export const internalHostname: BuiltInRule = {
  id: INTERNAL.id,
  manifest: INTERNAL,
  appliesTo: { resourceTypes: ['document', 'xhr', 'fetch', 'api', 'other'] },
  needsBody: ['document', 'xhr', 'fetch', 'api'],
  check(input, ctx) {
    if (!isRecord(input)) return [];
    let host: string;
    try {
      host = new URL(input.origin).hostname;
    } catch {
      return [];
    }
    if (internalSuffix(host) !== undefined) return [];
    // Local development: still worth a look, but advisory (06, chapter 4.14).
    const confidence = ctx.localDev ? 'low' : ctx.confidence;
    const found = new Map<string, RawFinding>();
    const location = { origin: input.origin, endpointKey: input.endpointKey };
    for (const h of input.responseHeaders) {
      for (const hit of findInternalHost(h.value)) {
        if (found.has(hit.suffix)) continue;
        found.set(
          hit.suffix,
          finding(ctx, INTERNAL, {
            subject: input.endpointKey,
            discriminator: hit.suffix,
            confidence,
            location: { ...location, header: h.name },
            evidence: [
              {
                kind: 'header',
                name: h.name,
                snippet: ctx.redact.text(h.value.slice(hit.index, hit.index + hit.length)),
              },
            ],
            message: `${input.endpointKey} discloses an internal host name (.${hit.suffix}) in ${h.name}.`,
          }),
        );
      }
    }
    if (input.body !== undefined) {
      const text = /html/i.test(input.body.contentType)
        ? input.body.text.replace(SCRIPT_OR_STYLE, (m) => ' '.repeat(m.length))
        : input.body.text;
      for (const hit of findInternalHost(text)) {
        if (found.has(hit.suffix)) continue;
        found.set(
          hit.suffix,
          finding(ctx, INTERNAL, {
            subject: input.endpointKey,
            discriminator: hit.suffix,
            confidence,
            location,
            evidence: [{ kind: 'body', snippet: ctx.redact.snippet(text, hit.index, hit.length) }],
            message: `${input.endpointKey} discloses an internal host name (.${hit.suffix}).`,
          }),
        );
      }
    }
    return [...found.values()];
  },
  docs: {
    title: INTERNAL.title,
    why: 'Internal host names (Kubernetes services, corporate DNS, .internal zones) map the network behind the application and give targets for SSRF and lateral movement.',
    fix: [
      'Remove internal host names from responses and headers: upstream names, debug fields, absolute URLs built from internal addresses.',
      '',
      '- nginx: `proxy_hide_header X-Upstream;` (and similar), `proxy_redirect` to rewrite internal `Location` values',
      '- Express: build absolute URLs from the public host (`trust proxy`), never from the internal one',
      '- Spring Boot: `server.forward-headers-strategy=framework`; no infrastructure fields in DTOs',
    ].join('\n'),
    falsePositives:
      'API documentation and examples that mention internal names on purpose. Apps served from such a host are skipped; on localhost the confidence is low.',
  },
};

const VERBOSE = manifestOf('disclosure.verbose-error-json');
const ERROR_KEYS = new Set([
  'stack',
  'stacktrace',
  'stack_trace',
  'exception',
  'trace',
  'traceback',
]);

/** Error detail keys of a JSON value with a non-empty text or array (depth ≤ 10). */
function errorKeys(
  value: unknown,
  depth = 0,
  found = new Map<string, string>(),
): Map<string, string> {
  if (depth > 10 || value === null || typeof value !== 'object') return found;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 200)) errorKeys(item, depth + 1, found);
    return found;
  }
  for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
    const lower = key.toLowerCase();
    const filled = (typeof v === 'string' && v.trim() !== '') || (Array.isArray(v) && v.length > 0);
    if (ERROR_KEYS.has(lower) && filled && !found.has(lower)) found.set(lower, key);
    errorKeys(v, depth + 1, found);
  }
  return found;
}

export const verboseErrorJson: BuiltInRule = {
  id: VERBOSE.id,
  manifest: VERBOSE,
  appliesTo: { resourceTypes: ['xhr', 'fetch', 'api', 'document', 'other'] },
  needsBody: ['xhr', 'fetch', 'api', 'document'],
  check(input, ctx) {
    if (!isRecord(input) || input.status < 400 || input.status > 599) return [];
    if (input.body === undefined || !isJson(input.body.contentType)) return [];
    let parsed: unknown;
    try {
      parsed = JSON.parse(input.body.text);
    } catch {
      return [];
    }
    const text = input.body.text;
    return [...errorKeys(parsed)].map(([lower, key]) => {
      const at = text.indexOf(`"${key}"`);
      return finding(ctx, VERBOSE, {
        subject: input.endpointKey,
        discriminator: lower,
        location: { origin: input.origin, endpointKey: input.endpointKey },
        evidence: [
          {
            kind: 'body',
            snippet:
              at < 0
                ? `"${key}": …`
                : ctx.redact.text(text.slice(at, at + 120) + (text.length > at + 120 ? '…' : '')),
          },
        ],
        message: `The ${input.status} response of ${input.endpointKey} returns error details in the JSON key "${key}".`,
      });
    });
  },
  docs: {
    title: VERBOSE.title,
    why: 'Stack traces and exception details in API errors reveal frameworks, file paths, queries and internal logic, which helps attackers tune their input.',
    fix: ERRORS_FIX(
      'Return a generic error body (a message and a correlation id) and log the details on the server.',
      'an error handler that returns `{ error, requestId }` only, with `NODE_ENV=production`',
      '`server.error.include-stacktrace=never` and `server.error.include-exception=false`',
    ),
    falsePositives:
      'A key named `trace` or `exception` that carries something harmless (e.g. a trace id): accept it with a note.',
  },
};

export const DISCLOSURE_RULES: readonly BuiltInRule[] = [
  stackTrace,
  sqlError,
  serverVersion,
  debugMode,
  privateIp,
  directoryListing,
  sourceMap,
  serverError,
];
