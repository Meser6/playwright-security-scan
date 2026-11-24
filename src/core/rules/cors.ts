// cors.* rules (06, chapter 4.3): responses to requests with an Origin header, and preflights.
import type { RuleManifest } from '../manifest/rules.ts';
import type { RawFinding, ResponseRecord } from '../types/index.ts';
import { isSessionCookie } from './cookies.ts';
import { finding, header, manifestOf } from './types.ts';
import type { BuiltInRule, RuleContext } from './types.ts';

interface Cors {
  origin: string | undefined;
  acao: string;
  credentials: boolean;
}

function corsOf(input: unknown): (Cors & { record: ResponseRecord }) | null {
  if (typeof input !== 'object' || input === null || !('status' in input)) return null;
  const r = input as ResponseRecord;
  const origin = header(r.requestHeaders, 'origin');
  if (origin === undefined && r.method !== 'OPTIONS') return null;
  const acao = header(r.responseHeaders, 'access-control-allow-origin');
  if (acao === undefined) return null;
  const acac = header(r.responseHeaders, 'access-control-allow-credentials');
  return {
    record: r,
    origin,
    acao: acao.trim(),
    credentials: acac?.trim().toLowerCase() === 'true',
  };
}

function corsFinding(
  ctx: RuleContext,
  m: RuleManifest,
  r: ResponseRecord,
  c: Cors,
  message: string,
): RawFinding {
  return finding(ctx, m, {
    subject: r.endpointKey,
    location: {
      origin: r.origin,
      endpointKey: r.endpointKey,
      header: 'access-control-allow-origin',
    },
    evidence: [
      {
        kind: 'header',
        name: 'access-control-allow-origin',
        snippet: `${c.acao}${c.credentials ? ' + access-control-allow-credentials: true' : ''}${c.origin === undefined ? '' : ` (request origin ${c.origin})`}`,
      },
    ],
    message,
  });
}

const CORS_FIX = [
  'Allow only the origins of your own frontends, from a fixed list, and send credentials only to them.',
  '',
  '- nginx: `map $http_origin $cors { "https://app.example.com" $http_origin; default ""; }` and `add_header Access-Control-Allow-Origin $cors;`',
  "- Express: `app.use(cors({ origin: ['https://app.example.com'], credentials: true }))`",
  '- Spring: `config.setAllowedOrigins(List.of("https://app.example.com")); config.setAllowCredentials(true);`',
].join('\n');

function corsRule(
  id: string,
  test: (c: Cors, r: ResponseRecord, ctx: RuleContext) => string | null,
  docs: Omit<BuiltInRule['docs'], 'title' | 'fix'>,
): BuiltInRule {
  const m = manifestOf(id);
  return {
    id,
    manifest: m,
    appliesTo: {},
    check(input, ctx) {
      const c = corsOf(input);
      if (c === null) return [];
      const message = test(c, c.record, ctx);
      return message === null ? [] : [corsFinding(ctx, m, c.record, c, message)];
    },
    docs: { title: m.title, fix: CORS_FIX, ...docs },
  };
}

export const wildcardCredentials = corsRule(
  'cors.wildcard-credentials',
  (c, r) =>
    c.acao === '*' && c.credentials
      ? `${r.endpointKey} allows any origin together with credentials.`
      : null,
  {
    why: 'Access-Control-Allow-Origin: * with credentials shows a CORS setup that trusts every site; browsers reject the pair, but the configuration usually reflects origins elsewhere.',
    falsePositives: 'None known.',
  },
);

export const reflectedOriginCredentials = corsRule(
  'cors.reflected-origin-credentials',
  (c, r, ctx) =>
    c.origin !== undefined && c.acao === c.origin && c.credentials && !ctx.inScope(c.origin)
      ? `${r.endpointKey} echoes the foreign origin ${c.origin} and allows credentials.`
      : null,
  {
    why: 'A server that echoes any Origin with credentials lets every website read the responses of a logged-in user (account data, CSRF tokens).',
    falsePositives:
      'Partner frontends on other origins that are allowed on purpose: add them to scope.origins or accept the finding. Passively only origins the tests used are seen; confidence is medium.',
  },
);

export const nullOrigin = corsRule(
  'cors.null-origin',
  (c, r) => (c.acao === 'null' ? `${r.endpointKey} allows the null origin.` : null),
  {
    why: 'The null origin is used by sandboxed iframes, data: URLs and local files, which any attacker can create; allowing it is as open as a wildcard.',
    falsePositives: 'None known.',
  },
);

export const wildcardSensitive = corsRule(
  'cors.wildcard-sensitive',
  (c, r, ctx) => {
    if (c.acao !== '*') return null;
    const auth = header(r.requestHeaders, 'authorization') !== undefined;
    const pattern =
      typeof ctx.options.sessionNamePattern === 'string'
        ? ctx.options.sessionNamePattern
        : 'sess|sid';
    const cookie = (header(r.requestHeaders, 'cookie') ?? '').split(';').some((pair) => {
      const [name = '', value = ''] = pair.trim().split('=');
      return name !== '' && isSessionCookie(name, value, pattern);
    });
    return auth || cookie
      ? `${r.endpointKey} allows any origin although the request carried credentials.`
      : null;
  },
  {
    why: 'An authenticated endpoint readable from any origin may expose user data if the credentials are also sent automatically or are guessable.',
    falsePositives:
      'Public APIs that authenticate with an API key on purpose. Reported with low confidence.',
  },
);

export const CORS_RULES: readonly BuiltInRule[] = [
  wildcardCredentials,
  reflectedOriginCredentials,
  nullOrigin,
  wildcardSensitive,
];
