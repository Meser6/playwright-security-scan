// Reference test application (10, chapter 3; 10-REQ-02): a small shop on node:http/https with a
// secure mode and one switch per rule. Without switches it is configured by the book and must give
// no finding of severity low or above (NF-11, 10-REQ-04). Each switch turns on exactly the case of
// its rule (10-REQ-05). Three servers: the app (HTTPS, in scope), a partner site (HTTPS, another
// origin: CORS, third-party scripts, redirect targets) and a plain HTTP server (cleartext, mixed
// content). No dependencies.
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';

/** Rules the app can reproduce; `transport.weak-tls` cannot be (no TLS 1.0/1.1 in Node 22+ and browsers). */
export const APP_RULES = [
  'header.csp-missing',
  'header.csp-unsafe',
  'header.csp-missing-directives',
  'header.csp-report-only',
  'header.clickjacking',
  'header.hsts-missing',
  'header.hsts-weak',
  'header.xcto-missing',
  'header.referrer-policy-unsafe',
  'header.content-type-missing',
  'header.permissions-policy-missing',
  'header.coop-missing',
  'cookie.no-secure',
  'cookie.no-httponly',
  'cookie.samesite-none',
  'cookie.samesite-missing',
  'cookie.long-lived-session',
  'cookie.non-session-insecure',
  'cors.wildcard-credentials',
  'cors.reflected-origin-credentials',
  'cors.null-origin',
  'cors.wildcard-sensitive',
  'transport.cleartext',
  'transport.mixed-content',
  'transport.form-to-http',
  'data.token-in-url',
  'data.jwt-alg-none',
  'data.jwt-no-exp',
  'data.jwt-long-lived',
  'data.jwt-sensitive-claims',
  'data.password-in-response',
  'data.secret-in-asset',
  'data.token-in-storage',
  'disclosure.stack-trace',
  'disclosure.sql-error',
  'disclosure.server-version',
  'disclosure.debug-mode',
  'disclosure.private-ip',
  'disclosure.directory-listing',
  'disclosure.source-map',
  'disclosure.server-error',
  'browser.csp-violation',
  'asset.sri-missing',
  'browser.open-redirect-candidate',
  'browser.reflected-param',
] as const;

/**
 * Switches for the custom rules of test/projects/shop (16-AC-01). The app answers /api/* with an
 * x-request-id header, except /api/token; this switch drops it from /api/me too.
 */
export const CUSTOM_SWITCHES = ['custom.request-id-missing'] as const;

/** Rules that cannot be reproduced by the app, with the reason (06-AC-01 exceptions). */
export const NOT_REPRODUCIBLE: Record<string, string> = {
  'transport.weak-tls':
    'Node 22+ and current browsers refuse TLS 1.0/1.1; the rule is covered by unit tests on records.',
};

export type AppRule = (typeof APP_RULES)[number];

export interface Shop {
  /** The app over HTTPS: the scan scope. */
  url: string;
  /** The app over plain HTTP (transport.cleartext runs the tests against it). */
  httpUrl: string;
  /** The partner site: another origin, out of scope. */
  partnerUrl: string;
  close(): Promise<void>;
}

const b64 = (o: object): string => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (header: object, payload: object, signature = 'c2hvcC1zaWduYXR1cmUtdmFsdWU'): string =>
  `${b64(header)}.${b64(payload)}.${signature}`;
const NOW = 1_795_000_000;

/** Every secret the app can emit; no output file may contain any of them (S-07, 07-AC-03). */
export const SECRETS = {
  session: 'Sh0pSess10nV4lue9x7Kq2LmZ',
  theme: 'dark-theme-pref-77',
  awsKey: 'AKIAQ3EXAMPLESHOPKEY',
  passwordHash: '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
  urlToken: 'urlT0kenAbc123Def456Ghi',
  storageJwt: jwt(
    { alg: 'HS256', typ: 'JWT' },
    { sub: 'u1', iat: NOW, exp: NOW + 900 },
    'c3RvcmFnZS1zaWc',
  ),
  jwtNone: jwt({ alg: 'none', typ: 'JWT' }, { sub: 'u1', iat: NOW, exp: NOW + 900 }, ''),
  jwtNoExp: jwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1', iat: NOW }, 'bm9leHAtc2lnbmF0dXJl'),
  jwtLong: jwt(
    { alg: 'HS256', typ: 'JWT' },
    { sub: 'u1', iat: NOW, exp: NOW + 30 * 86400 },
    'bG9uZy1zaWduYXR1cmU',
  ),
  jwtClaims: jwt(
    { alg: 'HS256', typ: 'JWT' },
    { sub: 'u1', iat: NOW, exp: NOW + 900, password: 'hunter2-secret' },
    'Y2xhaW1zLXNpZ25hdHVyZQ',
  ),
  basicAuth: 'cGFydG5lcjpzM2NyM3RQYXNz',
};

const APP_JS = `document.documentElement.dataset.ready = '1';`;
const LIB_JS = `window.partnerLib = { version: 1 };`;
const LIB_SRI = `sha384-${createHash('sha384').update(LIB_JS).digest('base64')}`;
const CSS = `body { font-family: sans-serif; }`;

interface Ports {
  app: string;
  http: string;
  partner: string;
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** The request handler of the app for one set of switches. */
function appHandler(vulns: ReadonlySet<string>, ports: () => Ports, build: string) {
  // The bundle name carries a build hash, like a bundler output (07-AC-02).
  const bundle = `app.${createHash('sha256').update(build).digest('hex').slice(0, 8)}.js`;
  const on = (rule: AppRule): boolean => vulns.has(rule);

  const securityHeaders = (nonce: string): Record<string, string> => {
    const h: Record<string, string> = {};
    const partner = ports().partner;
    let csp = `default-src 'self'; script-src 'self' 'nonce-${nonce}' ${partner}; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`;
    if (on('header.csp-unsafe')) csp = csp.replace(`'nonce-${nonce}'`, `'unsafe-inline'`);
    if (on('header.csp-missing-directives'))
      csp = csp.replace(`; object-src 'none'; base-uri 'self'`, '');
    if (on('header.clickjacking')) csp = csp.replace(`; frame-ancestors 'none'`, '');
    if (on('transport.form-to-http'))
      csp = csp.replace(`form-action 'self'`, `form-action 'self' ${ports().http}`);
    if (on('transport.mixed-content'))
      csp = csp.replace(`img-src 'self'`, `img-src 'self' ${ports().http}`);
    if (on('header.csp-report-only')) h['content-security-policy-report-only'] = csp;
    else if (!on('header.csp-missing')) h['content-security-policy'] = csp;
    if (!on('header.clickjacking')) h['x-frame-options'] = 'DENY';
    h['referrer-policy'] = on('header.referrer-policy-unsafe')
      ? 'unsafe-url'
      : 'strict-origin-when-cross-origin';
    if (!on('header.permissions-policy-missing'))
      h['permissions-policy'] = 'camera=(), microphone=(), geolocation=()';
    if (!on('header.coop-missing')) h['cross-origin-opener-policy'] = 'same-origin';
    return h;
  };

  const common = (): Record<string, string> => {
    const h: Record<string, string> = {};
    if (!on('header.xcto-missing')) h['x-content-type-options'] = 'nosniff';
    // HSTS on every response of the app, as a well-configured server sends it.
    if (on('header.hsts-weak')) h['strict-transport-security'] = 'max-age=60';
    else if (!on('header.hsts-missing'))
      h['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
    if (on('disclosure.server-version')) {
      h.server = 'nginx/1.25.3';
      h['x-powered-by'] = 'PHP/8.2.12';
    }
    return h;
  };

  const send = (
    res: ServerResponse,
    status: number,
    type: string | null,
    body: string,
    headers: Record<string, string | string[]> = {},
  ): void => {
    const h: Record<string, string | string[]> = { ...common(), ...headers };
    if (type !== null) h['content-type'] = type;
    res.writeHead(status, h);
    res.end(body);
  };

  const json = (
    res: ServerResponse,
    status: number,
    value: unknown,
    headers: Record<string, string | string[]> = {},
  ): void =>
    send(
      res,
      status,
      on('header.content-type-missing') ? null : 'application/json',
      JSON.stringify(value),
      headers,
    );

  const page = (res: ServerResponse, title: string, body: string, status = 200): void => {
    const nonce = randomBytes(12).toString('base64');
    const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title><link rel="stylesheet" href="/static/app.5d41402a.css"></head><body>${body.replaceAll('{{nonce}}', nonce)}</body></html>`;
    send(res, status, 'text/html; charset=utf-8', html, securityHeaders(nonce));
  };

  const sessionCookie = (): string => {
    const parts = [`sid=${SECRETS.session}`, 'Path=/'];
    if (!on('cookie.no-secure')) parts.push('Secure');
    if (!on('cookie.no-httponly')) parts.push('HttpOnly');
    if (on('cookie.samesite-none')) parts.push('SameSite=None');
    else if (!on('cookie.samesite-missing')) parts.push('SameSite=Lax');
    if (on('cookie.long-lived-session')) parts.push('Max-Age=7776000');
    return parts.join('; ');
  };

  const cors = (req: IncomingMessage): Record<string, string> => {
    const origin = req.headers.origin;
    const h: Record<string, string> = {};
    if (on('cors.wildcard-credentials')) {
      h['access-control-allow-origin'] = '*';
      h['access-control-allow-credentials'] = 'true';
    } else if (on('cors.reflected-origin-credentials') && origin !== undefined) {
      h['access-control-allow-origin'] = origin;
      h['access-control-allow-credentials'] = 'true';
      h.vary = 'Origin';
    } else if (on('cors.null-origin')) {
      h['access-control-allow-origin'] = 'null';
    } else if (on('cors.wildcard-sensitive')) {
      h['access-control-allow-origin'] = '*';
    }
    if (Object.keys(h).length > 0)
      h['access-control-allow-headers'] = 'authorization, content-type';
    return h;
  };

  return (req: IncomingMessage, res: ServerResponse): void => {
    const url = new URL(req.url ?? '/', 'https://shop.test');
    const path = url.pathname;
    const { partner, http } = ports();
    // For the custom rule of test/projects/shop (16-AC-01); no built-in rule reads it.
    if (
      path.startsWith('/api/') &&
      path !== '/api/token' &&
      !(path === '/api/me' && vulns.has('custom.request-id-missing'))
    ) {
      res.setHeader('x-request-id', 'req-0001');
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204, { ...common(), ...cors(req) });
      res.end();
      return;
    }
    switch (path) {
      case '/favicon.ico':
        res.writeHead(204, common());
        res.end();
        return;
      case '/': {
        const parts = [
          '<h1>Shop</h1>',
          '<nav><a id="account" href="/account">Account</a> <a id="search" href="/search?q=xyzzy42plugh">Search</a></nav>',
          `<script nonce="{{nonce}}" src="/static/${bundle}"></script>`,
          on('asset.sri-missing')
            ? `<script nonce="{{nonce}}" src="${partner}/lib.js"></script>`
            : `<script nonce="{{nonce}}" src="${partner}/lib.js" integrity="${LIB_SRI}" crossorigin="anonymous"></script>`,
          '<form id="subscribe" method="post" action="/subscribe"><button>Subscribe</button></form>',
        ];
        if (on('data.token-in-url'))
          parts[1] =
            parts[1]?.replace('href="/account"', `href="/account?token=${SECRETS.urlToken}"`) ?? '';
        if (on('transport.form-to-http'))
          parts[4] = `<form id="subscribe" method="post" action="${http}/subscribe"><button>Subscribe</button></form>`;
        if (on('transport.mixed-content')) parts.push(`<img alt="pixel" src="${http}/pixel.png">`);
        if (on('browser.csp-violation'))
          parts.push('<script>window.inlineWithoutNonce = 1</script>');
        if (on('data.token-in-storage')) {
          parts.push(
            `<script nonce="{{nonce}}">localStorage.setItem('access_token', ${JSON.stringify(SECRETS.storageJwt)});</script>`,
          );
        } else {
          parts.push(`<script nonce="{{nonce}}">localStorage.setItem('theme', 'dark');</script>`);
        }
        page(res, 'Shop', parts.join(''));
        return;
      }
      case '/account':
        page(res, 'Account', '<h1>Account</h1>');
        return;
      case '/search': {
        const q = url.searchParams.get('q') ?? '';
        page(
          res,
          'Search',
          on('browser.reflected-param')
            ? `<p>Results for ${q}</p>`
            : `<p>${escapeHtml(String(q.length))} characters searched</p>`,
        );
        return;
      }
      case '/redirect': {
        const next = url.searchParams.get('next') ?? '/';
        const target = on('browser.open-redirect-candidate') || next.startsWith('/') ? next : '/';
        res.writeHead(302, { ...common(), location: target });
        res.end();
        return;
      }
      case '/subscribe':
        res.writeHead(303, { ...common(), location: '/' });
        res.end();
        return;
      case `/static/${bundle}`: {
        let js = APP_JS;
        if (on('data.secret-in-asset')) js += `\nwindow.cfg = { awsKey: "${SECRETS.awsKey}" };`;
        if (on('disclosure.source-map')) js += `\n//# sourceMappingURL=${bundle}.map`;
        send(res, 200, 'text/javascript; charset=utf-8', js, { etag: `"js-${vulns.size}"` });
        return;
      }
      case '/static/app.5d41402a.css':
        send(res, 200, 'text/css; charset=utf-8', CSS);
        return;
      case '/static/':
        if (on('disclosure.directory-listing')) {
          send(
            res,
            200,
            'text/html',
            '<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1><a href="app.3f2a9c1b.js">app.3f2a9c1b.js</a></body></html>',
          );
        } else {
          send(res, 404, 'text/plain', 'Not found');
        }
        return;
      case '/api/login': {
        const cookies = [sessionCookie()];
        cookies.push(
          on('cookie.non-session-insecure')
            ? `theme=${SECRETS.theme}; Path=/; SameSite=Lax`
            : `theme=${SECRETS.theme}; Path=/; Secure; SameSite=Lax`,
        );
        json(res, 200, { ok: true }, { 'set-cookie': cookies });
        return;
      }
      case '/api/me': {
        const me: Record<string, unknown> = { id: 1, name: 'Alice', email: 'alice@example.com' };
        if (on('data.password-in-response')) me.passwordHash = SECRETS.passwordHash;
        if (on('disclosure.private-ip')) me.internalHost = '10.20.30.40';
        json(res, 200, me, cors(req));
        return;
      }
      case '/api/token': {
        const token = on('data.jwt-alg-none')
          ? SECRETS.jwtNone
          : on('data.jwt-no-exp')
            ? SECRETS.jwtNoExp
            : on('data.jwt-long-lived')
              ? SECRETS.jwtLong
              : on('data.jwt-sensitive-claims')
                ? SECRETS.jwtClaims
                : undefined;
        json(res, 200, token === undefined ? { ok: true } : { access_token: token });
        return;
      }
      case '/api/cors':
        json(res, 200, { items: [1, 2] }, cors(req));
        return;
      case '/api/fail':
        if (on('disclosure.stack-trace')) {
          send(
            res,
            500,
            'text/plain',
            `TypeError: Cannot read properties of undefined (reading 'id')\n    at handler (/srv/shop/node_modules/express/lib/router/layer.js:95:5)\n    at next (/srv/shop/node_modules/express/lib/router/route.js:149:13)`,
          );
        } else if (on('disclosure.sql-error')) {
          json(res, 400, {
            error:
              'SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax',
          });
        } else if (on('disclosure.debug-mode')) {
          send(
            res,
            400,
            'text/html',
            '<html><head><title>Werkzeug Debugger</title></head><body><div class="debugger"><h1>BadRequest</h1><div class="traceback">The debugger caught an exception in your WSGI application.</div></div></body></html>',
          );
        } else if (on('disclosure.server-error')) {
          json(res, 503, { error: 'service unavailable' });
        } else {
          json(res, 400, { error: 'bad request' });
        }
        return;
      default:
        if (path.startsWith('/api/products/')) {
          json(res, 200, { id: path.split('/').pop(), name: 'Teapot', price: 10 });
          return;
        }
        send(res, 404, 'text/plain', 'Not found');
    }
  };
}

/** The partner site: a page calling the app API cross-origin, a library and redirect targets. */
function partnerHandler(ports: () => Ports) {
  return (req: IncomingMessage, res: ServerResponse): void => {
    const path = new URL(req.url ?? '/', 'https://partner.test').pathname;
    const base = { 'x-content-type-options': 'nosniff' };
    if (path === '/lib.js') {
      res.writeHead(200, {
        ...base,
        'content-type': 'text/javascript',
        'access-control-allow-origin': '*',
      });
      res.end(LIB_JS);
      return;
    }
    if (path === '/partner') {
      const app = ports().app;
      res.writeHead(200, { ...base, 'content-type': 'text/html' });
      res.end(
        `<!doctype html><title>Partner</title><script>
window.done = Promise.allSettled([
  fetch(${JSON.stringify(`${app}/api/cors`)}, { credentials: 'include' }),
  fetch(${JSON.stringify(`${app}/api/me`)}, { headers: { authorization: 'Basic ${SECRETS.basicAuth}' } }),
]).then(() => true);
</script>`,
      );
      return;
    }
    res.writeHead(200, { ...base, 'content-type': 'text/html' });
    res.end('<!doctype html><title>Partner landing</title><p>landing</p>');
  };
}

function httpHandler(app: ReturnType<typeof appHandler>) {
  return (req: IncomingMessage, res: ServerResponse): void => {
    const path = new URL(req.url ?? '/', 'http://plain.test').pathname;
    if (path === '/pixel.png') {
      res.writeHead(200, { 'content-type': 'image/png', 'x-content-type-options': 'nosniff' });
      res.end(Buffer.from('89504e470d0a1a0a', 'hex'));
      return;
    }
    app(req, res);
  };
}

const listen = (server: Server, host: string): Promise<number> =>
  new Promise((resolve) =>
    server.listen(0, host, () => resolve((server.address() as AddressInfo).port)),
  );

/** Starts the app with the given switches; none = the secure mode (10-REQ-02). */
export async function startShop(
  vulns: Iterable<string> = [],
  options: { build?: string } = {},
): Promise<Shop> {
  const set = new Set(vulns);
  for (const rule of set) {
    if (
      !(APP_RULES as readonly string[]).includes(rule) &&
      !(CUSTOM_SWITCHES as readonly string[]).includes(rule)
    )
      throw new Error(`the test app has no switch ${rule}`);
  }
  const certs = join(import.meta.dirname, 'certs');
  const tls = {
    key: readFileSync(join(certs, 'key.pem')),
    cert: readFileSync(join(certs, 'cert.pem')),
  };
  let ports: Ports = { app: '', http: '', partner: '' };
  const handler = appHandler(set, () => ports, options.build ?? '1');
  const app = createHttpsServer(tls, handler);
  const plain = createServer(httpHandler(handler));
  const partner = createHttpsServer(
    tls,
    partnerHandler(() => ports),
  );
  const [appPort, httpPort, partnerPort] = await Promise.all([
    listen(app as unknown as Server, '127.0.0.1'),
    listen(plain, '127.0.0.1'),
    listen(partner as unknown as Server, '127.0.0.1'),
  ]);
  // The app on "localhost", the partner on "127.0.0.1": two origins of one certificate.
  ports = {
    app: `https://localhost:${appPort}`,
    http: `http://localhost:${httpPort}`,
    partner: `https://127.0.0.1:${partnerPort}`,
  };
  const servers = [app, plain, partner] as unknown as Server[];
  return {
    url: ports.app,
    httpUrl: ports.http,
    partnerUrl: ports.partner,
    async close() {
      for (const s of servers) s.closeAllConnections();
      await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
    },
  };
}
