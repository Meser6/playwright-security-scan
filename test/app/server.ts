// Test application (10, chapter 3): a small node:http/https server. This first version serves
// the pages the collector tests need; WP-07 adds the secure mode and the per-rule switches.
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';

export interface TestApp {
  url: string;
  httpsUrl: string;
  close(): Promise<void>;
}

const b64 = (o: object): string => Buffer.from(JSON.stringify(o)).toString('base64url');
/** Secrets of the test app: no output file may contain them (S-07, 07-AC-03). */
export const SECRETS = {
  storageJwt: `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: 'user-1', iat: 1795000000 })}.c3RvcmFnZS1zaWduYXR1cmU`,
  awsKey: 'AKIAZ7QW3EXAMPLEKEY1',
  lateAwsKey: 'AKIAZ7QW3EXAMPLEKEY2',
};

const BIG_SIZE = 5 * 1024 * 1024;
let bigBundle: Buffer | undefined;
function big(): Buffer {
  // The first secret is in the first megabyte, the second after it (05-AC-02).
  bigBundle ??= Buffer.from(
    `var k="${SECRETS.awsKey}";\n/*${'x'.repeat(2 * 1024 * 1024)}*/\nvar l="${SECRETS.lateAwsKey}";\n/*${'y'.repeat(BIG_SIZE - 2 * 1024 * 1024 - 100)}*/\n`,
  );
  return bigBundle;
}

const html = (res: ServerResponse, body: string, headers: Record<string, string> = {}): void => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', ...headers });
  res.end(
    `<!doctype html><html><head><meta charset="utf-8"><title>test app</title></head><body>${body}</body></html>`,
  );
};

function handle(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url ?? '/', 'http://app.test');
  const path = url.pathname;
  if (path === '/favicon.ico') {
    res.writeHead(204).end();
    return;
  }
  if (path === '/' || path === '/page') {
    html(
      res,
      '<h1>Shop</h1><script src="/static/app.3f2a9c1b.js"></script><script>fetch("/api/items/1")</script>',
      { 'x-content-type-options': 'nosniff' },
    );
    return;
  }
  if (path.startsWith('/static/app.')) {
    res.writeHead(200, {
      'content-type': 'application/javascript',
      etag: '"app-1"',
      'x-content-type-options': 'nosniff',
    });
    res.end(`window.cfg={aws:"${SECRETS.awsKey}"};`);
    return;
  }
  if (path === '/bundle') {
    html(res, '<script src="/static/big.js"></script>', { 'x-content-type-options': 'nosniff' });
    return;
  }
  if (path === '/static/big.js') {
    res.writeHead(200, {
      'content-type': 'application/javascript',
      etag: '"big-1"',
      'x-content-type-options': 'nosniff',
      'content-length': String(big().length),
    });
    res.end(big());
    return;
  }
  if (path === '/api/hang') {
    // Never answers within the test timeout (15-AC-03).
    setTimeout(() => res.writeHead(204).end(), 10_000).unref();
    return;
  }
  if (path === '/api/orders' && req.method === 'POST') {
    res.writeHead(201, { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' });
    res.end(JSON.stringify({ id: 7, status: 'created' }));
    return;
  }
  if (path === '/api/config') {
    res.writeHead(200, { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' });
    res.end(JSON.stringify({ stripe: SECRETS.awsKey }));
    return;
  }
  if (path.startsWith('/api/items/')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id: path.split('/').pop(), name: 'Item' }));
    return;
  }
  if (path === '/storage') {
    html(
      res,
      `<script>localStorage.setItem("auth_token", ${JSON.stringify(SECRETS.storageJwt)});</script>`,
      {
        'x-content-type-options': 'nosniff',
      },
    );
    return;
  }
  if (path === '/csp') {
    html(res, '<script>window.inline = 1</script><img src="/blocked.png">', {
      'content-security-policy': "default-src 'self'; img-src 'none'",
      'x-content-type-options': 'nosniff',
    });
    return;
  }
  if (path === '/slow') {
    res.writeHead(200, { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' });
    res.write(`{"data":"${'z'.repeat(10_000)}`);
    setTimeout(() => res.end('"}'), 3000);
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain', 'x-content-type-options': 'nosniff' });
  res.end('not found');
}

const listen = (server: Server): Promise<number> =>
  new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)),
  );

export async function startTestApp(): Promise<TestApp> {
  const http = createServer(handle);
  const certs = join(import.meta.dirname, 'certs');
  const https = createHttpsServer(
    { key: readFileSync(join(certs, 'key.pem')), cert: readFileSync(join(certs, 'cert.pem')) },
    handle,
  );
  const [port, httpsPort] = await Promise.all([listen(http), listen(https as unknown as Server)]);
  return {
    url: `http://127.0.0.1:${port}`,
    httpsUrl: `https://localhost:${httpsPort}`,
    close: async () => {
      http.closeAllConnections();
      https.closeAllConnections();
      await Promise.all([new Promise((r) => http.close(r)), new Promise((r) => https.close(r))]);
    },
  };
}
