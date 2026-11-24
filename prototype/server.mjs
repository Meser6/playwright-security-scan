// Prototype server (WP-02): one HTTP and one HTTPS listener serving the pages the checks need.
// Not part of the package; node built-ins only.
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const dir = fileURLToPath(new URL('.', import.meta.url));

function handler(req, res) {
  const url = new URL(req.url, 'http://x');
  switch (url.pathname) {
    case '/cookies':
      res.setHeader('set-cookie', [
        'session_id=abc123; Path=/; HttpOnly',
        'theme=dark; Path=/',
        'csrf=xyz; Path=/; SameSite=Strict',
      ]);
      res.setHeader('content-type', 'text/html');
      res.end('<!doctype html><title>cookies</title><p>cookies</p>');
      return;
    case '/page':
      res.setHeader('content-type', 'text/html');
      res.end(
        '<!doctype html><title>page</title><script src="/app.js"></script>' +
          '<script>fetch("/data.json")</script>',
      );
      return;
    case '/app.js':
      res.setHeader('content-type', 'application/javascript');
      res.end('window.__app = 1; // ' + 'x'.repeat(5000));
      return;
    case '/data.json':
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ items: [1, 2, 3], token: 'secret' }));
      return;
    case '/csp':
      res.setHeader('content-type', 'text/html');
      res.setHeader('content-security-policy', "default-src 'self'; img-src 'none'");
      res.end(
        '<!doctype html><title>csp</title><script>window.inlineRan = true</script>' +
          '<img src="/blocked.png">',
      );
      return;
    case '/csp-report-only':
      res.setHeader('content-type', 'text/html');
      res.setHeader('content-security-policy-report-only', "default-src 'self'");
      res.end('<!doctype html><title>csp-ro</title><script>window.inlineRan = true</script>');
      return;
    case '/storage':
      res.setHeader('content-type', 'text/html');
      res.end(
        '<!doctype html><title>storage</title><script>' +
          'localStorage.setItem("token","eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig");' +
          'sessionStorage.setItem("s","1")</script>',
      );
      return;
    case '/slow': {
      // A body that takes a while, so the context can close during the read.
      res.setHeader('content-type', 'application/json');
      res.write('{"a":"' + 'x'.repeat(10000));
      setTimeout(() => res.end('"}'), 1500);
      return;
    }
    case '/api':
      res.setHeader('content-type', 'application/json');
      res.setHeader('set-cookie', ['a=1; Path=/', 'b=2; Path=/; HttpOnly']);
      res.end('{"ok":true}');
      return;
    default:
      res.statusCode = 404;
      res.end('not found');
  }
}

export async function start() {
  const http = createServer(handler);
  const https = createHttpsServer(
    {
      key: readFileSync(`${dir}/certs/key.pem`),
      cert: readFileSync(`${dir}/certs/cert.pem`),
    },
    handler,
  );
  await new Promise((r) => http.listen(0, '127.0.0.1', r));
  await new Promise((r) => https.listen(0, '127.0.0.1', r));
  return {
    http: `http://127.0.0.1:${http.address().port}`,
    https: `https://localhost:${https.address().port}`,
    close: () => Promise.all([http.close(), https.close()]),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const s = await start();
  console.log(JSON.stringify({ http: s.http, https: s.https }));
}
