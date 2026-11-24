# header.csp-missing

**Content-Security-Policy missing**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

Without a Content-Security-Policy any injected script runs: one XSS bug gives full control of the page and the session.

## How to fix

Send `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'` on every response.

- nginx: `add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Content-Security-Policy', 'default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self'; frame-ancestors 'none''); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; object-src 'none'")))`

## False positives

Pages that only redirect or download files. Start with Content-Security-Policy-Report-Only if the policy may break the page.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.csp-missing': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
