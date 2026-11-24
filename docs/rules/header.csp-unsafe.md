# header.csp-unsafe

**Unsafe Content-Security-Policy**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

'unsafe-inline', 'unsafe-eval', wildcards and whole schemes in script-src let injected scripts run, so the policy no longer stops XSS.

## How to fix

Send `Content-Security-Policy: script-src 'self' 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'self'` on every response.

- nginx: `add_header Content-Security-Policy "script-src 'self' 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'self'" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Content-Security-Policy', 'script-src 'self' 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'self''); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("script-src 'self' 'nonce-{nonce}'")))`

## False positives

Legacy apps with inline handlers may need 'unsafe-inline' for a while: accept with an expiry date (until) and a ticket.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.csp-unsafe': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
