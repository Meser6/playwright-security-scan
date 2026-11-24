# header.csp-missing-directives

**CSP without object-src or base-uri**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

default-src does not cover base-uri, and plugins (object-src) can run code: without them an attacker can change the base URL of relative scripts or load a plugin.

## How to fix

Send `Content-Security-Policy: …; object-src 'none'; base-uri 'self'` on every response.

- nginx: `add_header Content-Security-Policy "…; object-src 'none'; base-uri 'self'" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Content-Security-Policy', '…; object-src 'none'; base-uri 'self''); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("…; object-src 'none'; base-uri 'self'")))`

## False positives

None known; object-src is not needed when default-src is 'none'.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.csp-missing-directives': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
