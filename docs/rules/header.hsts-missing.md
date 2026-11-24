# header.hsts-missing

**Strict-Transport-Security missing**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | origin                                                     |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

Without HSTS the first request of a visit can go over plain HTTP, where an attacker on the network can downgrade the connection and steal the session.

## How to fix

Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every response.

- nginx: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000).includeSubDomains(true)))`

## False positives

Local and test environments without a real certificate; accept them or scan the deployed environment.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.hsts-missing': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
