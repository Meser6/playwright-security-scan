# header.csp-report-only

**CSP in report-only mode only**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | info / high                                                |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| OWASP Top 10          | —                                                          |
| Presets               | `minimal`, `recommended`, `strict` (low)                   |

## Why it matters

A report-only policy reports violations but blocks nothing; it is a step towards an enforced policy, not a protection.

## How to fix

Send `Content-Security-Policy: <the report-only policy, once it reports no violations>` on every response.

- nginx: `add_header Content-Security-Policy "<the report-only policy, once it reports no violations>" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Content-Security-Policy', '<the report-only policy, once it reports no violations>'); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("…")))  // without .reportOnly()`

## False positives

Expected while a new policy is being tuned: accept with an until date.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.csp-report-only': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
