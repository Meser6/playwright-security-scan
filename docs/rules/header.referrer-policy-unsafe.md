# header.referrer-policy-unsafe

**Unsafe Referrer-Policy**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| OWASP Top 10          | —                                                          |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

unsafe-url and no-referrer-when-downgrade send the full URL, including tokens or personal data in the query, to every linked or embedded site.

## How to fix

Send `Referrer-Policy: strict-origin-when-cross-origin` on every response.

- nginx: `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.referrerPolicy(r -> r.policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)))`

## False positives

A missing header is reported as info only: current browsers use a safe default.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.referrer-policy-unsafe': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
