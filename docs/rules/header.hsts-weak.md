# header.hsts-weak

**Strict-Transport-Security max-age too short**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | origin                                                     |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

A short max-age lets the protection expire between visits, so the downgrade attack of a missing HSTS is possible again.

## How to fix

Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every response.

- nginx: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000)))`

## False positives

A short max-age during an HSTS rollout: accept with an until date. The threshold is the option minMaxAge.

## Options

| Option      | Default    |
| ----------- | ---------- |
| `minMaxAge` | `15552000` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.hsts-weak': 'off' }  // or { severity: 'low' }, or { options: { minMaxAge: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
