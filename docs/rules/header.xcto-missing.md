# header.xcto-missing

**X-Content-Type-Options: nosniff missing**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | origin                                                     |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

Without nosniff a browser may guess the type of a response and run text or JSON as a script or style (MIME sniffing), which helps XSS and data leaks.

## How to fix

Send `X-Content-Type-Options: nosniff` on every response.

- nginx: `add_header X-Content-Type-Options "nosniff" always;`
- Express: `app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.contentTypeOptions(withDefaults()))`

## False positives

None known for HTML, scripts, styles and JSON. Accept it for legacy endpoints you cannot change.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.xcto-missing': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
