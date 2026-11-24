# header.clickjacking

**No clickjacking protection**

|                       |                                                              |
| --------------------- | ------------------------------------------------------------ |
| Severity / confidence | medium / medium                                              |
| Subject               | origin                                                       |
| Traffic               | browser                                                      |
| CWE                   | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) |
| OWASP Top 10          | A02:2025                                                     |
| Presets               | `recommended`, `strict`                                      |

## Why it matters

A page that any site can put in an iframe can be overlaid with a decoy, so users click buttons they cannot see (clickjacking).

## How to fix

Send `Content-Security-Policy: frame-ancestors 'none'` on every response.

- nginx: `add_header Content-Security-Policy "frame-ancestors 'none'" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Content-Security-Policy', 'frame-ancestors 'none''); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.frameOptions(f -> f.deny()))`

## False positives

Pages meant to be embedded by partners (widgets): allow those origins in frame-ancestors, or accept the finding in the baseline.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.clickjacking': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
