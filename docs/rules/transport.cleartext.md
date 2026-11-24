# transport.cleartext

**Application served over HTTP**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | origin                                                     |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

Plain HTTP can be read and changed by anyone on the network: sessions, passwords and personal data are exposed.

## How to fix

Serve the application only over HTTPS and redirect HTTP to HTTPS.

- nginx: `server { listen 80; return 301 https://$host$request_uri; }`
- Express: behind a proxy, `app.use((req, res, next) => req.secure ? next() : res.redirect(301, 'https://' + req.headers.host + req.url))`
- Spring Security: `http.requiresChannel(c -> c.anyRequest().requiresSecure())`

## False positives

Local development (localhost) is reported with low confidence.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'transport.cleartext': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
