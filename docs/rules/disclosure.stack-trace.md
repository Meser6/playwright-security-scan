# disclosure.stack-trace

**Stack trace in a response**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) |
| OWASP Top 10          | A10:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

Stack traces show file paths, library versions and code structure, which helps an attacker pick an exploit; they also signal unhandled errors.

## How to fix

Return a generic error body to clients and log the details on the server.

- nginx: `proxy_intercept_errors on;` with generic `error_page 500 502 503 504 /50x.html;`
- Express: an error handler `app.use((err, req, res, next) => { log(err); res.status(500).json({ error: 'Internal error' }); })` and `NODE_ENV=production`
- Spring Boot: `server.error.include-stacktrace=never`

## False positives

Developer documentation pages that show sample traces: accept them as false-positive.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.stack-trace': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
