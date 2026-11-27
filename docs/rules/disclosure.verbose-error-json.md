# disclosure.verbose-error-json

**Error details in a JSON response**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / medium                                            |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) |
| OWASP Top 10          | A10:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

Stack traces and exception details in API errors reveal frameworks, file paths, queries and internal logic, which helps attackers tune their input.

## How to fix

Return a generic error body (a message and a correlation id) and log the details on the server.

- nginx: `proxy_intercept_errors on;` with generic `error_page 500 502 503 504 /50x.html;`
- Express: an error handler that returns `{ error, requestId }` only, with `NODE_ENV=production`
- Spring Boot: `server.error.include-stacktrace=never` and `server.error.include-exception=false`

## False positives

A key named `trace` or `exception` that carries something harmless (e.g. a trace id): accept it with a note.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.verbose-error-json': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
