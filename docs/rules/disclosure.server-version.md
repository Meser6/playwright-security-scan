# disclosure.server-version

**Server version disclosed**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | origin                                                     |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

Exact versions let an attacker look up known vulnerabilities of the server or framework without probing.

## How to fix

Hide versions in response headers.

- nginx: `server_tokens off;` (and `more_clear_headers Server;` with headers-more)
- Express: `app.disable('x-powered-by')` (or `helmet()`)
- Spring Boot: `server.server-header=` (empty) and no `X-Application-Context`

## False positives

None known; reported with low severity.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.server-version': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
