# disclosure.server-error

**Server error during tests**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | info / high                                                |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-755](https://cwe.mitre.org/data/definitions/755.html) |
| OWASP Top 10          | A10:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (low)                   |

## Why it matters

Unhandled server errors often reveal fragile input handling; they are also functional bugs.

## How to fix

Handle the error case and return a 4xx for invalid input.

- nginx: `proxy_intercept_errors on;` with generic `error_page 500 502 503 504 /50x.html;`
- Express: validate input and return `res.status(400)` for bad requests
- Spring Boot: `@ControllerAdvice` with `@ExceptionHandler` returning 4xx for client errors

## False positives

Tests that provoke 5xx on purpose. Reported as info.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.server-error': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
