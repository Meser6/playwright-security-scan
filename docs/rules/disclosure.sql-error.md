# disclosure.sql-error

**SQL error in a response**

|                       |                                                                                                                      |
| --------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Severity / confidence | high / medium                                                                                                        |
| Subject               | endpoint                                                                                                             |
| Traffic               | browser, api                                                                                                         |
| CWE                   | [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| OWASP Top 10          | A05:2025                                                                                                             |
| Presets               | `recommended`, `strict`                                                                                              |

## Why it matters

A database error in a response shows that input reached a query unescaped (a likely SQL injection) and leaks the schema.

## How to fix

Use parameterized queries everywhere and return generic errors.

- nginx: `proxy_intercept_errors on;` with generic `error_page 500 502 503 504 /50x.html;`
- Express: parameterized queries (`db.query('SELECT … WHERE id = $1', [id])`) and a generic error handler
- Spring Boot: Spring Data / `JdbcTemplate` with `?` parameters and `server.error.include-message=never`

## False positives

Pages that document SQL errors. Confirm SQL injection with an active test (stage E3).

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.sql-error': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
