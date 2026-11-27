# browser.password-form-get

**Password form submitted with GET**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser                                                    |
| CWE                   | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

A form sent with GET puts its fields, the password included, into the URL: browser history, server and proxy logs and the Referer header of the next page keep it.

## How to fix

Use `<form method="post">` for every form with a password field (or send it from script with a POST body).

- nginx: nothing to configure; fix the form (and do not log query strings of the login path meanwhile)
- Express: render the form with `method="post"` and handle it in `app.post(...)`
- Spring: `th:method="post"` in the template and `@PostMapping` for the login handler (Spring Security login is POST only)

## False positives

Forms without method and action are skipped (single-page apps submit them from script); a form whose submit is always intercepted by script but has a GET action: fix the markup or accept it with a note.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'browser.password-form-get': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
