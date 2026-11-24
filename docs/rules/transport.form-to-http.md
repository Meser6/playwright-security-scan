# transport.form-to-http

**Form submits over HTTP**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser                                                    |
| CWE                   | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

A form on an HTTPS page that posts to HTTP sends what the user typed (often passwords) in clear text.

## How to fix

Use HTTPS (or a relative URL) in every form action and add `form-action 'self'` to the CSP.

- nginx: `add_header Content-Security-Policy "form-action 'self'" always;`
- Express: `helmet.contentSecurityPolicy({ directives: { formAction: ["'self'"] } })`
- Spring Security: `http.headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives("form-action 'self'")))`

## False positives

None known.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'transport.form-to-http': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
