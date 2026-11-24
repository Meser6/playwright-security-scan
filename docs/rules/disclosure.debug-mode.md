# disclosure.debug-mode

**Debug page exposed**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / medium                                            |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

Debug pages expose source code, settings and sometimes an interactive console (Werkzeug) that runs code on the server.

## How to fix

Turn debug mode off outside development.

- nginx: nothing to configure; set the framework to production mode
- Express: `NODE_ENV=production`; remove `errorhandler` in production
- Spring Boot: no `spring-boot-devtools` in production, `server.error.include-stacktrace=never`

## False positives

Development environments scanned on purpose: scan the deployed environment instead.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'disclosure.debug-mode': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
