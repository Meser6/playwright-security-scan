# cookie.samesite-missing

**Cookie without SameSite**

|                       |                                                              |
| --------------------- | ------------------------------------------------------------ |
| Severity / confidence | info / high                                                  |
| Subject               | cookie                                                       |
| Traffic               | browser, api                                                 |
| CWE                   | [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) |
| OWASP Top 10          | —                                                            |
| Presets               | `minimal`, `recommended`, `strict` (low)                     |

## Why it matters

Without SameSite the browser default applies (Lax in current browsers, None in old ones); being explicit avoids surprises.

## How to fix

Set the cookie with `Secure; HttpOnly; SameSite=Lax`.

- nginx (as a proxy): `proxy_cookie_flags ~ secure httponly samesite=lax;`
- Express: `res.cookie('sid', value, { secure: true, httpOnly: true, sameSite: 'lax' })` (or the `cookie` options of `express-session`)
- Spring Boot: `server.servlet.session.cookie.same-site=lax`

## False positives

Reported as info: current browsers treat a missing SameSite as Lax.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cookie.samesite-missing': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
