# cookie.samesite-none

**Session cookie with SameSite=None**

|                       |                                                              |
| --------------------- | ------------------------------------------------------------ |
| Severity / confidence | low / medium                                                 |
| Subject               | cookie                                                       |
| Traffic               | browser, api                                                 |
| CWE                   | [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) |
| OWASP Top 10          | A01:2025                                                     |
| Presets               | `recommended`, `strict`                                      |

## Why it matters

SameSite=None sends the session with requests started by other sites, which re-enables CSRF and cross-site leaks.

## How to fix

Set the cookie with `Secure; HttpOnly; SameSite=Lax`.

- nginx (as a proxy): `proxy_cookie_flags ~ secure httponly samesite=lax;`
- Express: `res.cookie('sid', value, { secure: true, httpOnly: true, sameSite: 'lax' })` (or the `cookie` options of `express-session`)
- Spring Boot: `server.servlet.session.cookie.same-site=lax`

## False positives

Apps embedded in third-party sites (SSO, widgets) need SameSite=None: accept with a note.

## Options

| Option               | Default                                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cookie.samesite-none': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
