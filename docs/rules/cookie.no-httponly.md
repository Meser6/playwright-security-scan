# cookie.no-httponly

**Session cookie without HttpOnly**

|                       |                                                              |
| --------------------- | ------------------------------------------------------------ |
| Severity / confidence | medium / high                                                |
| Subject               | cookie                                                       |
| Traffic               | browser, api                                                 |
| CWE                   | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) |
| OWASP Top 10          | A02:2025                                                     |
| Presets               | `minimal`, `recommended`, `strict`                           |

## Why it matters

A session cookie without HttpOnly can be read by any script on the page, so a single XSS steals the session.

## How to fix

Set the cookie with `Secure; HttpOnly; SameSite=Lax`.

- nginx (as a proxy): `proxy_cookie_flags ~ secure httponly samesite=lax;`
- Express: `res.cookie('sid', value, { secure: true, httpOnly: true, sameSite: 'lax' })` (or the `cookie` options of `express-session`)
- Spring Boot: `server.servlet.session.cookie.http-only=true`

## False positives

CSRF tokens meant to be read by JavaScript (XSRF-TOKEN, csrftoken) are excluded by the option httpOnlyExceptions; add your own names there.

## Options

| Option               | Default                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"`                                                                                                       |
| `nonSessionNames`    | `["_ga","_ga_*","_gid","_gat*","_gcl_*","__utm*","_fbp","_fbc","_hj*","_clck","_clsk","ajs_*","mp_*","cf_clearance","__cf_bm","__cfruid","_cfuvid","OptanonConsent","OptanonAlertBoxClosed","CookieConsent","cookieconsent_status"]` |
| `httpOnlyExceptions` | `["XSRF-TOKEN","csrftoken","csrf_token","_csrf","CSRF-TOKEN"]`                                                                                                                                                                       |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cookie.no-httponly': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
