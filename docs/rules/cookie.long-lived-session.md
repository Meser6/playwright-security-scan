# cookie.long-lived-session

**Long-lived session cookie**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / medium                                               |
| Subject               | cookie                                                     |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-613](https://cwe.mitre.org/data/definitions/613.html) |
| OWASP Top 10          | A07:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

A long-lived session stays valid on shared or stolen devices long after the user left.

## How to fix

Set the cookie with `Secure; HttpOnly; SameSite=Lax; Max-Age=86400`.

- nginx (as a proxy): `proxy_cookie_flags ~ secure httponly samesite=lax max-age=86400;`
- Express: `res.cookie('sid', value, { secure: true, httpOnly: true, sameSite: 'lax', maxAge: 86_400_000 })` (or the `cookie` options of `express-session`)
- Spring Boot: `server.servlet.session.timeout=30m`

## False positives

"Remember me" cookies are long-lived by design: accept them with a note. The limit is the option maxSessionDays.

## Options

| Option               | Default                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"`                                                                                                       |
| `nonSessionNames`    | `["_ga","_ga_*","_gid","_gat*","_gcl_*","__utm*","_fbp","_fbc","_hj*","_clck","_clsk","ajs_*","mp_*","cf_clearance","__cf_bm","__cfruid","_cfuvid","OptanonConsent","OptanonAlertBoxClosed","CookieConsent","cookieconsent_status"]` |
| `maxSessionDays`     | `30`                                                                                                                                                                                                                                 |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cookie.long-lived-session': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
