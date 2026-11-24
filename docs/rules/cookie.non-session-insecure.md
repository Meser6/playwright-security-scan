# cookie.non-session-insecure

**Cookie without Secure**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | info / medium                                              |
| Subject               | cookie                                                     |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) |
| OWASP Top 10          | —                                                          |
| Presets               | `recommended`, `strict` (low)                              |

## Why it matters

Cookies without Secure also travel over plain HTTP; even non-session cookies can carry preferences or tracking data.

## How to fix

Set the cookie with `Secure; SameSite=Lax`.

- nginx (as a proxy): `proxy_cookie_flags ~ secure samesite=lax;`
- Express: `res.cookie('sid', value, { secure: true, sameSite: 'lax' })` (or the `cookie` options of `express-session`)
- Spring Boot: `cookie.setSecure(true)`

## False positives

Reported as info.

## Options

| Option               | Default                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"`                                                                                                       |
| `nonSessionNames`    | `["_ga","_ga_*","_gid","_gat*","_gcl_*","__utm*","_fbp","_fbc","_hj*","_clck","_clsk","ajs_*","mp_*","cf_clearance","__cf_bm","__cfruid","_cfuvid","OptanonConsent","OptanonAlertBoxClosed","CookieConsent","cookieconsent_status"]` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cookie.non-session-insecure': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
