# browser.csrf-missing

**State-changing request without CSRF protection**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / low                                               |
| Subject               | endpoint                                                   |
| Traffic               | browser                                                    |
| CWE                   | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| OWASP Top 10          | A01:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

A cookie without SameSite=Lax/Strict goes along with requests from other sites: without a CSRF token, any page the user visits can submit this request in their name (cross-site request forgery).

## How to fix

Set the session cookie with `SameSite=Lax` (or `Strict`) and protect state-changing requests with a CSRF token (synchronizer or double-submit) or a custom header that cross-site forms cannot send.

- nginx (as a proxy): `proxy_cookie_flags ~ samesite=lax;`
- Express: `csurf`-style middleware (e.g. `csrf-csrf`) and `cookie: { sameSite: 'lax' }` in express-session
- Spring Security: CSRF protection on (the default) with `CookieCsrfTokenRepository` for SPAs

## False positives

Servers that check the Origin or Referer header, which is invisible to a passive scan. Reported with low confidence and never blocks by default. Cookies not set during the test (e.g. from storageState) are not judged.

## Options

| Option               | Default                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"`                                                                                                       |
| `nonSessionNames`    | `["_ga","_ga_*","_gid","_gat*","_gcl_*","__utm*","_fbp","_fbc","_hj*","_clck","_clsk","ajs_*","mp_*","cf_clearance","__cf_bm","__cfruid","_cfuvid","OptanonConsent","OptanonAlertBoxClosed","CookieConsent","cookieconsent_status"]` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'browser.csrf-missing': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
