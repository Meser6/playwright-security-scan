# auth.session-fixation

**Session id not renewed at login**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / medium                                            |
| Subject               | cookie                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-384](https://cwe.mitre.org/data/definitions/384.html) |
| OWASP Top 10          | A07:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

When the session id stays the same across login, an attacker who planted or learned the id before the victim signed in (session fixation) is signed in as the victim afterwards.

## How to fix

Issue a new session id when the user signs in (and when privileges change), and invalidate the old one.

- nginx: nothing to configure; the application must renew the session
- Express: `req.session.regenerate(cb)` after a successful login (express-session)
- Spring Security: session fixation protection `changeSessionId` (the default) — do not set `sessionFixation().none()`

## False positives

Login paths are recognized by the option loginPathPattern; an endpoint that only matches by name (e.g. a token refresh) can be reported. Sessions that only become privileged later (step-up) are not seen. Browser traffic only.

## Options

| Option               | Default                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"`                                                                                                       |
| `nonSessionNames`    | `["_ga","_ga_*","_gid","_gat*","_gcl_*","__utm*","_fbp","_fbc","_hj*","_clck","_clsk","ajs_*","mp_*","cf_clearance","__cf_bm","__cfruid","_cfuvid","OptanonConsent","OptanonAlertBoxClosed","CookieConsent","cookieconsent_status"]` |
| `loginPathPattern`   | `"(^\|/)(login\|log-in\|signin\|sign-in\|auth\|authenticate\|session\|sessions\|token)(/\|$)"`                                                                                                                                       |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'auth.session-fixation': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
