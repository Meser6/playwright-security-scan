# data.token-in-storage

**Token in Web Storage**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / medium                                               |
| Subject               | storage-key                                                |
| Traffic               | browser                                                    |
| CWE                   | [CWE-922](https://cwe.mitre.org/data/definitions/922.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

Web Storage is readable by every script on the page, so one XSS is enough to steal the token. HttpOnly cookies are not readable by scripts.

## How to fix

Keep session tokens in a cookie with `HttpOnly; Secure; SameSite=Lax` and drop them from Web Storage.

- nginx: proxy the auth endpoint and set the cookie there (`proxy_cookie_flags ~ httponly secure samesite=lax;`).
- Express: `res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' })`.
- Spring Security: use the session cookie (`server.servlet.session.cookie.http-only=true`) instead of returning the token to the SPA.

## False positives

Short-lived tokens of a Backend-for-Frontend, or values that only look random (cache keys, ids). Accept them in the baseline with a note.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.token-in-storage': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
