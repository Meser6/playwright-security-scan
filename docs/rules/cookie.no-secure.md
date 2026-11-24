# cookie.no-secure

**Session cookie without Secure**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | cookie                                                     |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

A cookie without Secure is also sent over plain HTTP, where anyone on the network can read the session and take over the account.

## How to fix

Set the cookie with `Secure; HttpOnly; SameSite=Lax`.

- nginx (as a proxy): `proxy_cookie_flags ~ secure httponly samesite=lax;`
- Express: `res.cookie('sid', value, { secure: true, httpOnly: true, sameSite: 'lax' })` (or the `cookie` options of `express-session`)
- Spring Boot: `server.servlet.session.cookie.secure=true`

## False positives

Local development over HTTP is reported with low confidence only.

## Options

| Option               | Default                                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cookie.no-secure': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
