# data.jwt-long-lived

**Long-lived JWT**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-613](https://cwe.mitre.org/data/definitions/613.html) |
| OWASP Top 10          | A07:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

A long-lived access token gives an attacker who steals it a long window; access tokens should be short-lived and renewed with a refresh token.

## How to fix

Keep access tokens short (minutes) and renew them with a refresh token kept in an HttpOnly cookie.

- nginx (auth_jwt / OpenResty): reject tokens that fail the check before they reach the app
- Express: `jwt.sign(claims, key, { expiresIn: '15m' })`
- Spring Security: `JwtClaimsSet.builder().expiresAt(now.plus(15, MINUTES))`

## False positives

Refresh tokens are skipped when their name or claims say so. The limit is the option maxJwtHours.

## Options

| Option        | Default |
| ------------- | ------- |
| `maxJwtHours` | `24`    |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.jwt-long-lived': 'off' }  // or { severity: 'low' }, or { options: { maxJwtHours: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
