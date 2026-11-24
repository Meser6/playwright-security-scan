# data.jwt-no-exp

**JWT without expiry**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-613](https://cwe.mitre.org/data/definitions/613.html) |
| OWASP Top 10          | A07:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

A token without exp is valid forever: a leaked token cannot expire and logout does not end the session.

## How to fix

Issue every access token with a short exp and check it.

- nginx (auth_jwt / OpenResty): reject tokens that fail the check before they reach the app
- Express: `jwt.sign(claims, key, { expiresIn: '15m' })`
- Spring Security: `JwtClaimsSet.builder().expiresAt(now.plus(15, MINUTES))`

## False positives

Tokens of third parties you cannot change: accept them with a note.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.jwt-no-exp': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
