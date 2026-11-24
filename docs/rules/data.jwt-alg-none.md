# data.jwt-alg-none

**JWT with alg none**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | critical / high                                            |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

A token with alg "none" has no signature: anyone can change its claims (user id, roles) and, if the server accepts it, become any user.

## How to fix

Sign every token and accept only the algorithms you issue.

- nginx (auth_jwt / OpenResty): reject tokens that fail the check before they reach the app
- Express: `jwt.verify(token, key, { algorithms: ['RS256'] })` (jsonwebtoken)
- Spring Security: `NimbusJwtDecoder.withPublicKey(key).signatureAlgorithm(SignatureAlgorithm.RS256).build()`

## False positives

None known.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.jwt-alg-none': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
