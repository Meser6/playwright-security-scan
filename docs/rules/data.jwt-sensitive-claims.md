# data.jwt-sensitive-claims

**Sensitive data in JWT claims**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / medium                                            |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

JWT payloads are only base64-encoded, not encrypted: anyone who sees the token reads every claim.

## How to fix

Keep secrets and personal data out of token claims; put an opaque id in the token and look the data up on the server.

- nginx (auth_jwt / OpenResty): reject tokens that fail the check before they reach the app
- Express: `jwt.sign({ sub: user.id }, key)` without sensitive fields
- Spring Security: `JwtClaimsSet.builder().subject(userId)` without sensitive claims

## False positives

Claims whose names only look sensitive (e.g. "card_type"): accept them as false-positive.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.jwt-sensitive-claims': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
