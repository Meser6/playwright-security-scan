# header.permissions-policy-missing

**Permissions-Policy missing**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | info / high                                                |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| OWASP Top 10          | —                                                          |
| Presets               | `strict` (low)                                             |

## Why it matters

Permissions-Policy limits powerful browser features (camera, microphone, location) that injected or third-party code could otherwise use.

## How to fix

Send `Permissions-Policy: camera=(), microphone=(), geolocation=()` on every response.

- nginx: `add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.permissionsPolicy(p -> p.policy("camera=(), microphone=()")))`

## False positives

Reported only in the strict preset; it hardens the page but its absence is not a vulnerability by itself.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.permissions-policy-missing': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
