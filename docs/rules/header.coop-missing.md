# header.coop-missing

**Cross-Origin-Opener-Policy missing**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | info / high                                                |
| Subject               | origin                                                     |
| Traffic               | browser                                                    |
| CWE                   | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| OWASP Top 10          | —                                                          |
| Presets               | `strict` (low)                                             |

## Why it matters

Without Cross-Origin-Opener-Policy a page opened by another site keeps a reference to it (window.opener), which enables cross-window attacks and leaks.

## How to fix

Send `Cross-Origin-Opener-Policy: same-origin` on every response.

- nginx: `add_header Cross-Origin-Opener-Policy "same-origin" always;`
- Express: `app.use((req, res, next) => { res.setHeader('Cross-Origin-Opener-Policy', 'same-origin'); next(); });` or the matching `helmet` middleware
- Spring Security: `http.headers(h -> h.crossOriginOpenerPolicy(c -> c.policy(SAME_ORIGIN)))`

## False positives

Reported only in the strict preset; it hardens the page but its absence is not a vulnerability by itself.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'header.coop-missing': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
