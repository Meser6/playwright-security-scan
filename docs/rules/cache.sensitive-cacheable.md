# cache.sensitive-cacheable

**Authenticated response may be cached**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / medium                                            |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-524](https://cwe.mitre.org/data/definitions/524.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `recommended`, `strict`                                    |

## Why it matters

A personal response without `Cache-Control: no-store` (or at least `private`) can be kept by shared caches, proxies and the browser and shown to the next user of the same cache or device.

## How to fix

Send `Cache-Control: no-store` on responses to authenticated requests (or `private, no-cache` when the browser may keep them).

- nginx: `add_header Cache-Control "no-store" always;` in the locations of the application and API
- Express: `res.set('Cache-Control', 'no-store')` in a middleware for authenticated routes (helmet's `noCache` in older versions)
- Spring Security: the default `Cache-Control: no-cache, no-store, max-age=0, must-revalidate` — keep `headers().cacheControl()` on

## False positives

A response without cache-control, expires and last-modified has no freshness and is reported with low confidence. A CDN or gateway that sets cache headers after the application is not seen when the tests run against the application directly; public pages that only carry a session cookie. Requests with only an Authorization header are reported when the response allows shared caches (`public`, `s-maxage`, `must-revalidate`). API requests are judged only when the test passed the credential in its own headers.

## Options

| Option               | Default                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"`                                                                                                       |
| `nonSessionNames`    | `["_ga","_ga_*","_gid","_gat*","_gcl_*","__utm*","_fbp","_fbc","_hj*","_clck","_clsk","ajs_*","mp_*","cf_clearance","__cf_bm","__cfruid","_cfuvid","OptanonConsent","OptanonAlertBoxClosed","CookieConsent","cookieconsent_status"]` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cache.sensitive-cacheable': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
