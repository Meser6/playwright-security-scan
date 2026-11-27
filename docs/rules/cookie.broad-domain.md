# cookie.broad-domain

**Session cookie shared with subdomains**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | low / high                                                 |
| Subject               | cookie                                                     |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-565](https://cwe.mitre.org/data/definitions/565.html) |
| OWASP Top 10          | A02:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict` (medium)                |

## Why it matters

A cookie with a Domain attribute goes to every subdomain of that domain: any subdomain that is compromised, taken over or hosts user content can read or overwrite the session.

## How to fix

Leave out the `Domain` attribute so the cookie stays on the host that set it (a host-only cookie), or use the `__Host-` name prefix, which forbids `Domain`.

- nginx (as a proxy): `proxy_cookie_domain ~.* "";` removes the Domain attribute of upstream cookies
- Express: no `domain` in `res.cookie('sid', value, { … })` or in the `cookie` options of `express-session`
- Spring Boot: no `server.servlet.session.cookie.domain`; `cookie.setDomain(…)` not called

## False positives

Single sign-on across subdomains needs a shared cookie: accept it with a note when every subdomain is trusted.

## Options

| Option               | Default                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sessionNamePattern` | `"(sess\|sid\|auth\|token\|jwt\|login\|remember\|connect\\.sid\|PHPSESSID\|JSESSIONID\|ASP\\.NET_SessionId\|laravel_session)"`                                                                                                       |
| `nonSessionNames`    | `["_ga","_ga_*","_gid","_gat*","_gcl_*","__utm*","_fbp","_fbc","_hj*","_clck","_clsk","ajs_*","mp_*","cf_clearance","__cf_bm","__cfruid","_cfuvid","OptanonConsent","OptanonAlertBoxClosed","CookieConsent","cookieconsent_status"]` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'cookie.broad-domain': 'off' }  // or { severity: 'low' }, or { options: { sessionNamePattern: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
