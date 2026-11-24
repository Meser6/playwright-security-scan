# data.token-in-url

**Token in URL**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) |
| OWASP Top 10          | A04:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

URLs end up in browser history, server and proxy logs and the Referer header of linked sites, so a token in the query leaks far beyond the request.

## How to fix

Send tokens in a header (`Authorization`) or a request body, never in the query string; for links (password reset, magic login) use short-lived one-time codes.

- nginx: do not log the query of such endpoints (`log_format` without `$args`) while fixing the client
- Express: read the token from `req.get('authorization')`, not `req.query`
- Spring Security: `BearerTokenResolver` without `setAllowUriQueryParameter(true)`

## False positives

OAuth authorization codes (`code`) are expected and not on the default list; one-time codes in email links can be accepted with a note. The names are the option paramNames.

## Options

| Option       | Default                                                                                                                                  |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `paramNames` | `["token","access_token","id_token","refresh_token","api_key","apikey","password","passwd","secret","session","sessionid","jwt","auth"]` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'data.token-in-url': 'off' }  // or { severity: 'low' }, or { options: { paramNames: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
