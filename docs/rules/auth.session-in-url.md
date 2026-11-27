# auth.session-in-url

**Session id in URL**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | medium / high                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) |
| OWASP Top 10          | A07:2025                                                   |
| Presets               | `minimal`, `recommended`, `strict`                         |

## Why it matters

A session id in the URL ends up in browser history, logs and the Referer header of linked sites; whoever reads it takes over the session, and links with an id enable session fixation.

## How to fix

Keep the session id in a cookie only and turn off URL rewriting of sessions.

- nginx: do not log the query of such endpoints while fixing the application
- Express: read the session from a cookie (express-session); never put `req.sessionID` into links
- Spring Boot: `server.servlet.session.tracking-modes=cookie` (no `jsessionid` URL rewriting)

## False positives

A parameter named like a session that carries something else (e.g. `sid` as a site id): accept it with a note or change the option paramNames. Names of data.token-in-url are left to that rule.

## Options

| Option       | Default                                         |
| ------------ | ----------------------------------------------- |
| `paramNames` | `["sid","jsessionid","phpsessid","session_id"]` |

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'auth.session-in-url': 'off' }  // or { severity: 'low' }, or { options: { paramNames: … } }
```

_Generated from the rule catalog by `pnpm gen:docs`._
