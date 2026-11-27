# authz.vertical

**Higher-role endpoint readable by a lower role**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | high / medium                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-285](https://cwe.mitre.org/data/definitions/285.html) |
| OWASP Top 10          | A01:2025                                                   |
| Presets               | every preset, with `authz.enabled` (docs/authz.md)         |

An authorization test, not a passive rule: it runs only with `authz.enabled: true` and replays GET/HEAD requests of your tests (see [docs/authz.md](../authz.md)).

## Why it matters

A request of a role with a higher authz.roles level was replayed in the session of a role with a lower level that never got this endpoint in the tests, and the answer was the same. A lower role can use functions of a higher one (privilege escalation, OWASP A01).

## How to fix

Check the role or permission on the server for every function of a higher role, not only in the menu of the frontend.

- nginx: `auth_request` to an authorization service that knows the roles, for the admin locations
- Express: a `requireRole('admin')` middleware on the admin router that answers `res.sendStatus(403)`
- Spring Security: `.requestMatchers("/admin/**").hasRole("ADMIN")` or `@PreAuthorize("hasRole('ADMIN')")`

## False positives

Endpoints both roles may read, but the tests of the lower role never called: reported with medium confidence. Mark them in the baseline as false-positive, or call them in a test of the lower role (then they are not tested vertically).

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'authz.vertical': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
