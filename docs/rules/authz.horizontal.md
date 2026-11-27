# authz.horizontal

**Another user's object readable (IDOR)**

|                       |                                                            |
| --------------------- | ---------------------------------------------------------- |
| Severity / confidence | high / medium                                              |
| Subject               | endpoint                                                   |
| Traffic               | browser, api                                               |
| CWE                   | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) |
| OWASP Top 10          | A01:2025                                                   |
| Presets               | every preset, with `authz.enabled` (docs/authz.md)         |

An authorization test, not a passive rule: it runs only with `authz.enabled: true` and replays GET/HEAD requests of your tests (see [docs/authz.md](../authz.md)).

## Why it matters

A request of user A for an object of A (an id in the path or the query) was replayed in the session of user B of the same role, and B got A's object. Users can read each other's data by changing an id (BOLA/IDOR, OWASP A01).

## How to fix

Check on the server that the object belongs to the user of the session (or that the user may see it) before returning it; answer 404 or 403 otherwise. Never rely on ids being hard to guess.

- nginx: nothing to configure — ownership is application logic; at most `auth_request` to an authorization service that gets the object id
- Express: load the object with the owner in the query (`Invoice.findOne({ id: req.params.id, ownerId: req.user.id })`) and `res.sendStatus(404)` when there is none
- Spring Security: `@PostAuthorize("returnObject.ownerId == authentication.principal.id")` on the service method, or a check in the repository query

## False positives

Objects shared on purpose between users of a role (a team board): exclude the endpoint with authz.exclude or mark the finding in the baseline. Needs two projects of one role (authz.roles.<project>.role); without them the test is skipped and the coverage says so.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'authz.horizontal': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
