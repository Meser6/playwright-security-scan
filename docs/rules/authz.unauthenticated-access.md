# authz.unauthenticated-access

**Endpoint readable without a session**

|                       |                                                                                                                        |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Severity / confidence | high / medium                                                                                                          |
| Subject               | endpoint                                                                                                               |
| Traffic               | browser, api                                                                                                           |
| CWE                   | [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) |
| OWASP Top 10          | A01:2025                                                                                                               |
| Presets               | every preset, with `authz.enabled` (docs/authz.md)                                                                     |

An authorization test, not a passive rule: it runs only with `authz.enabled: true` and replays GET/HEAD requests of your tests (see [docs/authz.md](../authz.md)).

## Why it matters

A GET request that a test made with a session was replayed without any cookie or credential header and got an answer like the one of the logged-in user. Anyone who knows the URL can read the data (broken access control, OWASP A01).

## How to fix

Require an authenticated session on every non-public route and answer 401 (API) or a redirect to the sign-in page (pages) without one.

- nginx: `auth_request /auth;` in the protected `location` blocks, so the auth service decides before the upstream is called
- Express: an `requireAuth` middleware on the router of the API (`router.use(requireAuth)`) that answers `res.sendStatus(401)` without `req.user`
- Spring Security: `http.authorizeHttpRequests(a -> a.requestMatchers("/public/**").permitAll().anyRequest().authenticated())`

## False positives

Endpoints that are public on purpose but personalised when logged in (a product page with a wish-list flag): seen without a session in the run, they are recognised as public and not tested. A response that is the same for everyone (settings of the shop) is reported with medium confidence; high only when the answer carries an identifier of the original user.

## Accept or switch off

Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:

```ts
rules: { 'authz.unauthenticated-access': 'off' }  // or { severity: 'low' }
```

_Generated from the rule catalog by `pnpm gen:docs`._
