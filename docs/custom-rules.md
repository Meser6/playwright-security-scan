# Custom rules

> **Experimental.** The custom rules API (`playwright-security-scan/rules`) may change in `0.x`
> releases; such changes are listed in the [changelog](../CHANGELOG.md) under "Custom rules API".
> From `1.0.0` it follows semantic versioning like the rest of the package.

The built-in rules cover what every web app should do. Your team may have its own rules: a header
your gateway must add, script domains you do not allow, a cookie naming scheme. A custom rule is a
small function you write once; it then works exactly like a built-in rule: findings get
fingerprints, go into `security-baseline.json`, new ones fail the run above the gate, and they
appear in every report (console, HTML, JSON, SARIF, JUnit).

Write a custom rule when the check can be decided from the traffic your tests already make: one
response (status, headers, body) or one browser event (cookie jar, Web Storage, CSP violation).
A rule cannot send requests and cannot be asynchronous.

## A first rule

Every API response should carry an `x-request-id` header:

```ts
// security-rules.ts
import { defineRule, getHeader } from 'playwright-security-scan/rules';

export const requestId = defineRule({
  id: 'custom.request-id-missing',
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  scope: 'endpoint', // what the finding is about: one finding per endpoint
  appliesTo: { sources: ['api', 'browser'], resourceTypes: ['api', 'xhr', 'fetch'] },
  options: { header: 'x-request-id' }, // defaults, overridden in the config
  docs: {
    title: 'API response without x-request-id',
    why: 'Without a request id incidents cannot be traced across services.',
    fix: 'Add the header in the gateway (see the platform runbook).',
    falsePositives: 'Health checks served by the load balancer.',
    url: 'https://wiki.example.com/security/request-id', // optional
  },
  check(input, ctx) {
    if (input.kind !== 'response') return [];
    if (getHeader(input, ctx.options.header as string) !== undefined) return [];
    return [{ subject: input.endpointKey, message: `No ${String(ctx.options.header)} header` }];
  },
});
```

Add it to the package config:

```ts
// pw-sec.config.ts
import { defineSecurityConfig } from 'playwright-security-scan/config';
import { requestId } from './security-rules';

export default defineSecurityConfig({
  rules: {
    custom: [requestId],
    // Optional: the same settings as for built-in rules.
    'custom.request-id-missing': { severity: 'medium', options: { header: 'x-correlation-id' } },
  },
});
```

The start banner then says `Rules  45 enabled (preset recommended, 1 custom)`.

## The definition

| Field               | Required | Meaning                                                                                                              |
| ------------------- | -------- | -------------------------------------------------------------------------------------------------------------------- |
| `id`                | yes      | `custom.<name>`; `<name>` is lowercase letters, digits and `-`, up to 48 characters. No built-in rule uses `custom.` |
| `defaultSeverity`   | yes      | `info`, `low`, `medium`, `high` or `critical`                                                                        |
| `defaultConfidence` | yes      | `low`, `medium` or `high`; presets use it like for built-in rules                                                    |
| `scope`             | yes      | `origin`, `endpoint`, `cookie`, `storage-key` or `asset`: what `subject` is                                          |
| `check`             | yes      | `(input, ctx) => findings[]`, synchronous and pure                                                                   |
| `docs`              | yes      | `title`, `why`, `fix`; optional `falsePositives` and `url` (shown in the HTML report and SARIF)                      |
| `appliesTo`         | no       | `sources`, `resourceTypes`, `records`, `events`, `outOfScope` (below)                                                |
| `needsBody`         | no       | `true` or resource types whose response body the rule reads                                                          |
| `options`           | no       | defaults of the rule options                                                                                         |
| `cwe`, `owasp`      | no       | e.g. `[200]`, `'A02:2025'`; shown as SARIF tags and in the report                                                    |

`defineRule()` checks the definition when your rule file is imported and throws with every problem
at once (`CONFIG_INVALID_RULE`).

### Input

`check` gets one input at a time; tell them apart by `input.kind`:

- `'response'`: a request with its response (`ResponseRecord`): `method`, `url`, `endpointKey`
  (the normalized `GET /users/:id`), `origin`, `resourceType` (`document`, `script`, `xhr`,
  `fetch`, …; `api` for `APIRequestContext` calls), `source` (`browser` or `api`), `status`,
  `requestHeaders`, `responseHeaders` (lowercase names) and `body` when `needsBody` asks for it.
- `'cookie-jar'`, `'storage'`, `'csp-violation'`: browser events (`BrowserEvent`), only for rules
  with `appliesTo.events`.

`appliesTo` selects the input:

- `resourceTypes` and `sources` filter responses; without them a rule sees every response in scope.
- `events: ['cookie-jar']` makes it an event rule; add `records: true` to also get responses.
- `outOfScope: true` also passes responses from origins outside the scan scope (never with a body),
  for example third-party scripts.

`ctx` has the resolved `options`, `severity`, `confidence`, `inScope(origin)`, `localDev` and
`isHttps`. Helpers in `playwright-security-scan/rules`: `getHeader(record, name)`,
`getHeaders(record, name, 'response' | 'request')`, `parseSetCookie(value)`, `decodeJwt(token)`
(no signature check) and `builtinRuleIds`.

### Findings

Return an array (empty when everything is fine). Each finding has:

- `subject`: what the finding is about, matching `scope` (an endpoint key, an origin, a cookie as
  `name@domain`, a storage key or an asset URL). The fingerprint is
  `custom.<name>|<scope>|<subject>`, so keep it free of values that change between runs.
- `message`: one line for the reports.
- `discriminator` (optional): tells apart two problems of the rule on one subject; never a value.
- `location` (optional): `origin` (default: the input's origin), `endpointKey`, `param`, `header`.
- `evidence` (optional, up to 3): `{ kind: 'header' | 'cookie' | 'body' | 'url' | 'storage' | 'event', name?, snippet }`.

The package adds the rule id, severity, confidence and scope, and redacts every snippet and the
message like for built-in rules: header evidence with `name: 'set-cookie'`, `cookie` or
`authorization` loses its values, and JWTs, secret patterns and long random strings are replaced
by short hashes. Still, do not copy body text into evidence when a fixed message would do.

## A second rule: script domains

Report every script that does not come from your own or an allowed domain:

```ts
import { defineRule } from 'playwright-security-scan/rules';

export const forbiddenScripts = defineRule({
  id: 'custom.script-domain',
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  scope: 'origin',
  appliesTo: { sources: ['browser'], resourceTypes: ['script'], outOfScope: true },
  options: { allowed: ['https://cdn.example.com'] },
  docs: {
    title: 'Script from a domain outside the allowed list',
    why: 'Every script runs with the rights of the page; the security team reviews each new domain.',
    fix: 'Serve the script from the CDN, or ask for the domain to be added to the list.',
  },
  check(input, ctx) {
    if (input.kind !== 'response') return [];
    if (ctx.inScope(input.origin)) return [];
    if ((ctx.options.allowed as string[]).includes(input.origin)) return [];
    return [{ subject: input.origin, message: `Script from ${input.origin}` }];
  },
});
```

## Testing a rule

`playwright-security-scan/rules` imports neither Playwright nor Node, so a rule can be tested in
any test runner. Keep a record of a response in a file and call `check`:

```ts
// security-rules.test.ts (Vitest, Jest, node:test, …)
import { readFileSync } from 'node:fs';
import type { ResponseRecord, RuleContext } from 'playwright-security-scan/rules';
import { requestId } from './security-rules';

const record = JSON.parse(readFileSync('fixtures/api-me.json', 'utf8')) as ResponseRecord;
const ctx = {
  options: { header: 'x-request-id' },
  severity: 'low',
  confidence: 'high',
} as RuleContext;

test('reports an API response without x-request-id', () => {
  expect(requestId.check({ ...record, responseHeaders: [] }, ctx)).toHaveLength(1);
  expect(requestId.check(record, ctx)).toEqual([]);
});
```

A record needs at least `kind: 'response'`, `source`, `method`, `url`, `endpointKey`, `origin`,
`resourceType`, `status`, `requestHeaders` and `responseHeaders`.

## Presets and settings

- `minimal` keeps only rules with `defaultConfidence: 'high'`; `strict` raises `info` to `low` and
  `low` with high confidence to `medium`, like for built-in rules.
- `rules['custom.<name>']` takes `'off'`, `'on'` or `{ severity, confidence, options }`. An option
  that the rule does not define, or a value of another type than its default, fails the config
  check. A key `custom.<name>` without that rule in `rules.custom` is `CONFIG_UNKNOWN_RULE`.

## The baseline

Findings of custom rules are accepted in `security-baseline.json` like any other: run `baseline`,
review the entries, set a `note` (and `until`), commit. When you remove a rule from `rules.custom`,
its baseline entries stay and are reported as switched off (`BASELINE_RULE_OFF`), not as errors.

## Errors

- `CONFIG_INVALID_RULE`, `CONFIG_DUPLICATE_RULE`: the definition or the list is wrong; the run
  does not start.
- `CUSTOM_RULE_ERROR`: `check` threw. The rule is off for the rest of that test, the tests pass and
  the result is `TOOL_ERROR` (exit code 3) with the rule id, the error and the line in your file.
- `CUSTOM_RULE_ASYNC`: `check` returned a promise; the rule is off for the rest of the run.

Keep rules pure: no state between calls and no I/O. A rule that remembers earlier responses gives
findings that depend on the order of the tests, and the fingerprints stop being stable.

Custom rules need a `pw-sec.config.ts` (or `.js`) or the second argument of `withSecurity()`; a
JSON file in `PW_SEC_CONFIG` cannot hold functions (`CONFIG_INVALID_TYPE`). See
[Troubleshooting](troubleshooting.md) for every code.
