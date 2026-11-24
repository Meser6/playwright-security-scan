# Prototype results (WP-02)

Checks of the Playwright APIs the collector relies on, run with `@playwright/test` 1.57.0 on
Chromium, Firefox and WebKit: in CI on `ubuntu-24.04` and `windows-latest`, and locally on macOS
(Chromium and WebKit; Firefox 1497 does not start on the development machine). The checks are in
`verify.spec.ts` and `perf-chain.spec.ts`; `server.mjs` serves the pages over HTTP and HTTPS
(self-signed certificate in `certs/`, test only).

| Check | Spec                 | Result                                                               |
| ----- | -------------------- | -------------------------------------------------------------------- |
| V-01  | 05-REQ-08            | Pass on all browsers, see notes 1 and 2                              |
| V-02  | 05-REQ-09            | Pass on all browsers                                                 |
| V-02b | 05-REQ-09            | Pass: the expected error, see note 3                                 |
| V-03  | Q-05, 05-REQ-26      | Pass on all browsers: `serverAddr()` is `null` for `route.fulfill()` |
| V-04  | 05-REQ-20            | Pass on all browsers, see note 4                                     |
| V-05  | 05-REQ-23            | Pass on all browsers                                                 |
| V-06  | 15-REQ-02, 01-REQ-09 | Pass in both orders of the fixture chain                             |
| V-07  | —                    | Pass on all browsers, see note 5                                     |

## Notes

1. **`Response.headersArray()` of a browser response is asynchronous** (returns a promise);
   `APIResponse.headersArray()` is synchronous. Both keep every `set-cookie` header as a
   separate entry. `allHeaders()` joins repeated `set-cookie` values with `\n`.
2. Header names keep the case the browser reports, and it differs: Chromium and Firefox give
   `set-cookie` and `Date`, WebKit gives `Set-Cookie`. Lower-casing names (05-REQ-08) is required.
3. `response.body()` while or after the context closes rejects with
   `response.body: Target page, context or browser has been closed` on all browsers. Bodies must
   be read before the base `context` fixture closes the context, so the `context` override waits
   for the read queue in its teardown (as the perf package drains); a body that is still
   unread then becomes `BODY_READ_FAILED` (05-REQ-09).
4. A listener on `document` added with `addInitScript` and reported through `exposeBinding`
   receives `securitypolicyviolation` for enforced and report-only policies
   (`disposition` `enforce` / `report`, `effectiveDirective`, `blockedURI` = `inline` for
   inline scripts). Firefox also reports the browser's own `favicon.ico` request blocked by
   `img-src`; such events are noise for `browser.csp-violation`.
5. `securityDetails()` works with a self-signed certificate and `ignoreHTTPSErrors`. The
   protocol text differs: `TLS 1.3` (Chromium, Firefox, WebKit on macOS and Windows) and
   `TLSv1.3` (WebKit on Linux); `issuer` is missing on WebKit on Linux. `transport.weak-tls`
   must accept both forms. `APIResponse` has no `securityDetails()` (15, chapter 5).

## V-06 in detail

A wrapper of the `request` methods with its own `WeakSet` and nesting counter (the pattern of the
perf package) was layered with `withPerfFixtures()` of the perf package (`PW_PERF_MODE=test`), as
the inner and as the outer fixture. For `get`, `fetch` and `post` the wrapper saw each call once,
the perf attachment had one API sample per call, and results were unchanged.
