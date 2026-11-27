// Custom rules of the reference project (16-AC-01, 16-AC-02, 16-AC-06), switched on with
// SHOP_CUSTOM_RULES=1 (and SHOP_CUSTOM_THROW=1 for the broken one).
import { defineRule, getHeader, getHeaders } from 'playwright-security-scan/rules';

/** The example of the custom rules docs: every API response has a request id. */
export const requestId = defineRule({
  id: 'custom.request-id-missing',
  defaultSeverity: 'low',
  defaultConfidence: 'high',
  scope: 'endpoint',
  appliesTo: { sources: ['api', 'browser'], resourceTypes: ['api', 'xhr', 'fetch'] },
  options: { header: 'x-request-id' },
  docs: {
    title: 'API response without x-request-id',
    why: 'Without a request id incidents cannot be traced across services.',
    fix: 'Add the header in the gateway.',
    url: 'https://wiki.example.com/security/request-id',
  },
  check(record, ctx) {
    if (record.kind !== 'response') return [];
    if (getHeader(record, ctx.options.header as string) !== undefined) return [];
    return [{ subject: record.endpointKey, message: `No ${String(ctx.options.header)} header` }];
  },
});

/** Puts the Set-Cookie header of the login into its evidence: the package must redact it. */
export const loginCookies = defineRule({
  id: 'custom.login-cookies',
  defaultSeverity: 'info',
  defaultConfidence: 'high',
  scope: 'endpoint',
  appliesTo: { resourceTypes: ['api'] },
  docs: {
    title: 'Cookies set by the login',
    why: 'An inventory of the cookies the login sets.',
    fix: 'Nothing to fix.',
  },
  check(record) {
    if (record.kind !== 'response') return [];
    const cookies = getHeaders(record, 'set-cookie');
    if (cookies.length === 0) return [];
    return [
      {
        subject: record.endpointKey,
        message: `${cookies.length} cookies set`,
        evidence: cookies.map((value) => ({ kind: 'header', name: 'set-cookie', snippet: value })),
      },
    ];
  },
});

/** Throws on every response (16-AC-02). */
export const broken = defineRule({
  id: 'custom.broken',
  defaultSeverity: 'medium',
  defaultConfidence: 'high',
  scope: 'endpoint',
  docs: { title: 'Broken rule', why: 'Tests the error path.', fix: 'Fix the rule.' },
  check() {
    throw new Error('this custom rule fails on purpose');
  },
});
