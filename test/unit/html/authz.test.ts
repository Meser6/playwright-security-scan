// The Authorization tab of the HTML report (18-REQ-21): only with the authorization tests, a matrix
// of endpoints by role pair, a bypassed cell linking to its finding.
import { describe, expect, test } from 'vitest';
import { renderHtmlReport } from '../../../src/html/index.ts';
import { statesInput } from '../../browser/fixtures.ts';

describe('the Authorization tab (18-REQ-21)', () => {
  test('without the authorization tests there is no tab and the box says passive', () => {
    const page = renderHtmlReport(statesInput());
    expect(page).not.toContain('id="tab-authz"');
    expect(page).toContain('It is passive: it only looks at the traffic of your tests.');
  });

  test('with them: roles, budget, the matrix and a link to the finding', () => {
    const input = statesInput();
    const fingerprint = 'authz.horizontal|endpoint|GET /api/invoices/:id|customer->customer';
    input.report = {
      ...input.report,
      authz: {
        roles: [{ name: 'customer', projects: ['customer', 'customer2'], level: 0 }],
        templates: 4,
        replays: 3,
        budget: { maxRequests: 500, used: 3, exceeded: false },
        skipped: { 'no-credentials': 1 },
        matrix: [
          {
            endpointKey: 'GET /api/invoices/:id',
            from: 'customer',
            as: 'customer',
            result: 'bypassed',
            similarity: 0.97,
            fingerprint,
          },
          {
            endpointKey: 'GET /api/invoices/:id',
            from: 'customer',
            as: 'anonymous',
            result: 'enforced',
          },
          {
            endpointKey: 'GET /api/products/:id',
            from: 'customer',
            as: 'anonymous',
            result: 'public',
          },
        ],
      },
    };
    const page = renderHtmlReport(input);
    expect(page).toContain('id="tab-authz"');
    expect(page).toContain('customer → customer');
    expect(page).toContain(
      `href="#finding=${encodeURIComponent(fingerprint).replaceAll('&', '&amp;')}"`,
    );
    expect(page).toContain('bypassed · 0.97');
    expect(page).toContain('3 of 500 requests');
    expect(page).toContain('no-credentials 1');
    expect(page).toContain('authorization tests: GET/HEAD replays only');
  });
});
