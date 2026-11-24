// header.* rules (06, chapter 4.1).
import { ruleManifest } from '../manifest/rules.ts';
import type { RuleManifest } from '../manifest/rules.ts';
import type { ResponseRecord } from '../types/index.ts';
import { headerFix } from './fix-snippets.ts';
import { finding, header, isJson } from './types.ts';
import type { BuiltInRule } from './types.ts';

const m = (id: string): RuleManifest => {
  const found = ruleManifest(id);
  if (found === undefined) throw new Error(`no manifest entry for ${id}`);
  return found;
};

const is2xx = (r: ResponseRecord): boolean => r.status >= 200 && r.status < 300;

const XCTO = m('header.xcto-missing');
export const xctoMissing: BuiltInRule = {
  id: XCTO.id,
  manifest: XCTO,
  appliesTo: { resourceTypes: ['document', 'script', 'stylesheet', 'xhr', 'fetch', 'api'] },
  check(input, ctx) {
    if (!('status' in input) || !is2xx(input)) return [];
    const type = header(input.responseHeaders, 'content-type');
    const relevant =
      ['document', 'script', 'stylesheet'].includes(input.resourceType) || isJson(type);
    if (!relevant) return [];
    const value = header(input.responseHeaders, 'x-content-type-options');
    if (value !== undefined && value.trim().toLowerCase() === 'nosniff') return [];
    return [
      finding(ctx, XCTO, {
        subject: input.origin,
        location: {
          origin: input.origin,
          endpointKey: input.endpointKey,
          header: 'x-content-type-options',
        },
        evidence: [
          {
            kind: 'header',
            name: 'x-content-type-options',
            snippet: value === undefined ? '(missing)' : ctx.redact.text(value),
          },
        ],
        message: `${input.endpointKey} (${input.resourceType}) has no "X-Content-Type-Options: nosniff".`,
      }),
    ];
  },
  docs: {
    title: XCTO.title,
    why: 'Without nosniff a browser may guess the type of a response and run text or JSON as a script or style (MIME sniffing), which helps XSS and data leaks.',
    fix: headerFix(
      'X-Content-Type-Options',
      'nosniff',
      'http.headers(h -> h.contentTypeOptions(withDefaults()))',
    ),
    falsePositives:
      'None known for HTML, scripts, styles and JSON. Accept it for legacy endpoints you cannot change.',
  },
};
