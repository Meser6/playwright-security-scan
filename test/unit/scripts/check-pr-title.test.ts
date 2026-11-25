import { describe, expect, it } from 'vitest';
import { checkPrTitle } from '../../../scripts/check-pr-title.mjs';

describe('checkPrTitle', () => {
  it('accepts a conventional title', () => {
    expect(checkPrTitle('feat(rules): add a cookie rule')).toEqual([]);
  });

  it('accepts Dependabot titles in the deps scope', () => {
    expect(checkPrTitle('build(deps): Bump @types/node from 22.20.5 to 26.6.6')).toEqual([]);
    expect(checkPrTitle('ci(deps): Bump the actions group with 2 updates')).toEqual([]);
  });

  it('still rejects a capitalised subject outside the deps scope', () => {
    expect(checkPrTitle('build(core): Bump something')).not.toEqual([]);
    expect(checkPrTitle('fix(deps): Update something')).not.toEqual([]);
  });
});
