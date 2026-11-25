import { describe, expect, test } from 'vitest';
import { checkRelease } from '../../../scripts/check-release.mjs';

const pkg = (version: string, extra: object = {}) => ({ version, ...extra });
const CHANGELOG =
  '# Changelog\n\n## [Unreleased]\n\n## [0.2.0-beta.1] - 2026-11-26\n\n- Wizard.\n\n## [0.2.0] - 2026-12-01\n\n- Stable.\n';

describe('release preconditions (13-REQ-10)', () => {
  test('a beta tag on both packages gives the next dist-tag and the notes', () => {
    const r = checkRelease('v0.2.0-beta.1', pkg('0.2.0-beta.1'), pkg('0.2.0-beta.1'), CHANGELOG);
    expect(r).toMatchObject({ ok: true, distTag: 'next', prerelease: true, notes: '- Wizard.' });
  });

  test('a stable tag gives latest', () => {
    expect(checkRelease('v0.2.0', pkg('0.2.0'), pkg('0.2.0'), CHANGELOG)).toMatchObject({
      ok: true,
      distTag: 'latest',
    });
  });

  test('mismatched versions, private packages, a missing section and bad tags are refused', () => {
    const r = checkRelease('v0.3.0', pkg('0.3.0', { private: true }), pkg('0.2.0'), CHANGELOG);
    if (r.ok) throw new Error('expected problems');
    const text = r.problems.join('\n');
    expect(text).toMatch(/private/);
    expect(text).toMatch(/create\/package\.json: version 0\.2\.0/);
    expect(text).toMatch(/no "## \[0\.3\.0\]" section/);
    expect(checkRelease('v0.2', pkg('0.2'), pkg('0.2'), CHANGELOG).ok).toBe(false);
    expect(
      checkRelease('v0.2.0-alpha.1', pkg('0.2.0-alpha.1'), pkg('0.2.0-alpha.1'), CHANGELOG).ok,
    ).toBe(false);
  });
});
