import { describe, expect, test } from 'vitest';
import { Redactor } from '../../../src/core/fingerprint/index.ts';

const b64 = (o: object): string => Buffer.from(JSON.stringify(o)).toString('base64url');
const JWT = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: '42', exp: 2000000000 })}.c2lnbmF0dXJlLXNpZw`;
const SECRETS = {
  jwt: JWT,
  session: 'f3a9C2e81bD47a60e5c9',
  aws: 'AKIAIOSFODNN7EXAMPLE',
  github: 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789',
  bearer: 'kq83HfL2mZp0wq9YtR4x',
};

function assertNoSecret(text: string): void {
  for (const secret of Object.values(SECRETS)) expect(text).not.toContain(secret);
}

describe('redaction (07, chapter 5)', () => {
  const r = new Redactor({ salt: 'run-salt' });

  test('07-REQ-13 a JWT becomes eyJ…[jwt alg=… sha256:…]', () => {
    const out = r.text(`token is ${JWT} here`);
    expect(out).toMatch(/^token is eyJ…\[jwt alg=HS256 sha256:[0-9a-f]{6}\] here$/);
    assertNoSecret(out);
  });

  test('07-REQ-13 cookie values are redacted, attributes kept', () => {
    const out = r.header(
      'set-cookie',
      `session_id=${SECRETS.session}; Path=/; Secure; SameSite=Lax`,
    );
    expect(out).toMatch(
      /^session_id=\[redacted sha256:[0-9a-f]{6}\]; Path=\/; Secure; SameSite=Lax$/,
    );
    const cookie = r.header('Cookie', `a=${SECRETS.session}; theme=dark`);
    expect(cookie).toMatch(
      /^a=\[redacted sha256:[0-9a-f]{6}\]; theme=\[redacted sha256:[0-9a-f]{6}\]$/,
    );
    assertNoSecret(out + cookie);
  });

  test('07-REQ-13 authorization keeps the scheme only', () => {
    expect(r.header('authorization', `Bearer ${JWT}`)).toMatch(
      /^Bearer eyJ…\[jwt alg=HS256 sha256:/,
    );
    expect(r.header('authorization', `Bearer ${SECRETS.bearer}`)).toMatch(
      /^Bearer \[redacted sha256:[0-9a-f]{6}\]$/,
    );
    expect(r.header('x-api-key', 'abc')).toMatch(/^\[redacted sha256:/);
    expect(r.header('x-csrf-token', 'abc')).toMatch(/^\[redacted sha256:/);
    expect(r.header('content-type', 'text/html')).toBe('text/html');
  });

  test('07-REQ-13 secret pattern matches keep their first 4 characters', () => {
    const out = r.text(`const k = "${SECRETS.aws}"; const g = "${SECRETS.github}";`);
    expect(out).toContain('AKIA…[sha256:');
    expect(out).toContain('ghp_…[sha256:');
    assertNoSecret(out);
  });

  test('07-REQ-13 values of sensitive query parameters are redacted', () => {
    const out = r.text(`/callback?code=1&token=${SECRETS.session}&page=2`);
    expect(out).toMatch(/^\/callback\?code=1&token=\[redacted sha256:[0-9a-f]{6}\]&page=2$/);
    const custom = new Redactor({ salt: 's', paramNames: ['sig'] }).text('/x?sig=abcdef');
    expect(custom).toMatch(/sig=\[redacted sha256:/);
  });

  test('07-REQ-12 the final filter also catches long high-entropy strings', () => {
    const out = r.text(`{"value":"${SECRETS.session}x9Yq2"}`);
    assertNoSecret(out);
    expect(r.text('internationalization-settings-page')).toBe('internationalization-settings-page');
  });

  test('07-REQ-14 snippets keep 80 characters around the match, max 200, no control characters', () => {
    const text = `${'a'.repeat(300)}\nSECRET_LINE\u0007${'b'.repeat(300)}`;
    const index = text.indexOf('SECRET_LINE');
    const out = r.snippet(text, index, 'SECRET_LINE'.length);
    expect(out.length).toBeLessThanOrEqual(200);
    expect(out).toContain(' SECRET_LINE?');
    expect(out.startsWith('…')).toBe(true);
    expect(out.endsWith('…')).toBe(true);
  });

  test('07-REQ-15 hashes are salted per run: equal within a run, different across runs', () => {
    const a = new Redactor({ salt: 'run-a' });
    const b = new Redactor({ salt: 'run-b' });
    expect(a.value('x')).toBe(a.value('x'));
    expect(a.value('x')).not.toBe(b.value('x'));
  });

  test('07-REQ-12 enforce() runs every snippet and the message through the filter', () => {
    const finding = r.enforce({
      message: `JWT ${JWT} found`,
      evidence: [{ kind: 'body', snippet: `password=${SECRETS.session}` }],
    });
    assertNoSecret(JSON.stringify(finding));
  });

  test('redacting twice does not break placeholders', () => {
    const once = r.text(`a ${JWT} b`);
    expect(r.text(once)).toBe(once);
  });
});
