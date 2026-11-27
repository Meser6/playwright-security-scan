// Attack templates of the worker (19-REQ-03, 19 chapter 11a): which records give one, without
// credentials, with redacted bodies, and the shared pw-sec-templates attachment.
import { describe, expect, test } from 'vitest';
import {
  AttackTemplateCollector,
  templatesAttachmentBody,
} from '../../../src/collector/templates.ts';
import { resolveConfig } from '../../../src/core/config/index.ts';
import { Redactor } from '../../../src/core/fingerprint/index.ts';
import type { ResponseRecord } from '../../../src/core/types/index.ts';

const APP = 'https://localhost:4430';
const ctx = { testId: 't', titlePath: ['t'], file: 'a.spec.ts', line: 1, project: 'customer' };

function collector(methods?: ('GET' | 'POST')[]): AttackTemplateCollector {
  const resolved = resolveConfig({
    attack: { allowedOrigins: [APP], ...(methods === undefined ? {} : { methods }) },
  });
  if (!resolved.ok) throw new Error('config');
  return new AttackTemplateCollector({
    config: resolved.config,
    test: ctx,
    redactor: new Redactor({ salt: 'salt' }),
  });
}

const record = (o: Partial<ResponseRecord>): ResponseRecord => ({
  kind: 'response',
  id: 1,
  source: 'browser',
  method: 'GET',
  url: `${APP}/search?q=tea`,
  endpointKey: 'GET /search?q',
  origin: APP,
  resourceType: 'document',
  isNavigation: true,
  requestHeaders: [
    { name: 'accept', value: 'text/html' },
    { name: 'cookie', value: 'sid=B0bS3ss10nV4lue5Kd9WmQr' },
    { name: 'authorization', value: 'Bearer abc.def.ghi' },
  ],
  status: 200,
  responseHeaders: [],
  context: ctx,
  ...o,
});

describe('attack templates (19-REQ-03)', () => {
  test('methods of attack.methods, allowed origins, status < 400, no credentials', () => {
    const c = collector(['GET', 'POST']);
    c.add(record({}), null);
    c.add(record({ url: `${APP}/search?q=x`, status: 200 }), null); // same key: the first wins
    c.add(record({ endpointKey: 'GET /gone', url: `${APP}/gone`, status: 404 }), null);
    c.add(
      record({
        endpointKey: 'GET /p',
        url: 'https://127.0.0.1:4431/p',
        origin: 'https://127.0.0.1:4431',
      }),
      null,
    );
    c.add(record({ endpointKey: 'GET /logout', url: `${APP}/logout` }), null);
    c.add(record({ endpointKey: 'GET /cb?token', url: `${APP}/cb?token=abc` }), null);
    c.add(
      record({ endpointKey: 'GET /app.js', url: `${APP}/app.js`, resourceType: 'script' }),
      null,
    );
    c.add(
      record({
        method: 'POST',
        endpointKey: 'POST /api/login',
        url: `${APP}/api/login`,
        resourceType: 'fetch',
        status: 303,
        requestHeaders: [{ name: 'content-type', value: 'application/json' }],
      }),
      JSON.stringify({ email: 'bob@shop.example', password: 'Hunter2!' }),
    );
    const list = c.list();
    expect(list.map((t) => t.endpointKey)).toEqual(['GET /search?q', 'POST /api/login']);
    expect(list[0]?.headers).toEqual([{ name: 'accept', value: 'text/html' }]);
    expect(list[0]?.url).toBe(`${APP}/search?q=tea`);
    const body = JSON.parse(list[1]?.body ?? '{}');
    expect(body.password).toBe('[redacted]');
    expect(JSON.stringify(list)).not.toContain('B0bS3ss10n');
    expect(JSON.stringify(list)).not.toContain('Hunter2');
    expect(JSON.stringify(list)).not.toContain('bob@shop.example');
  });

  test('POST is not taken with the default methods; a dropped body drops its content type', () => {
    const c = collector();
    c.add(record({ method: 'POST', endpointKey: 'POST /x', url: `${APP}/x` }), 'a=1');
    expect(c.list()).toEqual([]);
    const all = collector(['POST']);
    all.add(
      record({
        method: 'POST',
        endpointKey: 'POST /upload',
        url: `${APP}/upload`,
        requestHeaders: [{ name: 'content-type', value: 'multipart/form-data; boundary=x' }],
      }),
      '--x--',
    );
    expect(all.list()[0]?.body).toBeUndefined();
    expect(all.list()[0]?.headers).toEqual([]);
  });

  test('one attachment for both lists, truncated to 512 KB longest first', () => {
    const c = collector();
    c.add(record({}), null);
    const doc = JSON.parse(templatesAttachmentBody([], c.list())?.body ?? '{}');
    expect(doc).toMatchObject({ schemaVersion: 1, templates: [] });
    expect(doc.attack).toHaveLength(1);
    expect(templatesAttachmentBody([], [])).toBeNull();
    const big = Array.from({ length: 40 }, (_, i) => ({
      ...(c.list()[0] as NonNullable<ReturnType<typeof c.list>[number]>),
      endpointKey: `GET /k${String(i)}`,
      body: 'x'.repeat(20_000 + i),
    }));
    const out = templatesAttachmentBody([], big);
    expect(out?.attackTruncated).toBe(true);
    expect(out?.authzTruncated).toBe(false);
    expect(Buffer.byteLength(out?.body ?? '')).toBeLessThanOrEqual(512 * 1024);
  });
});
