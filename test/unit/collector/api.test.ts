import { describe, expect, test } from 'vitest';
import { describeApiCall, wrapRequestContext } from '../../../src/collector/api.ts';
import type { ApiSink } from '../../../src/collector/api.ts';

function fakeContext() {
  const calls: string[] = [];
  const ctx = {
    fetch(url: string) {
      calls.push(`fetch ${url}`);
      return Promise.resolve({ marker: url });
    },
    get(url: string) {
      // Like Playwright: get() calls this.fetch() synchronously.
      return this.fetch(url);
    },
    post() {
      return Promise.reject(new Error('boom'));
    },
  };
  return { ctx, calls };
}

describe('APIRequestContext wrapping (15, chapter 3)', () => {
  test('15-REQ-02 wrapping is idempotent and a nested call is one call', async () => {
    const { ctx } = fakeContext();
    const pending = new Set<Promise<void>>();
    const sink = { pending, collector: { skipBody: () => undefined } } as unknown as ApiSink;
    expect(wrapRequestContext(ctx, () => sink)).toBe(true);
    expect(wrapRequestContext(ctx, () => sink)).toBe(false);
    await ctx.get('/a');
    expect(pending.size).toBeLessThanOrEqual(1);
  });

  test('15-REQ-03 the wrapped method returns the original promise, value and error', async () => {
    const { ctx } = fakeContext();
    const sink = {
      pending: new Set(),
      collector: { skipBody: () => undefined },
    } as unknown as ApiSink;
    const original = ctx.post;
    wrapRequestContext(ctx, () => sink);
    expect(ctx.post).not.toBe(original);
    await expect(ctx.post()).rejects.toThrow('boom');
    await expect(ctx.get('/x')).resolves.toEqual({ marker: '/x' });
  });

  test('outside a scanned test calls pass through untouched', async () => {
    const { ctx, calls } = fakeContext();
    wrapRequestContext(ctx, () => undefined);
    await ctx.get('/y');
    expect(calls).toEqual(['fetch /y']);
  });

  test('method and request headers of a call', () => {
    expect(describeApiCall('get', ['/x', { headers: { Origin: 'https://a.test', N: 1 } }])).toEqual(
      {
        method: 'GET',
        headers: [{ name: 'origin', value: 'https://a.test' }],
      },
    );
    expect(describeApiCall('fetch', ['/x', { method: 'patch' }])?.method).toBe('PATCH');
    expect(describeApiCall('fetch', [{ url: () => '/x', method: () => 'DELETE' }])?.method).toBe(
      'DELETE',
    );
    expect(describeApiCall('fetch', ['/x', { method: 'bad method' }])).toBeUndefined();
  });
});
