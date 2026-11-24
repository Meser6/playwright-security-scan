import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'test/projects/**'],
    // Own tests never retry: a flaky test is fixed, not retried.
    retry: 0,
    // A test timeout is a hang guard, not a performance limit (D-14).
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
