import { availableParallelism } from 'node:os';
import { configDefaults, defineConfig } from 'vitest/config';

// Test files that start Playwright runs (test projects with up to 4 workers each) or browsers.
// Run side by side without a limit they overload the machine (a 4-core CI runner had up to
// 3 runs, ~10 browsers, at once) and tests in the projects time out at random. One run per
// 4 cores keeps the browsers within the cores; a timeout then means a real hang.
const PLAYWRIGHT_FILES = [
  'test/integration/**/*.test.ts',
  'test/quality/**/*.test.ts',
  'test/browser/**/*.test.ts',
];
const PLAYWRIGHT_RUNS = Math.max(1, Math.floor(availableParallelism() / 4));

const common = {
  exclude: [...configDefaults.exclude, 'test/projects/**'],
  // Own tests never retry: a flaky test is fixed, not retried.
  retry: 0,
  // A test timeout is a hang guard, not a performance limit (D-14).
  testTimeout: 60_000,
  hookTimeout: 120_000,
};

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          ...common,
          name: 'unit',
          sequence: { groupOrder: 0 },
          include: ['test/**/*.test.ts'],
          exclude: [...common.exclude, ...PLAYWRIGHT_FILES],
        },
      },
      {
        test: {
          ...common,
          name: 'playwright',
          sequence: { groupOrder: 1 },
          include: PLAYWRIGHT_FILES,
          maxWorkers: PLAYWRIGHT_RUNS,
        },
      },
    ],
  },
});
