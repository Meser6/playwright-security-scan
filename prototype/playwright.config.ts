// Prototype runner (WP-02). Not part of the package.
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  workers: 1,
  reporter: [['list'], ['json', { outputFile: 'results/report.json' }]],
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] }, testIgnore: /perf-chain/ },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, testIgnore: /perf-chain/ },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, testIgnore: /perf-chain/ },
    { name: 'perf-chain', use: { ...devices['Desktop Chrome'] }, testMatch: /perf-chain/ },
  ],
});
