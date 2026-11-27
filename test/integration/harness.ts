// Harness for the integration projects in test/projects (modelled on the perf package): each project
// is copied to a temporary directory, with the built package and @playwright/test linked into its
// node_modules, and run with the user's Playwright CLI against the test app (BASE_URL). Needs
// `pnpm build` and the Chromium of the installed Playwright.
import { spawn } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { OutcomeFile, RunReport, TestAttachment } from '../../src/core/types/index.ts';
import { createAjv, validator } from '../contract/schemas.ts';
import { startTestApp } from '../app/server.ts';
import type { TestApp } from '../app/server.ts';

export const ROOT = join(import.meta.dirname, '../..');
const PROJECTS = join(ROOT, 'test/projects');
const RUNNER = join(ROOT, 'node_modules/@playwright/test/cli.js');
export const RUN_TIMEOUT = 300_000;

const ajv = createAjv();
const validReport = validator(ajv, 'run-report.schema.json');
const validOutcome = validator(ajv, 'outcome.schema.json');

function readJson<T>(path: string, validate: ReturnType<typeof validator>): T | null {
  if (!existsSync(path)) return null;
  const value: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!validate(value)) throw new Error(`${path} is invalid: ${JSON.stringify(validate.errors)}`);
  return value as T;
}

export interface TestResult {
  project: string;
  title: string;
  status: string;
  /** First line of the first error of a failed attempt, for assertion messages. */
  error?: string;
  /** The pw-sec-findings attachment, parsed; null when the test has none. */
  attachment: TestAttachment | null;
  /** The pw-perf-samples attachment of the perf package, parsed; null when none. */
  perf: { apiRequests: unknown[]; requests: unknown[] } | null;
}

export interface ProjectRun {
  status: number | null;
  output: string;
  dir: string;
  results: TestResult[];
  /** reports/pw-sec/report.json, validated against its schema; null when not written. */
  report: RunReport | null;
  /** reports/pw-sec/outcome.json, validated; null when not written. */
  outcome: OutcomeFile | null;
  /** security-baseline.json text, if any. */
  baseline: string | null;
}

export interface Harness {
  app: TestApp;
  copy(name: string): string;
  run(
    dir: string,
    options?: { env?: Record<string, string>; args?: string[] },
  ): Promise<ProjectRun>;
  close(): Promise<void>;
}

export async function startHarness(): Promise<Harness> {
  if (!existsSync(join(ROOT, 'dist/fixture.js'))) {
    throw new Error('The integration tests use the built package: run "pnpm build" first.');
  }
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), 'pw-sec-projects-')));
  const app = await startTestApp();
  let copies = 0;
  return {
    app,
    copy(name) {
      copies += 1;
      const dir = join(scratch, `${name} copy ${copies}`);
      cpSync(join(PROJECTS, name), dir, {
        recursive: true,
        filter: (path) => !/[\\/](node_modules|reports|test-results)$/u.test(path),
      });
      const type = process.platform === 'win32' ? 'junction' : 'dir';
      mkdirSync(join(dir, 'node_modules/@playwright'), { recursive: true });
      symlinkSync(
        join(ROOT, 'node_modules/@playwright/test'),
        join(dir, 'node_modules/@playwright/test'),
        type,
      );
      symlinkSync(ROOT, join(dir, 'node_modules/playwright-security-scan'), type);
      // The perf package, for the compatibility projects (01-AC-02, 15-AC-05).
      symlinkSync(
        realpathSync(join(ROOT, 'node_modules/playwright-performance-regression')),
        join(dir, 'node_modules/playwright-performance-regression'),
        type,
      );
      return dir;
    },
    run: (dir, options = {}) => runProject(dir, app, options),
    async close() {
      await app.close();
      rmSync(scratch, { recursive: true, force: true });
    },
  };
}

interface JsonSuite {
  suites?: JsonSuite[];
  specs?: {
    title: string;
    tests: {
      projectName: string;
      results: {
        status: string;
        error?: { message?: string };
        attachments: { name: string; body?: string; path?: string }[];
      }[];
    }[];
  }[];
}

function readResults(path: string): TestResult[] {
  if (!existsSync(path)) return [];
  const report = JSON.parse(readFileSync(path, 'utf8')) as { suites: JsonSuite[] };
  const results: TestResult[] = [];
  const walk = (suite: JsonSuite): void => {
    for (const spec of suite.specs ?? []) {
      for (const t of spec.tests) {
        for (const r of t.results) {
          const a = r.attachments.find((x) => x.name === 'pw-sec-findings');
          let attachment: TestAttachment | null = null;
          if (a?.body !== undefined) {
            attachment = JSON.parse(
              Buffer.from(a.body, 'base64').toString('utf8'),
            ) as TestAttachment;
          } else if (a?.path !== undefined) {
            attachment = JSON.parse(readFileSync(a.path, 'utf8')) as TestAttachment;
          }
          const p = r.attachments.find((x) => x.name === 'pw-perf-samples');
          const perf =
            p?.body === undefined
              ? null
              : (JSON.parse(Buffer.from(p.body, 'base64').toString('utf8')) as {
                  apiRequests: unknown[];
                  requests: unknown[];
                });
          results.push({
            project: t.projectName,
            title: spec.title,
            status: r.status,
            ...(r.error?.message === undefined ? {} : { error: r.error.message.split('\n')[0] }),
            attachment,
            perf,
          });
        }
      }
    }
    for (const child of suite.suites ?? []) walk(child);
  };
  for (const suite of report.suites) walk(suite);
  return results;
}

function runProject(
  dir: string,
  app: TestApp,
  options: { env?: Record<string, string>; args?: string[] },
): Promise<ProjectRun> {
  for (const old of ['reports', 'test-results', 'results.json']) {
    rmSync(join(dir, old), { recursive: true, force: true });
  }
  const clean = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => !name.startsWith('PW_SEC_') && !name.startsWith('PW_PERF_'),
    ),
  );
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [RUNNER, 'test', ...(options.args ?? [])], {
      cwd: dir,
      env: {
        ...clean,
        CI: '',
        NO_COLOR: '1',
        BASE_URL: app.url,
        HTTPS_URL: app.httpsUrl,
        ...options.env,
      },
    });
    let output = '';
    child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString()));
    child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString()));
    child.on('error', reject);
    child.on('close', (status) => {
      try {
        const baselineFile = join(dir, 'security-baseline.json');
        resolve({
          status,
          output,
          dir,
          results: readResults(join(dir, 'results.json')),
          report: readJson<RunReport>(join(dir, 'reports/pw-sec/report.json'), validReport),
          outcome: readJson<OutcomeFile>(join(dir, 'reports/pw-sec/outcome.json'), validOutcome),
          baseline: existsSync(baselineFile) ? readFileSync(baselineFile, 'utf8') : null,
        });
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  });
}

/** Every file under `dir` (recursively), for privacy checks (S-07). */
export function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...filesUnder(path));
    else out.push(path);
  }
  return out;
}
