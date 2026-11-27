// Commit, branch and build URL of the CI job, read from the environment (17-REQ-07).
// Source: playwright-performance-regression src/io/run-metadata.ts, readCiInfo (MIT, same author;
// D-08), without the provider field.
import type { CiInfo } from './shard-file.ts';

type Env = Readonly<Record<string, string | undefined>>;

/** Value of a variable, or null when it is not set or empty. */
function read(env: Env, name: string): string | null {
  const value = env[name];
  return value === undefined || value === '' ? null : value;
}

function first(env: Env, ...names: string[]): string | null {
  for (const name of names) {
    const value = read(env, name);
    if (value !== null) return value;
  }
  return null;
}

/** Joins the parts when every variable is set, otherwise null. */
function compose(env: Env, build: (values: string[]) => string, ...names: string[]): string | null {
  const values = names.map((name) => read(env, name));
  return values.every((v) => v !== null) ? build(values as string[]) : null;
}

const NONE: CiInfo = { commit: null, branch: null, buildUrl: null };

/** GitHub Actions, GitLab CI, Jenkins or Azure Pipelines; nulls elsewhere. */
export function readCiInfo(env: Env): CiInfo {
  if (env.GITHUB_ACTIONS === 'true') {
    return {
      commit: read(env, 'GITHUB_SHA'),
      branch: first(env, 'GITHUB_HEAD_REF', 'GITHUB_REF_NAME'),
      buildUrl: compose(
        env,
        ([server, repository, runId]) => `${server}/${repository}/actions/runs/${runId}`,
        'GITHUB_SERVER_URL',
        'GITHUB_REPOSITORY',
        'GITHUB_RUN_ID',
      ),
    };
  }
  if (env.GITLAB_CI === 'true') {
    return {
      commit: read(env, 'CI_COMMIT_SHA'),
      branch: read(env, 'CI_COMMIT_REF_NAME'),
      buildUrl: read(env, 'CI_JOB_URL'),
    };
  }
  if (read(env, 'JENKINS_URL') !== null) {
    return {
      commit: read(env, 'GIT_COMMIT'),
      branch: first(env, 'BRANCH_NAME', 'GIT_BRANCH'),
      buildUrl: read(env, 'BUILD_URL'),
    };
  }
  if (env.TF_BUILD === 'True') {
    return {
      commit: read(env, 'BUILD_SOURCEVERSION'),
      branch: read(env, 'BUILD_SOURCEBRANCHNAME'),
      buildUrl: compose(
        env,
        ([collection, project, buildId]) =>
          `${collection}${project}/_build/results?buildId=${buildId}`,
        'SYSTEM_COLLECTIONURI',
        'SYSTEM_TEAMPROJECT',
        'BUILD_BUILDID',
      ),
    };
  }
  return NONE;
}
