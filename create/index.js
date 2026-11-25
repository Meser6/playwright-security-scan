#!/usr/bin/env node
// create-playwright-security-scan (11-REQ-02): `npm init
// playwright-security-scan`, `pnpm create …` and `yarn create …`. Installs the package as
// a dev dependency with the package manager of the project (found by its lockfile) and hands over
// to the wizard (the pw-sec binary without arguments, 11-REQ-01). It takes no arguments: the
// wizard is controlled by the terminal and PW_SEC_* variables. No dependencies, no shell, no network access of its own: only the package
// manager is started.
import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, dirname, join, resolve } from 'node:path';

const PKG = 'playwright-security-scan';
const PREFIX = `create-${PKG}: `;
const own = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

const LOCKFILES = [
  ['pnpm-lock.yaml', 'pnpm'],
  ['yarn.lock', 'yarn'],
  ['package-lock.json', 'npm'],
];

const INSTALL = {
  npm: ['install', '--save-dev'],
  pnpm: ['add', '--save-dev'],
  yarn: ['add', '--dev'],
};

function say(text) {
  process.stderr.write(`${PREFIX}${text}\n`);
}

/** Package manager of the project: lockfile, else the one running this command, else npm. */
function packageManager(cwd, env) {
  for (const [file, manager] of LOCKFILES) {
    if (existsSync(join(cwd, file))) return manager;
  }
  const agent = /^(npm|pnpm|yarn)\//u.exec(env.npm_config_user_agent ?? '');
  return agent?.[1] ?? 'npm';
}

/** Manager name of the JavaScript entry in npm_execpath (npm-cli.js, pnpm.cjs, yarn.js …). */
function execPathManager(execPath) {
  const name = basename(execPath ?? '');
  if (/^npm-cli\.[cm]?js$/u.test(name)) return 'npm';
  if (/^pnpm\.[cm]?js$/u.test(name)) return 'pnpm';
  if (/^yarn(?:-[\d.]+)?\.[cm]?js$/u.test(name)) return 'yarn';
  return null;
}

/** Runs a command without a shell; resolves with the exit code (128 + n for a signal). */
function run(command, args, cwd) {
  return new Promise((done) => {
    const child = spawn(command, args, { cwd, stdio: 'inherit', shell: false });
    // The terminal sends Ctrl+C to the child too; this process waits for its exit code.
    const ignore = () => undefined;
    process.on('SIGINT', ignore);
    process.on('SIGTERM', ignore);
    const finish = (code) => {
      process.off('SIGINT', ignore);
      process.off('SIGTERM', ignore);
      done(code);
    };
    child.on('error', (error) => {
      say(`could not start ${command}: ${error.message}`);
      finish(3);
    });
    child.on('exit', (code, signal) => {
      finish(code ?? (signal === 'SIGINT' ? 130 : signal === 'SIGTERM' ? 143 : 1));
    });
  });
}

/** The pw-sec binary of the package installed in the project, or null. */
function installedCli(cwd) {
  try {
    const require = createRequire(join(cwd, 'package.json'));
    const manifest = require.resolve(`${PKG}/package.json`);
    const bin = JSON.parse(readFileSync(manifest, 'utf8')).bin?.['pw-sec'];
    return typeof bin === 'string' ? resolve(dirname(manifest), bin) : null;
  } catch {
    return null;
  }
}

async function main() {
  const cwd = process.cwd();
  const args = process.argv.slice(2);
  if (args.length > 0) {
    say(
      `takes no arguments, got "${args.join(' ')}". The setup runs in a terminal; its variables are ` +
        'PW_SEC_LANG=<code>, PW_SEC_DRY_RUN=1 and PW_SEC_NO_TUTORIAL=1, e.g. ' +
        `PW_SEC_LANG=pl npm init ${PKG}.`,
    );
    return 3;
  }
  if (!existsSync(join(cwd, 'package.json'))) {
    say(`no package.json in ${cwd}. Run this command in the directory of your Playwright project.`);
    return 3;
  }
  if (installedCli(cwd) === null) {
    const manager = packageManager(cwd, process.env);
    const installArgs = [...INSTALL[manager], `${PKG}@${own.version}`];
    say(`installing ${PKG}@${own.version} with ${manager}: ${manager} ${installArgs.join(' ')}`);
    let code;
    if (execPathManager(process.env.npm_execpath) === manager) {
      // The JavaScript entry of the running package manager: works on every system.
      code = await run(process.execPath, [process.env.npm_execpath, ...installArgs], cwd);
    } else if (process.platform === 'win32') {
      // npm.cmd and friends cannot be started without a shell on Windows.
      say(`run "${manager} ${installArgs.join(' ')}", then "npm init ${PKG}" again.`);
      return 3;
    } else {
      code = await run(manager, installArgs, cwd);
    }
    if (code !== 0) {
      say(`the installation ended with exit code ${code}.`);
      return code === 130 || code === 143 ? code : 3;
    }
  }
  const cli = installedCli(cwd);
  if (cli === null) {
    say(
      `${PKG} is not resolvable from ${cwd} after the installation. Check the installation, then run "npm init ${PKG}" again.`,
    );
    return 3;
  }
  return run(process.execPath, [cli], cwd);
}

process.exitCode = await main();
