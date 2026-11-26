#!/usr/bin/env node
// @ts-check
// Generates docs/rules/<ruleId>.md, docs/rules/README.md and, when README.md has the markers, its rules table (between
// the markers) from the rule catalog and its manifest (13-REQ-07, 13-REQ-08). The output is
// committed. Uses Node's TypeScript type stripping (Node >= 22.18).
//
// Usage: node scripts/generate-docs.mjs [--check]
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as prettier from 'prettier';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const load = (/** @type {string} */ path) => import(pathToFileURL(join(root, path)).href);
const { BUILT_IN_RULES } = await load('src/core/rules/index.ts');
const { presetRule } = await load('src/core/config/resolve.ts');

/** @param {any} rule */
function presets(rule) {
  return ['minimal', 'recommended', 'strict']
    .filter((p) => presetRule(rule.manifest, p).enabled)
    .map(
      (p) =>
        `\`${p}\`${presetRule(rule.manifest, p).severity !== rule.manifest.defaultSeverity ? ` (${presetRule(rule.manifest, p).severity})` : ''}`,
    )
    .join(', ');
}

/** @param {any} rule */
function rulePage(rule) {
  const m = rule.manifest;
  const options = Object.entries(m.options);
  return [
    `# ${rule.id}`,
    '',
    `**${rule.docs.title}**`,
    '',
    '| | |',
    '|---|---|',
    `| Severity / confidence | ${m.defaultSeverity} / ${m.defaultConfidence} |`,
    `| Subject | ${m.scope} |`,
    `| Traffic | ${m.sources.join(', ')} |`,
    `| CWE | ${m.cwe.map((/** @type {number} */ n) => `[CWE-${n}](https://cwe.mitre.org/data/definitions/${n}.html)`).join(', ')} |`,
    `| OWASP Top 10 | ${m.owasp ?? '—'} |`,
    `| Presets | ${presets(rule)} |`,
    '',
    '## Why it matters',
    '',
    rule.docs.why,
    '',
    '## How to fix',
    '',
    rule.docs.fix,
    '',
    '## False positives',
    '',
    rule.docs.falsePositives,
    '',
    ...(options.length === 0
      ? []
      : [
          '## Options',
          '',
          '| Option | Default |',
          '|---|---|',
          ...options.map(
            ([k, v]) => `| \`${k}\` | \`${JSON.stringify(v).replaceAll('|', '\\|')}\` |`,
          ),
          '',
        ]),
    '## Accept or switch off',
    '',
    'Accept a finding after review: run `PW_SEC_MODE=baseline`, add a `note` (and optionally `until`) to its entry in `security-baseline.json` and commit. To switch the rule off or change its severity:',
    '',
    '```ts',
    `rules: { '${rule.id}': 'off' }  // or { severity: 'low' }${options.length > 0 ? `, or { options: { ${options[0]?.[0]}: … } }` : ''}`,
    '```',
    '',
    '_Generated from the rule catalog by `pnpm gen:docs`._',
    '',
  ].join('\n');
}

const table = [
  '| Rule | Severity | Confidence | Traffic | CWE |',
  '|---|---|---|---|---|',
  ...BUILT_IN_RULES.map(
    (/** @type {any} */ r) =>
      `| [\`${r.id}\`](docs/rules/${r.id}.md)${r.manifest.strictOnly ? ' (strict)' : ''} — ${r.docs.title} | ${r.manifest.defaultSeverity} | ${r.manifest.defaultConfidence} | ${r.manifest.sources.join(', ')} | ${r.manifest.cwe.join(', ')} |`,
  ),
].join('\n');

/** @type {[string, string][]} */
const outputs = [];
for (const rule of BUILT_IN_RULES)
  outputs.push([join(root, 'docs/rules', `${rule.id}.md`), rulePage(rule)]);
outputs.push([
  join(root, 'docs/rules/README.md'),
  `# Rules\n\n${BUILT_IN_RULES.length} passive rules; ${BUILT_IN_RULES.filter((/** @type {any} */ r) => !r.manifest.strictOnly).length} in the default \`recommended\` preset.\n\n${table.replaceAll('](docs/rules/', '](')}\n`,
]);
const readmePath = join(root, 'README.md');
const readme = readFileSync(readmePath, 'utf8');
const start = '<!-- rules:start -->';
const end = '<!-- rules:end -->';
if (readme.includes(start) && readme.includes(end)) {
  outputs.push([
    readmePath,
    `${readme.slice(0, readme.indexOf(start) + start.length)}\n\n${table}\n\n${readme.slice(readme.indexOf(end))}`,
  ]);
}

const formatted = await Promise.all(
  outputs.map(
    async ([file, text]) =>
      /** @type {[string, string]} */ ([
        file,
        await prettier.format(text, { ...(await prettier.resolveConfig(file)), filepath: file }),
      ]),
  ),
);
if (process.argv.includes('--check')) {
  const stale = formatted.filter(
    ([file, text]) => !existsSync(file) || readFileSync(file, 'utf8') !== text,
  );
  for (const [file] of stale)
    console.error(
      `check-docs-generated: ${relative(root, file)} is out of date; run \`pnpm gen:docs\``,
    );
  if (stale.length > 0) process.exit(1);
  console.log(`check-docs-generated: ${formatted.length} files up to date`);
} else {
  mkdirSync(join(root, 'docs/rules'), { recursive: true });
  for (const [file, text] of formatted) writeFileSync(file, text);
  console.log(`generate-docs: wrote ${formatted.length} files`);
}
