#!/usr/bin/env node
// @ts-check
// Rule fixture coverage (10-REQ-01): every rule of the catalog has at least one positive and one
// negative record file in test/fixtures/records/<ruleId>/, and every fixture directory names a
// rule of the catalog. Uses Node's TypeScript type stripping (Node >= 22.18).
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const { BUILT_IN_RULES } = await import(pathToFileURL(join(root, 'src/core/rules/index.ts')).href);
const dir = join(root, 'test/fixtures/records');
const ids = new Set(BUILT_IN_RULES.map((/** @type {{ id: string }} */ r) => r.id));
const problems = [];
for (const id of [...ids].sort()) {
  for (const kind of ['positive', 'negative']) {
    const path = join(dir, id, kind);
    if (!existsSync(path) || readdirSync(path).filter((f) => f.endsWith('.json')).length === 0) {
      problems.push(`${id}: no ${kind} record in test/fixtures/records/${id}/${kind}/`);
    }
  }
}
for (const name of existsSync(dir) ? readdirSync(dir) : []) {
  if (!ids.has(name)) problems.push(`test/fixtures/records/${name}: no rule with this id`);
}
if (problems.length > 0) {
  for (const p of problems) console.error(`check-rule-fixtures: ${p}`);
  process.exit(1);
}
console.log(`check-rule-fixtures: ok, ${ids.size} rules with positive and negative records`);
