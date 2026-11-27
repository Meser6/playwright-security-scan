// The package config file the wizard writes (11-REQ-08): at most 12 options, each with a short
// comment, every one an active value: the answers of steps 2 to 4 and the defaults. Values and
// defaults come from the package defaults, so the file never drifts from them. Pure.
import { DEFAULTS } from '../../core/config/index.ts';
import type { Preset } from '../../core/config/index.ts';
import type { Severity } from '../../core/types/index.ts';
import { DOCS_URL, PACKAGE_NAME } from '../constants.ts';

/** The answers of the wizard (steps 2 to 6; step IDs of 11, chapter 4). */
export interface InitAnswers {
  preset: Preset;
  minSeverity: Severity;
  /** Origins of step 4 (scope.origins). */
  origins: string[];
  /** The test command of step 6. */
  command: string;
  /** Run the check of step 8 (a terminal and step 6 not skipped). */
  runCheck: boolean;
}

export type ConfigFormat = 'ts' | 'esm' | 'cjs';

/** A value as TypeScript/JavaScript source. */
export function ts(value: unknown): string {
  if (typeof value === 'string') return `'${value.replace(/\\/gu, '\\\\').replace(/'/gu, "\\'")}'`;
  if (Array.isArray(value)) return `[${value.map(ts).join(', ')}]`;
  return String(value);
}

interface Option {
  key: string;
  value: unknown;
  default: unknown;
  comment: string;
}

interface Section {
  name: string;
  comment: string;
  options: Option[];
}

function sections(a: InitAnswers): Section[] {
  const d = DEFAULTS;
  return [
    {
      name: 'scope',
      comment: 'Which traffic is scanned.',
      options: [
        {
          key: 'origins',
          value: a.origins,
          default: d.scope.origins,
          comment: 'Origins scanned besides the use.baseURL origins, e.g. your API.',
        },
        {
          key: 'exclude',
          value: d.scope.exclude,
          default: d.scope.exclude,
          comment: 'Origins never scanned, even when they match.',
        },
        {
          key: 'projects',
          value: d.scope.projects,
          default: d.scope.projects,
          comment: "Playwright projects whose tests are scanned: 'all' or a list of names.",
        },
        {
          key: 'api',
          value: d.scope.api,
          default: d.scope.api,
          comment: 'Scan the calls of the request fixture (API tests).',
        },
      ],
    },
    {
      name: 'rules',
      comment: 'The passive rules; turn one off with rules: { "<rule id>": "off" }.',
      options: [
        {
          key: 'preset',
          value: a.preset,
          default: d.preset,
          comment: "'recommended', 'strict' (every rule, higher severities) or 'minimal'.",
        },
      ],
    },
    {
      name: 'gate',
      comment: 'Which new findings fail the scan; findings in the baseline never do.',
      options: [
        {
          key: 'minSeverity',
          value: a.minSeverity,
          default: d.gate.minSeverity,
          comment: 'Lowest severity of a new finding that fails the scan.',
        },
        {
          key: 'minConfidence',
          value: d.gate.minConfidence,
          default: d.gate.minConfidence,
          comment: 'Lowest confidence of a new finding that fails the scan.',
        },
        {
          key: 'failOnNoTraffic',
          value: d.gate.failOnNoTraffic,
          default: d.gate.failOnNoTraffic,
          comment: 'Fail when no response was in scope (a wrong scope scans nothing).',
        },
      ],
    },
    {
      name: 'baseline',
      comment: 'The baseline file you commit.',
      options: [
        {
          key: 'path',
          value: d.baseline.path,
          default: d.baseline.path,
          comment: 'Relative to the Playwright config.',
        },
        {
          key: 'requireNote',
          value: d.baseline.requireNote,
          default: d.baseline.requireNote,
          comment: 'Require a note on every accepted entry.',
        },
      ],
    },
    {
      name: 'report',
      comment: 'Reports of a run.',
      options: [
        {
          key: 'dir',
          value: d.report.dir,
          default: d.report.dir,
          comment:
            'Directory of report.html, report.json, results.sarif and junit.xml (do not commit it), relative to the Playwright config.',
        },
      ],
    },
  ];
}

/** Every option path the file sets, for tests (11-REQ-08: at most 12). */
export function configOptionPaths(a: InitAnswers): string[] {
  return sections(a).flatMap((s) => s.options.map((o) => `${s.name}.${o.key}`));
}

/** Words of `text` in comment lines of at most 97 characters with `indent`. */
function comment(text: string, indent: string): string[] {
  const lines: string[] = [];
  let line = '';
  for (const word of text.split(' ')) {
    const next = line === '' ? word : `${line} ${word}`;
    if (indent.length + 3 + next.length > 97 && line !== '') {
      lines.push(`${indent}// ${line}`);
      line = word;
    } else line = next;
  }
  if (line !== '') lines.push(`${indent}// ${line}`);
  return lines;
}

/** Text of pw-sec.config.* in `format` (11-REQ-08). */
export function renderSecConfig(a: InitAnswers, format: ConfigFormat): string {
  const head = [
    ...(format === 'ts' ? [] : ['// @ts-check']),
    `// Config of ${PACKAGE_NAME}. Every option: ${DOCS_URL}/configuration.md`,
    '// Objects are merged with the defaults; an array you set replaces the default one.',
    format === 'cjs'
      ? `const { defineSecurityConfig } = require('${PACKAGE_NAME}/config');`
      : `import { defineSecurityConfig } from '${PACKAGE_NAME}/config';`,
    '',
    format === 'cjs'
      ? 'module.exports = defineSecurityConfig({'
      : 'export default defineSecurityConfig({',
  ];
  const body: string[] = [];
  sections(a).forEach((section, index) => {
    if (index > 0) body.push('');
    body.push(...comment(section.comment, '  '), `  ${section.name}: {`);
    for (const o of section.options) {
      const changed = ts(o.value) !== ts(o.default);
      body.push(
        ...comment(changed ? `${o.comment} Default: ${ts(o.default)}.` : o.comment, '    '),
        `    ${o.key}: ${ts(o.value)},`,
      );
    }
    body.push('  },');
  });
  return `${[...head, ...body, '});'].join('\n')}\n`;
}
