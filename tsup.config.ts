import { defineConfig } from 'tsup';

/** Library entry points (01, chapter 5). */
const entries = {
  config: 'src/entries/config.ts',
  fixture: 'src/entries/fixture.ts',
  reporter: 'src/entries/reporter.ts',
  rules: 'src/entries/rules.ts',
  test: 'src/entries/test.ts',
};

export default defineConfig([
  {
    entry: entries,
    format: ['esm'],
    dts: true,
    target: 'node22',
    platform: 'node',
    clean: false,
    sourcemap: false,
    splitting: true,
    treeshake: true,
    esbuildOptions(options) {
      options.charset = 'utf8';
    },
  },
  {
    entry: entries,
    format: ['cjs'],
    dts: true,
    target: 'node22',
    platform: 'node',
    clean: false,
    sourcemap: false,
    splitting: true,
    treeshake: true,
    esbuildOptions(options) {
      options.charset = 'utf8';
    },
  },
]);
