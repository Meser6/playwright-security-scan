// Absolute path of the reporter entry point that withSecurity() adds (01-REQ-07). The config and
// reporter entry points are siblings in dist/ (config.js/reporter.js, config.cjs/reporter.cjs);
// the same technique as the perf package.

function currentFile(): string {
  return typeof __filename === 'string' ? __filename : import.meta.filename;
}

/** The reporter entry point next to `file`, with the same extension. */
export function reporterPathNextTo(file: string): string {
  const cut = Math.max(file.lastIndexOf('/'), file.lastIndexOf('\\')) + 1;
  const name = file.slice(cut);
  const dot = name.lastIndexOf('.');
  return `${file.slice(0, cut)}reporter${dot === -1 ? '' : name.slice(dot)}`;
}

export function reporterEntryPath(): string {
  return reporterPathNextTo(currentFile());
}
