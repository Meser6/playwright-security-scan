// Date and count formatting of the HTML report: fixed, locale-independent and without the time
// zone of the machine. Copied from playwright-performance-regression (src/html/format.ts, MIT,
// D-08), the parts the security report uses.

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

/** `YYYY-MM-DD HH:mm:ss UTC`; text that is not a date is returned unchanged. */
export function formatDate(iso: string): string {
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return iso;
  const d = new Date(time);
  return (
    `${String(d.getUTCFullYear())}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`
  );
}

/** Wall-clock duration of the run: `1 h 02 min`, `12 min 03 s` or `45 s`; `—` when unknown. */
export function formatRunDuration(startedAt: string, finishedAt: string): string {
  const ms = Date.parse(finishedAt) - Date.parse(startedAt);
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const total = Math.round(ms / 1000);
  const h = Math.floor(total / 3600);
  const min = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${String(h)} h ${pad(min)} min`;
  if (min > 0) return `${String(min)} min ${pad(s)} s`;
  return `${String(s)} s`;
}

/** `n word` with a plural `s` (or the given plural form). */
export function plural(n: number, word: string, many = `${word}s`): string {
  return `${String(n)} ${n === 1 ? word : many}`;
}
