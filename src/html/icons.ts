// Icons of the page (09, chapter 3.6): one hidden SVG sprite at the start of <body> with a <symbol>
// per icon, used through <use href="#i-…">. Line icons in currentColor; decorative, never the only
// carrier of a status (the text next to them says it), so every use is aria-hidden.
// Copied from playwright-performance-regression (src/html/icons.ts, MIT, D-08); the logo is a
// shield instead of the stopwatch, and the globe and copy icons are new.
import { trustedHtml } from './escape.ts';
import type { SafeHtml } from './escape.ts';

const SYMBOLS = {
  ok: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12.5 2.5 2.5 4.5-5"/>',
  bad: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6m0-6-6 6"/>',
  warn: '<path d="M10.3 4.2 2.6 17.6A2 2 0 0 0 4.3 20.6h15.4a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0z"/><path d="M12 10v4m0 3h.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5m0-8h.01"/>',
  bulb: '<path d="M9 18h6m-5 3h4M12 3a6 6 0 0 0-3.6 10.8c.7.5 1.1 1.3 1.1 2.1V16h5v-.1c0-.8.4-1.6 1.1-2.1A6 6 0 0 0 12 3z"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  l: '<path d="m15 6-6 6 6 6"/>',
  r: '<path d="m9 6 6 6-6 6"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  dl: '<path d="M12 4v11m-5-5 5 5 5-5M5 20h14"/>',
  mute: '<path d="M9 4.6A6 6 0 0 1 18 9c0 3 .7 5 1.5 6.5M6.3 6.3C6.1 7.1 6 8 6 9c0 5-2 7-2 7h12M10 20a2 2 0 0 0 4 0M3 3l18 18"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  branch:
    '<circle cx="6" cy="18" r="2.5"/><circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="8" r="2.5"/><path d="M6 8.5v7M18 10.5c0 4-4 5-9.5 6.5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  env: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  play: '<path d="M7 5v14l11-7z"/>',
  inbox: '<path d="M3 13h5l1.5 3h5l1.5-3h5M5.5 5h13L21 13v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-5z"/>',
  globe:
    '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
} as const;

export type IconName = keyof typeof SYMBOLS;

/** Ids of the symbols in the sprite, for the check that every <use> points to one. */
export const ICON_NAMES = Object.keys(SYMBOLS) as IconName[];

/** The hidden sprite with every icon of the page. */
export function iconSprite(): SafeHtml {
  const symbols = ICON_NAMES.map(
    (name) => `<symbol id="i-${name}" viewBox="0 0 24 24">${SYMBOLS[name]}</symbol>`,
  ).join('');
  return trustedHtml(
    `<svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false">${symbols}</svg>`,
  );
}

/** A 16 px line icon from the sprite, hidden from assistive technology. */
export function icon(name: IconName): SafeHtml {
  return trustedHtml(`<svg class="i" aria-hidden="true"><use href="#i-${name}"/></svg>`);
}

/** Shapes of the logo: a shield with a check mark, drawn like the stopwatch of the perf logo. */
const SHIELD = 'M12 2.5 4.5 5.5v6c0 4.6 3.2 8.4 7.5 10 4.3-1.6 7.5-5.4 7.5-10v-6z';
const CHECK = 'm8.5 12 2.5 2.5 4.5-5';

/** The logo of the app bar: colors come from the theme tokens in styles.css. */
export function logo(): SafeHtml {
  return trustedHtml(
    `<svg class="logo" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path class="shield" d="${SHIELD}"/><path class="bars" d="${CHECK}"/></svg>`,
  );
}

/**
 * The logo as the favicon, a data: URI. A data: image cannot see the tokens of the page, so it has
 * the accent color of the light theme.
 */
export const FAVICON_URI = `data:image/svg+xml,${encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"><path d="${SHIELD}" fill="#4f46e5" stroke="#4f46e5"/><path d="${CHECK}" stroke="#fff"/></svg>`,
)}`;
