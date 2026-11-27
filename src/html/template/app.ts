// Script of the HTML report (09-REQ-18): tabs, filters, sorting, search, deep links to tabs and
// copying. The content is rendered statically; the script only changes the order, visibility,
// parent and attributes of existing elements and the text of counters and the status region. It
// never builds elements from report data and never uses innerHTML. No dependencies.
// Adapted from the report script of playwright-performance-regression
// (src/html/template/app.ts, MIT, D-08).

type Direction = 'ascending' | 'descending';

const doc = document;
doc.documentElement.classList.add('js');

function all<T extends Element>(selector: string, root: ParentNode = doc): T[] {
  return Array.from(root.querySelectorAll<T>(selector));
}

const statusRegion = doc.getElementById('status');
function announce(text: string): void {
  if (statusRegion !== null) statusRegion.textContent = text;
}

function setHash(hash: string): void {
  history.replaceState(null, '', hash);
}

// ---------------------------------------------------------------------------------------------
// Tabs: ARIA tabs over the static navigation and panels

const tabList = doc.querySelector<HTMLElement>('[data-tabs]');
const tabLinks = tabList === null ? [] : all<HTMLAnchorElement>('a[data-tab]', tabList);
const panels = new Map<string, HTMLElement>();
for (const panel of all<HTMLElement>('[data-panel]')) {
  panels.set(panel.dataset['panel'] ?? '', panel);
}
const firstTab = tabLinks[0]?.dataset['tab'] ?? 'findings';
let currentTab = firstTab;

function reveal(bar: HTMLElement, link: HTMLElement): void {
  const left = link.offsetLeft;
  const right = left + link.offsetWidth;
  if (left < bar.scrollLeft) bar.scrollLeft = left;
  else if (right > bar.scrollLeft + bar.clientWidth) bar.scrollLeft = right - bar.clientWidth;
}

function selectTab(id: string, focus = false): void {
  if (!panels.has(id)) return;
  currentTab = id;
  for (const link of tabLinks) {
    const selected = link.dataset['tab'] === id;
    link.setAttribute('aria-selected', String(selected));
    link.tabIndex = selected ? 0 : -1;
    if (selected && focus) link.focus();
    if (selected && tabList !== null) reveal(tabList, link);
  }
  for (const [name, panel] of panels) panel.hidden = name !== id;
}

if (tabList !== null) {
  tabList.setAttribute('role', 'tablist');
  for (const link of tabLinks) {
    const id = link.dataset['tab'] ?? '';
    link.setAttribute('role', 'tab');
    link.setAttribute('aria-controls', `tab-${id}`);
    const panel = panels.get(id);
    panel?.setAttribute('role', 'tabpanel');
    panel?.setAttribute('aria-labelledby', link.id);
  }
  tabList.addEventListener('keydown', (event) => {
    const index = tabLinks.findIndex((l) => l.dataset['tab'] === currentTab);
    let next = -1;
    if (event.key === 'ArrowRight') next = (index + 1) % tabLinks.length;
    else if (event.key === 'ArrowLeft') next = (index - 1 + tabLinks.length) % tabLinks.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabLinks.length - 1;
    if (next < 0) return;
    event.preventDefault();
    const id = tabLinks[next]?.dataset['tab'] ?? firstTab;
    selectTab(id, true);
    setHash(`#tab=${id}`);
  });
}

/** The panel that holds an element. */
function panelOf(element: Element): string | null {
  return element.closest<HTMLElement>('[data-panel]')?.dataset['panel'] ?? null;
}

// ---------------------------------------------------------------------------------------------
// Findings table: filters, search and sorting on the data-* attributes of the rows

const table = doc.querySelector<HTMLTableElement>('#table-findings');
const bodies = table === null ? [] : Array.from(table.tBodies);
const tools = doc.querySelector<HTMLElement>('[data-for="table-findings"]');
const search = tools?.querySelector<HTMLInputElement>('input[type="search"]') ?? null;
const chips = tools === null ? [] : all<HTMLButtonElement>('button[data-f]', tools);
const selects = tools === null ? [] : all<HTMLSelectElement>('select[data-sel]', tools);
const counter = tools?.querySelector<HTMLElement>('[data-count]') ?? null;
const none = tools?.querySelector<HTMLElement>('[data-none]') ?? null;

/** Attribute of a row for a filter group. */
const ATTRIBUTE: Record<string, string> = {
  c: 'c',
  sev: 'sev',
  conf: 'conf',
  grp: 'grp',
  org: 'org',
};

/** Search text of a row: its cells and the test that first saw the finding. */
const searchText = new Map<HTMLTableSectionElement, string>();
for (const body of bodies) {
  const first = body.querySelector('.tl li.first .tt')?.textContent ?? '';
  searchText.set(body, `${body.rows[0]?.textContent ?? ''} ${first}`.toLowerCase());
}

function applyFilters(): void {
  const text = (search?.value ?? '').toLowerCase();
  const groups = new Map<string, Set<string>>();
  for (const chip of chips) {
    if (chip.getAttribute('aria-pressed') !== 'true') continue;
    const group = chip.dataset['f'] ?? '';
    const set = groups.get(group) ?? new Set<string>();
    set.add(chip.dataset['v'] ?? '');
    groups.set(group, set);
  }
  for (const sel of selects) {
    if (sel.value !== '') groups.set(sel.dataset['sel'] ?? '', new Set([sel.value]));
  }
  let shown = 0;
  for (const body of bodies) {
    let visible = (searchText.get(body) ?? '').includes(text);
    for (const [group, values] of groups) {
      const value = body.dataset[ATTRIBUTE[group] ?? group] ?? null;
      if (value === null || !values.has(value)) visible = false;
    }
    body.hidden = !visible;
    if (visible) shown++;
  }
  if (counter !== null) counter.textContent = `showing ${shown} of ${bodies.length}`;
  if (none !== null) none.hidden = shown > 0;
}

/** Resets every filter, then presses the given classification chips. */
function filterClasses(classes: readonly string[]): void {
  if (search !== null) search.value = '';
  for (const sel of selects) sel.value = '';
  for (const chip of chips) {
    const on = chip.dataset['f'] === 'c' && classes.includes(chip.dataset['v'] ?? '');
    chip.setAttribute('aria-pressed', String(on));
  }
  applyFilters();
}

for (const chip of chips) {
  chip.addEventListener('click', () => {
    chip.setAttribute('aria-pressed', String(chip.getAttribute('aria-pressed') !== 'true'));
    applyFilters();
  });
}
search?.addEventListener('input', applyFilters);
for (const sel of selects) sel.addEventListener('change', applyFilters);
for (const reset of tools === null ? [] : all<HTMLElement>('[data-reset]', tools)) {
  reset.addEventListener('click', () => filterClasses([]));
}

const NUMERIC: Record<string, string> = {
  sev: 'sv',
  conf: 'cv',
  occ: 'occ',
  tests: 'tn',
  cls: 'cr',
};

function sortText(body: HTMLTableSectionElement, column: string): string {
  const row = body.rows[0];
  if (row === undefined) return '';
  const cell = column === 'rule' ? row.querySelector('.rk .key') : row.querySelector('.subj .sv');
  return cell?.textContent ?? '';
}

if (table !== null) {
  const headers = all<HTMLTableCellElement>('th[data-sort]', table);
  let sorted: { column: string; direction: Direction } | null = null;
  for (const th of headers) {
    const column = th.dataset['sort'] ?? '';
    th.querySelector('button')?.addEventListener('click', () => {
      const textual = column === 'rule' || column === 'subject' || column === 'cls';
      const first: Direction = textual ? 'ascending' : 'descending';
      const direction: Direction =
        sorted?.column === column
          ? sorted.direction === 'ascending'
            ? 'descending'
            : 'ascending'
          : first;
      sorted = { column, direction };
      const sign = direction === 'ascending' ? 1 : -1;
      const order = (b: HTMLTableSectionElement): number => Number(b.dataset['o'] ?? '0');
      const attribute = NUMERIC[column];
      const rows = [...bodies].sort((a, b) => {
        if (attribute === undefined) {
          const x = sortText(a, column);
          const y = sortText(b, column);
          return (x < y ? -1 : x > y ? 1 : 0) * sign || order(a) - order(b);
        }
        const x = Number(a.dataset[attribute] ?? '0');
        const y = Number(b.dataset[attribute] ?? '0');
        return (x - y) * sign || order(a) - order(b);
      });
      for (const row of rows) table.appendChild(row);
      for (const h of headers) {
        if (h === th) h.setAttribute('aria-sort', direction);
        else h.removeAttribute('aria-sort');
      }
    });
  }
}

// ---------------------------------------------------------------------------------------------
// Rows: a click anywhere on a finding row opens or closes its details

function detailsOf(body: HTMLTableSectionElement): HTMLDetailsElement | null {
  return body.querySelector<HTMLDetailsElement>('details');
}

/** Shows or hides the details row of a finding; `open` forces a state. */
function toggleRow(body: HTMLTableSectionElement, open?: boolean): void {
  const details = detailsOf(body);
  if (details === null) return;
  const on = open ?? !details.open;
  details.open = on;
  body.rows[0]?.classList.toggle('sel', on);
  body.rows[1]?.classList.toggle('on', on);
}

// ---------------------------------------------------------------------------------------------
// Rule reference: the Why, Fix, False positives and references of a rule are rendered once; the
// details of a finding get a copy of that static block when they open (09, chapter 3.7)

const ruleDocs = new Map<string, HTMLElement>();
for (const block of all<HTMLElement>('.rdoc[data-rule]')) {
  ruleDocs.set(block.dataset['rule'] ?? '', block);
}

function fillRuleDocs(root: ParentNode): void {
  for (const placeholder of all<HTMLElement>('.rref[data-rule]', root)) {
    if (placeholder.dataset['filled'] !== undefined) continue;
    const block = ruleDocs.get(placeholder.dataset['rule'] ?? '');
    if (block === undefined) continue;
    const parts = all<HTMLElement>(':scope > .ds', block).map((p) => p.cloneNode(true));
    placeholder.replaceChildren(...parts);
    placeholder.dataset['filled'] = '';
  }
}

doc.addEventListener(
  'toggle',
  (event) => {
    const details = event.target;
    if (details instanceof HTMLDetailsElement && details.open) fillRuleDocs(details);
  },
  true,
);

// ---------------------------------------------------------------------------------------------
// Deep links: #tab=<id>

function route(hash: string): void {
  const match = /^#tab[=-]([a-z-]+)$/u.exec(hash);
  if (match === null) {
    // A link to an element inside a panel selects that panel.
    const target = hash.length > 1 ? doc.getElementById(decodeURIComponent(hash.slice(1))) : null;
    const id = target === null ? null : panelOf(target);
    if (id !== null) selectTab(id);
    const body = target?.closest('#table-findings > tbody');
    if (body instanceof HTMLTableSectionElement) toggleRow(body, true);
    else if (target instanceof HTMLDetailsElement) target.open = true;
    target?.scrollIntoView({ block: 'start' });
    return;
  }
  const id = match[1] ?? '';
  if (panels.has(id)) {
    selectTab(id);
    setHash(`#tab=${id}`);
  } else {
    selectTab(firstTab);
    announce('Tab not found in this report');
  }
}

doc.addEventListener('click', (event) => {
  const target = event.target as Element;
  const link = target.closest<HTMLAnchorElement>('a[href^="#"]');
  if (link === null) {
    const row = target.closest<HTMLTableRowElement>('#table-findings > tbody > tr:first-child');
    const body = row?.parentElement;
    if (row == null || !(body instanceof HTMLTableSectionElement)) return;
    if (target.closest('button, input, label, summary, select') !== null) return;
    toggleRow(body);
    return;
  }
  const hash = link.getAttribute('href') ?? '';
  const filter = link.dataset['filter'];
  if (filter !== undefined) {
    // A counter tile: the Findings tab filtered to its classes (09-REQ-17, item 3).
    event.preventDefault();
    selectTab('findings');
    setHash('#tab=findings');
    filterClasses(filter.split(' '));
    return;
  }
  if (link.closest('#table-findings > tbody > tr:first-child') !== null) {
    event.preventDefault();
    const body = link.closest('tbody');
    if (body !== null) toggleRow(body);
    return;
  }
  if (hash.startsWith('#tab-') || hash.startsWith('#cov-')) {
    event.preventDefault();
    if (hash.startsWith('#tab-')) {
      route(`#tab=${hash.slice(5)}`);
    } else {
      selectTab('coverage');
      setHash('#tab=coverage');
      doc.getElementById(hash.slice(1))?.scrollIntoView({ block: 'start' });
    }
  }
});
window.addEventListener('hashchange', () => route(location.hash));

// ---------------------------------------------------------------------------------------------
// Copy: the button copies the text of the element before it (fingerprint, baseline entry)

doc.addEventListener('click', (event) => {
  const button = (event.target as Element).closest<HTMLButtonElement>('[data-copy-prev]');
  const text = button?.previousElementSibling?.textContent ?? null;
  if (button == null || text === null) return;
  if (navigator.clipboard === undefined) {
    announce('Copying is not available here; select the text instead');
    return;
  }
  navigator.clipboard.writeText(text).then(
    () => announce('Copied'),
    () => announce('Copying failed; select the text instead'),
  );
});

// Controls that need the script are hidden in the static page.
for (const element of all<HTMLElement>('.js-only')) element.hidden = false;

// ---------------------------------------------------------------------------------------------
// Printing: details of blocking and expired findings open

let opened: HTMLDetailsElement[] = [];
window.addEventListener('beforeprint', () => {
  opened = all<HTMLDetailsElement>('details[data-v]:not([open])');
  for (const details of opened) details.open = true;
});
window.addEventListener('afterprint', () => {
  for (const details of opened) details.open = false;
  opened = [];
});

selectTab(firstTab);
if (location.hash !== '') route(location.hash);
