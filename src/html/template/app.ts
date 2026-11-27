// Script of the HTML report (09-REQ-18): tabs, filters, sorting, search, the finding dialog
// (09-REQ-19), deep links (09-REQ-21) and copying. The content is rendered statically; the script only changes the order, visibility,
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
// Finding dialog (09-REQ-19): a native <dialog> opened with showModal(); the browser keeps the
// focus in it and makes the rest of the page inert. The details block of the row moves into it
// and back. Copied from the key dialog of the perf report (MIT, D-08).

/** Rows by fingerprint, compared exactly, never used as a selector (09-REQ-21). */
const byFingerprint = new Map<string, HTMLTableSectionElement>();
for (const body of bodies) byFingerprint.set(body.dataset['fp'] ?? '', body);

const dialog = doc.getElementById('finding-dialog') as HTMLDialogElement | null;
const dialogTitle = doc.getElementById('dlg-title');
const dialogPos = doc.getElementById('dlg-pos');
const dialogSlot = dialog?.querySelector<HTMLElement>('.dh-slot') ?? null;
const dialogBody = dialog?.querySelector<HTMLElement>('.db') ?? null;
const copyOut = dialog?.querySelector<HTMLElement>('.copy-out') ?? null;
const prevButton = dialog?.querySelector<HTMLButtonElement>('[data-act="prev"]') ?? null;
const nextButton = dialog?.querySelector<HTMLButtonElement>('[data-act="next"]') ?? null;
let current: {
  body: HTMLTableSectionElement;
  block: HTMLElement;
  head: HTMLElement | null;
  home: HTMLElement;
} | null = null;
let returnFocus: HTMLElement | null = null;

/** Puts the details block (and its header, moved into the dialog head) back in its row. */
function giveBack(): void {
  if (current === null) return;
  if (current.head !== null) current.block.prepend(current.head);
  current.home.appendChild(current.block);
  current.body.rows[0]?.classList.remove('sel');
  current = null;
}

function visibleRows(): HTMLTableSectionElement[] {
  return table === null ? [] : Array.from(table.tBodies).filter((b) => !b.hidden);
}

/** Shows the details of a finding row in the dialog; `deep` (a link) selects Findings first. */
function openFinding(body: HTMLTableSectionElement, from: HTMLElement | null, deep = false): void {
  const home = body.querySelector<HTMLElement>('details');
  const block = home?.querySelector<HTMLElement>('.kd');
  if (dialog === null || dialogBody === null || home === null || block == null) return;
  giveBack();
  if (from !== null) returnFocus = from;
  fillRuleDocs(block);
  const head = block.querySelector<HTMLElement>('.kh');
  if (head !== null) dialogSlot?.appendChild(head);
  dialogBody.appendChild(block);
  current = { body, block, head, home };
  body.rows[0]?.classList.add('sel');
  const rowsShown = visibleRows();
  const index = rowsShown.indexOf(body);
  const fingerprint = body.dataset['fp'] ?? '';
  if (dialogTitle !== null) {
    dialogTitle.textContent = `Finding ${head?.querySelector('.ft')?.textContent ?? ''}`;
  }
  if (dialogPos !== null) {
    dialogPos.textContent =
      index < 0 ? 'Finding' : `Finding ${String(index + 1)} of ${String(rowsShown.length)}`;
  }
  if (prevButton !== null) prevButton.disabled = index <= 0;
  if (nextButton !== null) nextButton.disabled = index < 0 || index >= rowsShown.length - 1;
  if (copyOut !== null) copyOut.hidden = true;
  if (deep) selectTab('findings');
  if (!dialog.open) {
    dialog.showModal();
    doc.documentElement.classList.add('modal-open');
  }
  dialog.scrollTop = 0;
  setHash(`#finding=${encodeURIComponent(fingerprint)}`);
  dialogTitle?.focus();
}

/** Closes the dialog; the `close` event gives the block back and restores the focus. */
let restoreOnClose = true;
function closeDialog(restoreFocus = true): void {
  if (dialog === null || !dialog.open) return;
  restoreOnClose = restoreFocus;
  giveBack();
  dialog.close();
}

dialog?.addEventListener('close', () => {
  giveBack();
  doc.documentElement.classList.remove('modal-open');
  if (restoreOnClose) {
    setHash(`#tab=${currentTab}`);
    returnFocus?.focus();
  }
  restoreOnClose = true;
  returnFocus = null;
});

function step(delta: number): void {
  if (current === null) return;
  const rowsShown = visibleRows();
  const next = rowsShown[rowsShown.indexOf(current.body) + delta];
  if (next !== undefined) openFinding(next, next.querySelector<HTMLElement>('a.kl'));
}

dialog?.addEventListener('click', (event) => {
  // A click on the backdrop targets the dialog itself (its content covers the whole box).
  if (event.target === dialog) {
    closeDialog();
    return;
  }
  const action = (event.target as Element).closest<HTMLElement>('[data-act]')?.dataset['act'];
  if (action === 'close') closeDialog();
  else if (action === 'prev') step(-1);
  else if (action === 'next') step(1);
});

// ---------------------------------------------------------------------------------------------
// Deep links (09-REQ-21): #tab=<id>, #finding=<encoded fingerprint>, anchors inside a panel

function route(hash: string, from: HTMLElement | null = null): void {
  let match = /^#tab[=-]([a-z-]+)$/u.exec(hash);
  if (match !== null) {
    closeDialog(false);
    const id = match[1] ?? '';
    if (panels.has(id)) {
      selectTab(id);
      setHash(`#tab=${id}`);
    } else {
      selectTab(firstTab);
      announce('Tab not found in this report');
    }
    return;
  }
  match = /^#finding=(.*)$/su.exec(hash);
  if (match !== null) {
    let fingerprint: string | null;
    try {
      fingerprint = decodeURIComponent(match[1] ?? '');
    } catch {
      fingerprint = null;
    }
    const body = fingerprint === null ? undefined : byFingerprint.get(fingerprint);
    if (body === undefined) {
      closeDialog(false);
      selectTab('findings');
      announce('Finding not found in this report');
      return;
    }
    openFinding(body, from, from === null);
    return;
  }
  // A link to an element inside a panel (the rule reference, a row anchor) selects that panel.
  let target: HTMLElement | null;
  try {
    target = hash.length > 1 ? doc.getElementById(decodeURIComponent(hash.slice(1))) : null;
  } catch {
    target = null;
  }
  if (target === null) return;
  const body = target.closest('#table-findings > tbody');
  if (body instanceof HTMLTableSectionElement) {
    openFinding(body, from, true);
    return;
  }
  closeDialog(false);
  const id = panelOf(target);
  if (id !== null) selectTab(id);
  for (
    let d = target.closest('details');
    d !== null;
    d = d.parentElement?.closest('details') ?? null
  ) {
    d.open = true;
  }
  target.scrollIntoView({ block: 'start' });
}

doc.addEventListener('click', (event) => {
  const target = event.target as Element;
  const link = target.closest<HTMLAnchorElement>('a[href^="#"]');
  if (link === null) {
    // A click anywhere on a finding row opens its details (09-REQ-19).
    const row = target.closest<HTMLTableRowElement>('#table-findings > tbody > tr:first-child');
    const body = row?.parentElement;
    if (row == null || !(body instanceof HTMLTableSectionElement)) return;
    if (target.closest('button, input, label, summary, select') !== null) return;
    openFinding(body, row.querySelector<HTMLElement>('a.kl'));
    return;
  }
  const hash = link.getAttribute('href') ?? '';
  const filter = link.dataset['filter'];
  if (filter !== undefined) {
    // A counter tile: the Findings tab filtered to its classes (09-REQ-17, item 3).
    event.preventDefault();
    closeDialog(false);
    selectTab('findings');
    setHash('#tab=findings');
    filterClasses(filter.split(' '));
    return;
  }
  if (hash.startsWith('#tab-')) {
    event.preventDefault();
    route(`#tab=${hash.slice(5)}`);
    return;
  }
  if (hash.length > 1) {
    event.preventDefault();
    route(hash, link);
  }
});
window.addEventListener('hashchange', () => route(location.hash));

// ---------------------------------------------------------------------------------------------
// Copy: the button copies the text of the element before it (fingerprint, baseline entry)

doc.addEventListener('click', (event) => {
  if ((event.target as Element).closest('[data-copy-link]') === null) return;
  const url = location.href;
  const fallback = (): void => {
    const input = copyOut?.querySelector('input');
    if (copyOut === null || input == null) return;
    copyOut.hidden = false;
    input.value = url;
    input.focus();
    input.select();
  };
  if (navigator.clipboard === undefined) {
    fallback();
    return;
  }
  navigator.clipboard.writeText(url).then(() => announce('Link copied'), fallback);
});

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
  closeDialog(false);
  opened = all<HTMLDetailsElement>('details[data-v]:not([open])');
  for (const details of opened) details.open = true;
});
window.addEventListener('afterprint', () => {
  for (const details of opened) details.open = false;
  opened = [];
});

selectTab(firstTab);
if (location.hash !== '') route(location.hash);
