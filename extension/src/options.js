import { parseUserFilters } from './lib/userfilters.js';

const $ = id => document.getElementById(id);

async function send(msg) {
  const res = await chrome.runtime.sendMessage(msg);
  if (!res?.ok) throw new Error(res?.error || 'Something went wrong');
  return res;
}

let dirty = false;
function markDirty() {
  dirty = true;
  $('saveStatus').textContent = 'Unsaved changes';
}

function renderErrors(listEl, errors) {
  listEl.replaceChildren(...errors.map(e => {
    const li = document.createElement('li');
    li.textContent = e.line ? `Line ${e.line}: ${e.msg}` : e.msg;
    return li;
  }));
}

async function renderLists() {
  const status = await send({ type: 'getStatus', tabId: -1, url: '' });
  const container = $('lists');
  container.replaceChildren();
  for (const rs of status.rulesets) {
    const row = document.createElement('div');
    row.className = 'list';
    row.innerHTML = `
      <div class="name"><strong></strong><small></small><span class="err" hidden></span></div>
      <span class="rules"></span>
      <label class="switch"><input type="checkbox"><span class="track"></span></label>`;
    row.querySelector('strong').textContent = rs.name;
    row.querySelector('small').textContent = rs.description;
    row.querySelector('.rules').textContent = `${rs.rules.toLocaleString()} rules`;
    const input = row.querySelector('input');
    input.checked = rs.enabled;
    input.disabled = status.paused;
    input.setAttribute('aria-label', `Enable ${rs.name}`);
    input.addEventListener('change', async () => {
      const err = row.querySelector('.err');
      err.hidden = true;
      try {
        await send({ type: 'setRulesetEnabled', id: rs.id, enabled: input.checked });
      } catch (e) {
        input.checked = !input.checked;
        err.textContent = e.message;
        err.hidden = false;
      }
    });
    container.append(row);
  }
  const { available } = await send({ type: 'getAvailableRuleCount' });
  const meta = await fetch(chrome.runtime.getURL('rulesets/rulesets.json')).then(r => r.json());
  const built = new Date(meta.generatedAt);
  $('listsMeta').textContent =
    `Lists compiled ${built.toLocaleDateString(undefined, { dateStyle: 'medium' })}. ` +
    `Chrome can enable ${available.toLocaleString()} more static rules.` +
    (status.paused ? ' Blocking is paused — resume it from the toolbar popup.' : '');
}

const LABELS = {
  trackers: v => (v === 'aggressive' ? 'aggressive blocking' : 'standard blocking'),
  blockScripts: v => (v ? 'scripts blocked' : 'scripts allowed'),
  cookies: v => (v === 'block3p' ? 'cross-site cookies blocked' : 'cross-site cookies allowed'),
  fingerprinting: v => (v ? 'fingerprinting blocked' : 'fingerprinting allowed'),
  autoShred: v => (v ? 'forgotten on close' : 'kept on close'),
};

async function renderShields() {
  const status = await send({ type: 'getStatus', tabId: -1, url: '' });
  for (const el of document.querySelectorAll('[data-global]')) {
    const key = el.dataset.global;
    const v = status.globals[key];
    if (el.tagName === 'SELECT') el.value = v;
    else el.checked = key === 'cookies' ? v === 'block3p' : !!v;
  }
  const list = $('overrides');
  const entries = Object.entries(status.siteOverrides || {}).sort(([a], [b]) => a.localeCompare(b));
  list.replaceChildren(...(entries.length ? entries.map(([site, o]) => {
    const li = document.createElement('li');
    const code = document.createElement('code');
    code.textContent = site;
    const what = document.createElement('span');
    what.className = 'what';
    what.textContent = Object.entries(o).map(([k, v]) => LABELS[k]?.(v) ?? k).join(', ');
    const reset = document.createElement('button');
    reset.className = 'link';
    reset.textContent = 'Use defaults';
    reset.addEventListener('click', async () => { await send({ type: 'resetSite', site }); renderShields(); });
    li.append(code, what, reset);
    return li;
  }) : [Object.assign(document.createElement('li'), { className: 'empty', textContent: 'None yet. Change a site from the toolbar popup.' })]));
}

for (const el of document.querySelectorAll('[data-global]')) {
  el.addEventListener('change', async () => {
    const key = el.dataset.global;
    const value = el.tagName === 'SELECT' ? el.value : key === 'cookies' ? (el.checked ? 'block3p' : 'allow3p') : el.checked;
    try { await send({ type: 'setGlobalDefault', key, value }); } catch (e) { $('saveStatus').textContent = e.message; }
    renderShields();
  });
}

async function load() {
  const { allowlist = [], userFilters = '' } = await chrome.storage.local.get(['allowlist', 'userFilters']);
  $('allowlist').value = allowlist.join('\n');
  $('userFilters').value = userFilters;
  renderErrors($('filterErrors'), parseUserFilters(userFilters).errors);
  $('version').textContent = `Version ${chrome.runtime.getManifest().version}`;
  await renderLists();
  await renderShields();
}

$('allowlist').addEventListener('input', markDirty);
$('userFilters').addEventListener('input', () => {
  markDirty();
  renderErrors($('filterErrors'), parseUserFilters($('userFilters').value).errors);
});

$('save').addEventListener('click', async () => {
  $('save').disabled = true;
  try {
    const res = await send({
      type: 'saveSettings',
      allowlist: $('allowlist').value.split('\n'),
      userFilters: $('userFilters').value,
    });
    renderErrors($('allowErrors'), res.errors.filter(e => e.field === 'allowlist'));
    renderErrors($('filterErrors'), res.errors.filter(e => e.field === 'userFilters'));
    const { allowlist } = await chrome.storage.local.get('allowlist');
    $('allowlist').value = (allowlist || []).join('\n');
    const c = res.counts;
    dirty = false;
    $('saveStatus').textContent = res.errors.length
      ? 'Saved. Lines with errors were skipped.'
      : `Saved — ${c.domains} domains, ${c.patterns} URL patterns, ${c.selectors} hidden elements.`;
  } catch (e) {
    $('saveStatus').textContent = e.message;
  } finally {
    $('save').disabled = false;
  }
});

window.addEventListener('beforeunload', e => { if (dirty) e.preventDefault(); });

// Keep the page in sync when the picker or popup changes settings elsewhere.
chrome.storage.onChanged.addListener((changes) => {
  if (dirty) return;
  if (changes.userFilters) $('userFilters').value = changes.userFilters.newValue || '';
  if (changes.allowlist) $('allowlist').value = (changes.allowlist.newValue || []).join('\n');
  if (changes.paused || changes.enabledRulesets) renderLists();
  if (changes.globalDefaults || changes.siteOverrides) renderShields();
});

load().catch(e => { $('saveStatus').textContent = e.message; });
