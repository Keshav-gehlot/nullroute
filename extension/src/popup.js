const $ = id => document.getElementById(id);
const root = document.querySelector('.popup');

// Each segment groups one or more rulesets (ids from rulesets.json).
const SEGMENTS = [
  { label: 'Ads', rulesets: ['ads', 'ublock', 'aggressive'], color: 'var(--seg-ads)' },
  { label: 'Trackers', rulesets: ['privacy', 'cname', 'cookies'], color: 'var(--seg-privacy)' },
  { label: 'Bad hosts', rulesets: ['hosts'], color: 'var(--seg-hosts)' },
  { label: 'Link tracking', rulesets: ['params'], color: 'var(--seg-params)' },
  { label: 'My filters', rulesets: ['custom'], color: 'var(--seg-custom)' },
];

let tab = null;
let status = null;

async function send(msg) {
  const res = await chrome.runtime.sendMessage(msg);
  if (!res?.ok) throw new Error(res?.error || 'Something went wrong');
  return res;
}

function showError(e) {
  $('error').textContent = e?.message || String(e || '');
  $('error').hidden = !e;
}

function render() {
  const s = status;
  const isWeb = !!s.host;
  $('host').textContent = isWeb ? s.site : 'This page';
  $('siteToggle').disabled = !isWeb || s.paused;
  $('siteToggle').checked = isWeb && !s.allowlisted && !s.paused;
  $('pauseToggle').checked = s.paused;
  $('picker').disabled = !isWeb || s.paused || s.allowlisted;
  $('brokenHint').hidden = !isWeb || s.paused || s.allowlisted;
  renderControls(s);

  let state = 'on';
  let text = 'Blocking ads and trackers';
  if (!isWeb) { state = 'idle'; text = 'NullRoute only runs on websites'; }
  else if (s.paused) { state = 'paused'; text = 'Paused everywhere'; }
  else if (s.allowlisted) { state = 'allowed'; text = 'Allowed — nothing is blocked here'; }
  root.dataset.state = state;
  $('status').textContent = text;

  const counts = s.counts || {};
  const total = s.counts ? Object.values(counts).reduce((a, b) => a + b, 0) : Number(s.badge) || 0;
  $('count').textContent = total.toLocaleString();

  const enabled = new Set(s.rulesets.filter(r => r.enabled).map(r => r.id));
  const bar = $('bar');
  bar.replaceChildren();
  const legend = $('legend');
  legend.replaceChildren();
  for (const seg of SEGMENTS) {
    const n = seg.rulesets.reduce((sum, id) => sum + (counts[id] || 0), 0);
    if (n > 0) {
      const span = document.createElement('span');
      span.style.background = seg.color;
      span.style.flexGrow = String(n);
      span.title = `${seg.label}: ${n}`;
      bar.append(span);
    }
    const li = document.createElement('li');
    const on = seg.rulesets.some(id => id === 'custom' || enabled.has(id));
    if (!on) li.className = 'off';
    const i = document.createElement('i');
    i.style.background = on ? seg.color : 'var(--line)';
    const label = document.createElement('span');
    label.textContent = seg.label;
    const b = document.createElement('b');
    b.textContent = on ? (s.counts ? n.toLocaleString() : '—') : 'off';
    li.append(i, label, b);
    legend.append(li);
  }
}

const SOURCE_TEXT = {
  blockScripts: ['Stops all JavaScript on this site'],
  cookies: ['Embedded trackers can\'t read or set cookies'],
  fingerprinting: ['Adds noise to canvas & audio readings'],
  autoShred: ['Clears cookies & storage when its last tab closes'],
};

function renderControls(s) {
  const adv = $('advanced');
  const usable = !!s.shields && !s.paused && !s.allowlisted;
  adv.setAttribute('aria-disabled', String(!usable));
  if (!s.shields) { $('advancedNote').textContent = ''; return; }
  const { effective, override } = s.shields;
  const overridden = Object.keys(override).filter(k => k !== 'site');
  $('advancedNote').textContent = overridden.length ? `${overridden.length} set for this site` : 'Using defaults';
  $('resetSite').hidden = !overridden.length;
  for (const btn of document.querySelectorAll('.segmented button')) {
    btn.setAttribute('aria-checked', String(effective[btn.dataset.key] === btn.dataset.value));
  }
  for (const input of document.querySelectorAll('.control input[data-key]')) {
    const key = input.dataset.key;
    input.checked = key === 'cookies' ? effective.cookies === 'block3p' : !!effective[key];
  }
  for (const small of document.querySelectorAll('small[data-source]')) {
    const key = small.dataset.source;
    const isSite = overridden.includes(key);
    small.textContent = isSite ? 'Changed for this site' : SOURCE_TEXT[key][0];
    small.classList.toggle('is-override', isSite);
  }
}

async function setControl(key, value) {
  showError(null);
  try {
    // Matching the global default removes the override instead of pinning it.
    const v = status.globals[key] === value ? null : value;
    await send({ type: 'setSiteControl', site: status.site, key, value: v });
    await chrome.tabs.reload(tab.id);
    await refresh();
  } catch (err) { showError(err); await refresh(); }
}

for (const btn of document.querySelectorAll('.segmented button')) {
  btn.addEventListener('click', () => setControl(btn.dataset.key, btn.dataset.value));
}
for (const input of document.querySelectorAll('.control input[data-key]')) {
  input.addEventListener('change', () => {
    const key = input.dataset.key;
    setControl(key, key === 'cookies' ? (input.checked ? 'block3p' : 'allow3p') : input.checked);
  });
}
$('resetSite').addEventListener('click', async () => {
  try {
    await send({ type: 'resetSite', site: status.site });
    await chrome.tabs.reload(tab.id);
    await refresh();
  } catch (err) { showError(err); }
});
$('shred').addEventListener('click', async () => {
  showError(null);
  try {
    $('shred').disabled = true;
    await send({ type: 'shredSite', site: status.site });
    $('shred').textContent = 'Site data forgotten';
    await chrome.tabs.reload(tab.id);
  } catch (err) { showError(err); } finally {
    setTimeout(() => { $('shred').disabled = false; $('shred').textContent = 'Forget site data'; }, 1500);
  }
});

async function refresh() {
  status = await send({ type: 'getStatus', tabId: tab.id, url: tab.url });
  render();
}

$('siteToggle').addEventListener('change', async e => {
  showError(null);
  try {
    await send({ type: 'setSiteAllowed', site: status.host, allowed: !e.target.checked });
    await chrome.tabs.reload(tab.id);
    await refresh();
  } catch (err) { showError(err); await refresh(); }
});

$('pauseToggle').addEventListener('change', async e => {
  showError(null);
  try {
    await send({ type: 'setPaused', paused: e.target.checked });
    await chrome.tabs.reload(tab.id);
    await refresh();
  } catch (err) { showError(err); await refresh(); }
});

$('picker').addEventListener('click', async () => {
  try {
    await send({ type: 'startPicker', tabId: tab.id });
    window.close();
  } catch (err) { showError(err); }
});

$('openOptions').addEventListener('click', e => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

(async () => {
  try {
    // ?tab=<id> lets the popup be opened as a page (used by the e2e tests).
    const forced = Number(new URLSearchParams(location.search).get('tab'));
    tab = forced ? await chrome.tabs.get(forced)
                 : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
    await refresh();
  } catch (err) { showError(err); }
})();
