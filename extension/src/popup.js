const $ = id => document.getElementById(id);
const root = document.querySelector('.popup');

const SEGMENTS = [
  { id: 'ads', label: 'Ads', color: 'var(--seg-ads)' },
  { id: 'privacy', label: 'Trackers', color: 'var(--seg-privacy)' },
  { id: 'hosts', label: 'Bad hosts', color: 'var(--seg-hosts)' },
  { id: 'custom', label: 'My filters', color: 'var(--seg-custom)' },
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
    const n = counts[seg.id] || 0;
    if (n > 0) {
      const span = document.createElement('span');
      span.style.background = seg.color;
      span.style.flexGrow = String(n);
      span.title = `${seg.label}: ${n}`;
      bar.append(span);
    }
    const li = document.createElement('li');
    const on = seg.id === 'custom' || enabled.has(seg.id);
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
