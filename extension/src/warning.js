// Interstitial for a navigation whose host hit the local reputation prefix
// set. Asks the service worker for the full check, then either continues to
// the page or shows the warning.
const params = new URLSearchParams(location.search);
const target = params.get('url') || '';
const card = document.getElementById('card');
let host = '';
try { host = new URL(target).hostname; } catch { /* invalid */ }

const send = msg => chrome.runtime.sendMessage(msg).then(r => { if (!r?.ok) throw new Error(r?.error || 'No response'); return r; });

function go() { location.replace(target); }

async function run() {
  if (!/^https?:/i.test(target) || !host) {
    card.dataset.state = 'error';
    document.getElementById('error').textContent = 'This address is not a website.';
    return;
  }
  document.title = `NullRoute — ${host}`;
  try {
    const r = await send({ type: 'repCheck', url: target });
    if (r.verdict !== 'listed') return go();
    document.getElementById('host').textContent = host;
    if (r.expression && r.expression !== host) document.getElementById('match').textContent = ` (via ${r.expression})`;
    document.title = 'Dangerous site blocked';
    card.dataset.state = 'danger';
    document.getElementById('back').focus();
  } catch {
    go(); // fail open: never strand someone because the check itself failed
  }
}

document.getElementById('back').addEventListener('click', () => {
  if (history.length > 1) history.back(); else location.replace('about:blank');
});
document.getElementById('proceed').addEventListener('click', async () => {
  await send({ type: 'repProceed', url: target }).catch(() => {});
  go();
});
run();
