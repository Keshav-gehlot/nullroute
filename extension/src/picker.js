// Element picker: hover to highlight, click to select, then confirm to hide
// that element (and anything matching the same selector) on this site.
// Injected on demand; all UI lives in a closed shadow root so the page can
// neither style nor script it.
(() => {
  if (window.__nullroutePicker) return;
  window.__nullroutePicker = true;

  const host = document.createElement('nullroute-picker');
  host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none;';
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = `
    <style>
      :host { all: initial; }
      .box { position: fixed; pointer-events: none; border: 2px solid #2f5bea;
             background: rgba(47,91,234,.14); border-radius: 3px; transition: all .06s ease-out; }
      .panel { position: fixed; right: 16px; bottom: 16px; width: 360px; pointer-events: auto;
               font: 13px/1.4 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
               color: #e5e7eb; background: #1b2333; border: 1px solid #2b354b; border-radius: 12px;
               box-shadow: 0 12px 40px rgba(0,0,0,.45); padding: 14px; }
      .title { font-weight: 600; display: flex; justify-content: space-between; align-items: center; }
      .hint { color: #9ca3af; margin: 6px 0 10px; }
      textarea { width: 100%; box-sizing: border-box; min-height: 56px; resize: vertical;
                 background: #121826; color: #c7d4ff; border: 1px solid #2b354b; border-radius: 8px;
                 font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; padding: 8px; }
      .row { display: flex; gap: 8px; margin-top: 10px; align-items: center; }
      .count { color: #9ca3af; flex: 1; font-size: 12px; }
      button { font: inherit; border: 0; border-radius: 8px; padding: 7px 12px; cursor: pointer; }
      .primary { background: #2f5bea; color: #fff; }
      .primary:disabled { opacity: .45; cursor: default; }
      .ghost { background: #1f2937; color: #e5e7eb; }
      .err { color: #fca5a5; font-size: 12px; margin-top: 6px; min-height: 1em; }
      kbd { font: 11px ui-monospace, monospace; background:#1f2937; padding:1px 5px; border-radius:4px; }
    </style>
    <div class="box" hidden></div>
    <div class="panel">
      <div class="title"><span>Block an element</span><button class="ghost close" title="Esc">✕</button></div>
      <div class="hint">Click the element to hide. <kbd>↑</kbd> selects the parent, <kbd>Enter</kbd> blocks, <kbd>Esc</kbd> cancels.</div>
      <textarea spellcheck="false" placeholder="Hover the page and click an element…"></textarea>
      <div class="row"><span class="count"></span>
        <button class="ghost cancel">Cancel</button><button class="primary block" disabled>Block</button></div>
      <div class="err"></div>
    </div>`;
  document.documentElement.appendChild(host);

  const box = root.querySelector('.box');
  const panel = root.querySelector('.panel');
  const input = root.querySelector('textarea');
  const count = root.querySelector('.count');
  const err = root.querySelector('.err');
  const blockBtn = root.querySelector('.block');
  let hovered = null;
  let selected = null;

  // ------------------------------------------------------------ selector generation
  const cssEscape = s => (window.CSS && CSS.escape ? CSS.escape(s) : s.replace(/[^a-zA-Z0-9_-]/g, '\\$&'));
  // Class/id names that look auto-generated (hashes, CSS-in-JS) change on every build.
  const looksRandom = s => /\d{3,}|[a-z]+-[a-zA-Z0-9]{5,}$|^[a-zA-Z0-9_-]{12,}$|^(css|sc|jsx|emotion)-/.test(s);

  function isUnique(sel) {
    try { return document.querySelectorAll(sel).length === 1; } catch { return false; }
  }

  function part(el) {
    if (el.id && !looksRandom(el.id)) return `#${cssEscape(el.id)}`;
    let p = el.localName;
    const classes = [...el.classList].filter(c => !looksRandom(c)).slice(0, 3);
    if (classes.length) p += classes.map(c => `.${cssEscape(c)}`).join('');
    const parent = el.parentElement;
    if (parent) {
      const same = [...parent.children].filter(c => c.localName === el.localName);
      if (same.length > 1 && !classes.length) p += `:nth-of-type(${same.indexOf(el) + 1})`;
    }
    return p;
  }

  function selectorFor(el) {
    const parts = [];
    for (let cur = el; cur && cur !== document.documentElement && parts.length < 6; cur = cur.parentElement) {
      parts.unshift(part(cur));
      const sel = parts.join(' > ');
      if (parts[0].startsWith('#') || isUnique(sel)) return sel;
    }
    return parts.join(' > ');
  }

  // ------------------------------------------------------------ UI
  function outline(el) {
    if (!el) { box.hidden = true; return; }
    const r = el.getBoundingClientRect();
    Object.assign(box.style, { left: `${r.left}px`, top: `${r.top}px`, width: `${r.width}px`, height: `${r.height}px` });
    box.hidden = false;
  }

  function refreshCount() {
    err.textContent = '';
    const sel = input.value.trim();
    if (!sel) { count.textContent = ''; blockBtn.disabled = true; return; }
    try {
      const n = document.querySelectorAll(sel).length;
      count.textContent = n === 1 ? '1 element matches' : `${n} elements match`;
      blockBtn.disabled = n === 0 || /[{}]/.test(sel);
      const first = document.querySelector(sel);
      outline(first);
    } catch {
      count.textContent = 'Invalid selector';
      blockBtn.disabled = true;
    }
  }

  function select(el) {
    selected = el;
    input.value = selectorFor(el);
    refreshCount();
  }

  const isOwn = e => e.composedPath().includes(host);

  function onMove(e) {
    if (selected || isOwn(e)) return;
    const el = document.elementFromPoint(e.clientX, e.clientY);
    if (el && el !== hovered && el !== host) { hovered = el; outline(el); }
  }
  function onClick(e) {
    if (isOwn(e)) return;
    e.preventDefault(); e.stopImmediatePropagation();
    if (hovered) select(hovered);
  }
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); stop(); }
    else if (e.key === 'Enter' && !e.shiftKey && selected && !blockBtn.disabled) {
      e.preventDefault(); blockBtn.click();
    }
    else if (e.key === 'ArrowUp' && selected?.parentElement && selected.parentElement !== document.body) {
      e.preventDefault(); select(selected.parentElement);
    }
  }
  const swallow = e => { if (!isOwn(e)) { e.preventDefault(); e.stopImmediatePropagation(); } };

  function stop() {
    document.removeEventListener('mousemove', onMove, true);
    document.removeEventListener('click', onClick, true);
    document.removeEventListener('keydown', onKey, true);
    for (const t of ['mousedown', 'mouseup', 'pointerdown', 'pointerup', 'auxclick', 'contextmenu']) {
      document.removeEventListener(t, swallow, true);
    }
    host.remove();
    window.__nullroutePicker = false;
  }

  document.addEventListener('mousemove', onMove, true);
  document.addEventListener('click', onClick, true);
  document.addEventListener('keydown', onKey, true);
  for (const t of ['mousedown', 'mouseup', 'pointerdown', 'pointerup', 'auxclick', 'contextmenu']) {
    document.addEventListener(t, swallow, true);
  }
  input.addEventListener('input', refreshCount);
  root.querySelector('.close').onclick = stop;
  root.querySelector('.cancel').onclick = () => {
    if (selected) { selected = null; input.value = ''; refreshCount(); outline(null); } else stop();
  };
  blockBtn.onclick = async () => {
    const selector = input.value.trim();
    blockBtn.disabled = true;
    try {
      const res = await chrome.runtime.sendMessage({ type: 'pickerBlock', selector });
      if (!res?.ok) throw new Error(res?.error || 'Failed');
      stop();
    } catch (e) {
      err.textContent = e.message;
      blockBtn.disabled = false;
    }
  };
  panel.addEventListener('mousemove', () => !selected && outline(null));
})();
