// Removes "please turn off your ad blocker" walls without relying on names.
// Copy of extension/src/antinag.js for the in-app browsers (Android and iOS), no chrome.* APIs.
//
// Anti-adblock scripts give their overlays random per-load ids and classes
// (e.g. <span id="epgr3ltl0n" class="giqad39tt">), so a filter written against
// one page load is useless on the next. This script recognises the wall by
// what it *is* instead: a fixed or absolutely positioned element covering most
// of the viewport whose text asks you to disable or allowlist an ad blocker.
// It removes that element and any empty full-screen backdrop beside it, and
// undoes the scroll lock and blur these walls apply to the page.
//
// It never touches elements without that text, so ordinary modals (cookie
// banners, newsletter pop-ups, login dialogs) are left alone. Runs in the
// extension's isolated world and only on sites that aren't paused/allowed.
(() => {
  if (window.__nullrouteAntinag) return;
  window.__nullrouteAntinag = true;

  const NAG = new RegExp([
    'ad[\\s-]?block', 'adblock', 'ad blocker', 'ad-blocker',
    'disable (?:your )?ad', 'turn off (?:your )?ad', 'deactivate (?:your )?ad', 'pause (?:your )?ad',
    'whitelist (?:this|our|us)', 'allow ?list (?:this|our|us)', 'add (?:us|this site) to (?:your )?(?:white|allow) ?list',
    'blocking ads', 'block(?:ing)? our ads', 'we rely on ads', 'ads (?:help|keep) us',
  ].join('|'), 'i');

  const viewportArea = () => Math.max(1, window.innerWidth * window.innerHeight);

  function covers(el, fraction) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0) return false;
    if (cs.position !== 'fixed' && cs.position !== 'absolute' && cs.position !== 'sticky') return false;
    const r = el.getBoundingClientRect();
    const w = Math.max(0, Math.min(r.right, window.innerWidth) - Math.max(r.left, 0));
    const h = Math.max(0, Math.min(r.bottom, window.innerHeight) - Math.max(r.top, 0));
    return (w * h) / viewportArea() >= fraction;
  }

  function textOf(el) {
    const t = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
    return t.length > 3000 ? '' : t; // a wall is a short message, not the article
  }

  /** The outermost positioned ancestor of a nag message that still looks like a wall. */
  function wallFor(el) {
    let wall = null;
    for (let cur = el; cur && cur !== document.body && cur !== document.documentElement; cur = cur.parentElement) {
      if (covers(cur, 0.25)) wall = cur;
    }
    return wall;
  }

  function unlockPage() {
    for (const el of [document.documentElement, document.body]) {
      if (!el) continue;
      const cs = getComputedStyle(el);
      if (cs.overflow === 'hidden' || cs.overflowY === 'hidden') el.style.setProperty('overflow', 'auto', 'important');
      if (cs.position === 'fixed') el.style.setProperty('position', 'static', 'important');
    }
    // Walls often blur or dim the content behind them.
    for (const el of document.querySelectorAll('body > *')) {
      const f = getComputedStyle(el).filter;
      if (f && f.includes('blur')) el.style.setProperty('filter', 'none', 'important');
    }
  }

  let removed = 0;
  function sweep() {
    if (!document.body) return;
    const candidates = new Set();
    // Positioned elements are the only ones that can be a wall; this keeps the scan cheap.
    for (const el of document.body.querySelectorAll('div, section, aside, span, dialog, iframe, p')) {
      if (el.childElementCount > 200) continue;
      const t = textOf(el);
      if (t && NAG.test(t)) {
        const wall = wallFor(el);
        if (wall) candidates.add(wall);
      }
    }
    if (!candidates.size) return;
    for (const wall of candidates) {
      // Empty full-screen siblings are the dimmed backdrop that goes with it.
      for (const sib of wall.parentElement ? [...wall.parentElement.children] : []) {
        if (sib !== wall && !textOf(sib) && covers(sib, 0.9)) sib.remove();
      }
      wall.remove();
      removed++;
    }
    unlockPage();
    document.documentElement.dataset.nullrouteNagsRemoved = String(removed);
  }

  let pending = false;
  const schedule = () => {
    if (pending) return;
    pending = true;
    setTimeout(() => { pending = false; sweep(); }, 150);
  };

  // NullRoute Browser: injected at document start only when the setting is on.
  const start = () => {
    sweep();
    const mo = new MutationObserver(schedule);
    mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'class'] });
    setTimeout(() => mo.disconnect(), 60_000);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
