// Parser for the "My filters" box. Supports a safe subset of ABP syntax:
//
//   ads.example.com            block this domain (+ subdomains)
//   ||example.com/ads/*        block URLs matching an ABP pattern
//   ##.sticky-banner           hide elements on every site
//   news.com##.paywall-promo   hide elements on one site (+ subdomains)
//   ! comment
//
// Returns DNR rules (ids assigned by the caller) plus cosmetic selectors.

import { isValidDomain } from './domains.js';

export const MAX_USER_RULES = 5000;

function isSafeSelector(sel) {
  return sel.length > 0 && sel.length <= 1000 && !/[{}\\]|\/\*|<\/?style/i.test(sel);
}

export function parseUserFilters(text) {
  const domains = new Set();
  const urlFilters = new Set();
  const cosmetic = { generic: [], specific: {} };
  const errors = [];

  String(text || '').split(/\r?\n/).forEach((raw, idx) => {
    const line = raw.trim();
    const n = idx + 1;
    if (!line || line.startsWith('!') || line.startsWith('# ')) return;

    const hashIdx = line.indexOf('##');
    if (hashIdx !== -1) {
      const domainPart = line.slice(0, hashIdx).trim().toLowerCase();
      const selector = line.slice(hashIdx + 2).trim();
      if (!isSafeSelector(selector)) { errors.push({ line: n, msg: 'Invalid selector' }); return; }
      if (!domainPart) { cosmetic.generic.push(selector); return; }
      const ds = domainPart.split(',').map(s => s.trim()).filter(Boolean);
      if (!ds.every(isValidDomain)) { errors.push({ line: n, msg: 'Invalid domain before ##' }); return; }
      for (const d of ds) (cosmetic.specific[d] ||= []).push(selector);
      return;
    }

    if (/[^\x20-\x7e]/.test(line)) { errors.push({ line: n, msg: 'Only ASCII is supported' }); return; }
    if (line.startsWith('@@') || line.includes('$')) {
      errors.push({ line: n, msg: 'Exceptions and $options are not supported here — use the site allowlist' });
      return;
    }

    const bare = line.replace(/^\|\|/, '').replace(/\^$/, '').toLowerCase();
    if (isValidDomain(bare) && !line.includes('/') && !line.includes('*')) { domains.add(bare); return; }

    let pattern = line;
    if (pattern.startsWith('||*')) pattern = pattern.slice(2);
    if (pattern.replace(/[*|^]/g, '').length < 4) {
      errors.push({ line: n, msg: 'Pattern too broad — it would block almost everything' });
      return;
    }
    urlFilters.add(pattern);
  });

  const rules = [];
  const dl = [...domains].sort();
  for (let i = 0; i < dl.length; i += 1000) {
    rules.push({ priority: 1, action: { type: 'block' }, condition: { requestDomains: dl.slice(i, i + 1000) } });
  }
  for (const urlFilter of [...urlFilters].sort()) {
    rules.push({ priority: 1, action: { type: 'block' }, condition: { urlFilter } });
  }
  if (rules.length > MAX_USER_RULES) {
    errors.push({ line: 0, msg: `Too many rules (${rules.length} > ${MAX_USER_RULES})` });
    rules.length = MAX_USER_RULES;
  }
  return { rules, cosmetic, errors, counts: { domains: dl.length, patterns: urlFilters.size,
    selectors: cosmetic.generic.length + Object.values(cosmetic.specific).reduce((a, s) => a + s.length, 0) } };
}
