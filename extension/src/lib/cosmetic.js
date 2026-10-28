// Resolves which CSS selectors to hide for a given frame hostname.
//
// The bulk of generic selectors ship as a static content-script stylesheet
// (rulesets/generic.css) injected at document_start, so ads never flash.
// Domains that have exceptions to generic selectors are excluded from that
// stylesheet, and get a filtered copy injected here instead.

import { parents } from './domains.js';

const CHUNK = 400;

export class CosmeticEngine {
  constructor(data, genericExcluded) {
    this.generic = data.generic;
    this.genericExcept = Object.entries(data.genericExcept || {}).map(([s, d]) => [s, new Set(d)]);
    this.specific = data.specific || {};
    this.exceptions = data.exceptions || {};
    this.elemhide = new Set(data.elemhide || []);
    this.generichide = new Set(data.generichide || []);
    this.genericExcluded = new Set(genericExcluded || []);
  }

  static async load() {
    const [data, excluded] = await Promise.all([
      fetch(chrome.runtime.getURL('rulesets/cosmetic.json')).then(r => r.json()),
      fetch(chrome.runtime.getURL('rulesets/generic-excluded.json')).then(r => r.json()),
    ]);
    return new CosmeticEngine(data, excluded);
  }

  /** Returns the selectors to hide on `host` beyond the static generic sheet. */
  selectorsFor(host, user = { generic: [], specific: {} }) {
    const chain = parents(host);
    if (chain.some(d => this.elemhide.has(d))) return [];

    const out = new Set();
    const exc = new Set();
    for (const d of chain) {
      for (const s of this.specific[d] || []) out.add(s);
      for (const s of this.exceptions[d] || []) exc.add(s);
      for (const s of user.specific?.[d] || []) out.add(s);
    }
    const noGeneric = chain.some(d => this.generichide.has(d));
    if (!noGeneric && chain.some(d => this.genericExcluded.has(d))) {
      // The static sheet skipped this site; inject generic minus its exceptions.
      for (const s of this.generic) out.add(s);
    }
    if (!noGeneric) {
      for (const [s, doms] of this.genericExcept) {
        if (!chain.some(d => doms.has(d))) out.add(s);
      }
    }
    for (const s of user.generic || []) out.add(s);
    for (const s of exc) out.delete(s);
    return [...out];
  }

  static toCss(selectors) {
    const parts = [];
    for (let i = 0; i < selectors.length; i += CHUNK) {
      parts.push(`${selectors.slice(i, i + CHUNK).join(',\n')}{display:none!important}`);
    }
    return parts.join('\n');
  }
}
